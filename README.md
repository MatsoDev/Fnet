# Fnet — NetCut Pro

An interactive network management, auditing, and **bandwidth control** tool written in Python with a web UI. It scans your local subnet, identifies connected devices (hostname + MAC vendor), and lets you control their internet access using ARP cache poisoning — cutting them off, rate-limiting them, or enforcing an internet quota automatically.

**⚠️ Disclaimer:** This tool is strictly for educational purposes and authorized penetration testing. You must only run this on networks you own or have explicit, written permission to audit. The author is not responsible for any misuse or damage caused by this software.

---

## Features

### Network Control
* **Dynamic Interface Selection** — Auto-detects active network interfaces and resolves their IP / Gateway configuration.
* **Comprehensive Scanning** — Discovers local devices and resolves Hostnames (reverse DNS) and Hardware Vendors (MacVendors API).
* **One-Click Block / Restore** — Cut any device off from the gateway with ARP poisoning, then restore it cleanly.
* **Live Traffic Monitor** — Real-time per-device traffic counters with a web UI bar graph.
* **Auto-Rescan** — Keeps the device list fresh automatically (`8s` interval).
* **Graceful Restoration** — Restores all ARP tables on exit, so nothing stays cut off.

### Throttling (Real Bandwidth Shaping)
* **Per-Device Speed Control** — Drag a slider on any device card to cap its internet speed (0–1000 kbps).
* **Real MITM Rate Limiting** — `TokenBucketForwarder` ARPs-poison the target so its traffic crosses your NIC, then applies a token bucket to the relayed frames — dropping what exceeds your configured bit-rate. WhatsApp/text keeps working; heavy video throttles down.
* **Throttle All** — One-click apply a limit to every device at once.
* **Persistent state** — Limits survive rescans (stored in `devices.json`).

### Quota Auto-Mode
Save your router's monthly internet allowance automatically:
* Set a **monthly limit (GB)**, a **throttle threshold (%)**, and a **block threshold (%)**.
* The app accumulates actual traffic flowing through the interface.
* When usage passes the throttle %, **all devices are automatically throttled** to your chosen speed.
* When it passes the block %, **all devices are blocked** entirely.
* Reset the meter for a new month with one click.

---

## Prerequisites

* Windows (10/11) recommended — run as **Administrator** (Python 3.12+, Npcap/WinPcap).
* Linux also supported — run as **root** (`sudo`) for raw sockets.
* Python 3 + dependencies:
  ```
  pip install flask netifaces scapy
  ```
* [Npcap](https://npcap.com/) must be installed (so Scapy can send/receive raw packets).

---

## Installation & Run

```bash
git clone https://github.com/MatsoDev/Fnet
cd Fnet
python app.py            # Windows: run as Administrator
sudo python3 app.py      # Linux: run as root
```

1. The app auto-selects your active interface + gateway and scans the network.
2. Open the web UI: **http://localhost:5000**
3. Use the **Scan / Restore All** buttons, the per-device **block toggle** and **limit slider**, and configure the **Quota Auto-Mode** panel.

**CLI only?** Use `netcut.py` for the original terminal interface:
```bash
sudo python3 netcut.py
1. Select the Network Card
2. Select the IP_Address (toggle)
3. r - to rescan & q - Quit the Tools
```

---

## Project Layout

| File | Purpose |
|------|---------|
| `app.py` | Flask web backend + controller, ARP spoofing, token-bucket throttling, quota engine |
| `templates/index.html` | Web UI (device cards, throttle sliders, quota panel) |
| `netcut.py` | Original CLI client |
| `devices.json` | Saved device names, block/throttle states, quota (auto-generated) |

---

## License / Legal

For educational and authorized security testing only. Use responsibly on networks you own or manage.