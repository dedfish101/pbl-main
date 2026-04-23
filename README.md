# 🛡️ Behavioral Network Intrusion Detection System (NIDS)

> A real-time, AI-augmented Network Intrusion Detection System built with Python, featuring native packet capture, behavioral anomaly detection, and a live SOC operations dashboard.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.x%2F3.x-black?logo=flask)](https://flask.palletsprojects.com)
[![Scapy](https://img.shields.io/badge/Scapy-2.5.x-orange)](https://scapy.net)
[![Groq](https://img.shields.io/badge/AI-Groq%20LPU%20%7C%20LLaMA%203.3%2070B-purple)](https://groq.com)
[![License](https://img.shields.io/badge/License-Open%20Source-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)](https://github.com/dedfish101/pbl-main)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Screenshots](#screenshots)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Dataset Logging](#dataset-logging)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Academic Context](#academic-context)
- [Limitations](#limitations)
- [Future Scope](#future-scope)
- [Contributing](#contributing)

---

## Overview

This project implements a **three-layered behavioral NIDS** that goes beyond simple packet sniffing. Instead of relying on signature databases, it analyzes the *shape* and *timing* of traffic — catching threats based on how connections behave rather than what they contain.

The system combines:
- **High-speed native packet capture** via Scapy + Npcap
- **Local rule-based anomaly detection** (zero API cost, microsecond latency)
- **Deep-learning AI escalation** via Groq LPU running LLaMA 3.3 70B
- **A real-time SOC dashboard** accessible from any browser

Built as a B.Tech final-year project at **Symbiosis Skills and Professional University, Pune** — but designed with production-grade engineering practices: environment secret management, thread-safe concurrency, AI request locking, and ML dataset export.

---

## Architecture

The system is organized as three independent layers:

```
┌─────────────────────────────────────────────────────────────┐
│          LAYER 3 — SOC Operations Dashboard (Flask/JS)       │
│  Threat Gauge · Alert Sidebar · Host Inventory · Charts      │
└────────────────────────────┬────────────────────────────────┘
                             │ REST API (JSON)
┌────────────────────────────▼────────────────────────────────┐
│         LAYER 2 — Behavioral Analysis Engine                 │
│  IAT Tracking · Throughput Delta · Hybrid Anomaly Detection  │
│  ┌─────────────────────┐   ┌──────────────────────────────┐ │
│  │ Stage 1: Local Rules│   │ Stage 2: Groq LPU (AI)       │ │
│  │ · Rate > 800 KB/s   │──▶│ · Behavioral Fingerprint     │ │
│  │ · Payload > 1450 B  │   │ · LLaMA 3.3 70B verdict      │ │
│  └─────────────────────┘   └──────────────────────────────┘ │
└────────────────────────────┬────────────────────────────────┘
                             │ Raw packets
┌────────────────────────────▼────────────────────────────────┐
│         LAYER 1 — Core Traffic Intelligence                   │
│  Scapy/Npcap · MAC-based Direction · WHOIS · Port Mapping   │
│              Network Interface Card (NIC)                    │
└─────────────────────────────────────────────────────────────┘
```

**Detection escalation flow:**

1. Every packet → Layer 1 extracts metadata (src/dst IP, protocol, payload size, IAT)
2. Local rules fire instantly for obvious anomalies (floods, oversized payloads)
3. After 50 packets from a host → behavioral fingerprint sent to Groq LPU for deep-learning verdict
4. All events surface on the dashboard in real time

---

## Features

### 🔍 Core Traffic Intelligence
- **Native packet sniffing** — Scapy + Npcap capturing live Layer 2/3 traffic from the MediaTek Wi-Fi 6 NIC
- **Passive WHOIS/hostname discovery** — background threads resolve every external IP to an org name (Google, Microsoft, Unknown, etc.)
- **MAC-based directional accuracy** — perfectly distinguishes Inbound vs Outbound traffic, bypassing Windows hardware offloading issues
- **Service protocol identification** — maps port numbers to human-readable services (443 → HTTPS, 22 → SSH, etc.)

### 🧠 Behavioral Analysis
- **Inter-Arrival Time (IAT) tracking** — measures packet timing in microseconds to expose machine-speed automated attacks
- **Throughput delta calculation** — real-time KB/s per host via background accumulation daemon
- **Hybrid anomaly detection:**
  - *Stage 1 (instant, free):* High-Rate Flood detection (> 800 KB/s) and Large Payload detection (> 1450 bytes MTU violation)
  - *Stage 2 (AI, after 50 pkts):* Behavioral fingerprint → Groq LPU → LLaMA 3.3 70B → Normal / Suspicious / Attack verdict

### 📊 SOC Dashboard
- **Dynamic Threat Gauge** — color-coded severity indicator (🟢 Clear → 🟡 Warning → 🔴 Critical)
- **Live Alert Log Sidebar** — real-time event feed with severity categories (Info / Warning / Critical)
- **Dual-View Navigation:**
  - *SOC Summary* — network-wide metrics, protocol distribution doughnut, throughput sparklines
  - *Host Inventory* — per-IP stats, local flags, and AI verdict for every active host
- **Chart.js visualizations** — live TCP/UDP protocol distribution and throughput trend charts

### 🔒 Security & Engineering
- Environment variable secret management (`.env` + `python-dotenv`)
- Thread-safe shared data access (`threading.Lock` + snapshot pattern)
- AI request locking + per-host cooldown (prevents API rate-limit crashes)
- ML dataset export via "Log Normal" / "Log Attack" buttons → labeled CSV

---

## Screenshots

> *(Add screenshots of the dashboard here after running the system)*

| SOC Summary View | Host Inventory View |
|:---:|:---:|
| `[screenshot]` | `[screenshot]` |

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Must be added to PATH |
| Npcap | 1.70+ | Windows only — install in WinPcap-compatible mode |
| libpcap-dev | latest | Linux only |
| Groq API Key | — | [groq.com](https://console.groq.com) |

---

## Installation

### Windows

```bash
# 1. Install Npcap from https://npcap.com
#    ✅ Check "Install Npcap in WinPcap API-compatible Mode"

# 2. Clone the repository
git clone https://github.com/dedfish101/pbl-main.git
cd pbl-main

# 3. Install Python dependencies
pip install scapy flask python-dotenv requests

# 4. Set up your API key (see Configuration below)

# 5. Run as Administrator (required for raw socket access)
python sniffer.py
```

### Linux / Ubuntu

```bash
# 1. Install system dependencies
sudo apt update && sudo apt install python3 python3-pip libpcap-dev

# 2. Clone the repository
git clone https://github.com/dedfish101/pbl-main.git
cd pbl-main

# 3. Install Python dependencies
pip3 install scapy flask python-dotenv requests

# 4. Set up your API key (see Configuration below)

# 5. Run with superuser privileges
sudo python3 sniffer.py
```

> **Why admin/root?** Raw socket access — required by Scapy's capture engine — is a privileged OS operation on all platforms.

---

## Configuration

Create a `.env` file in the project root (this file is git-ignored and never committed):

```env
GROQ_API_KEY=your_groq_api_key_here
```

Optional tuning constants inside `sniffer.py`:

```python
LARGE_PAYLOAD_THRESHOLD = 1450   # bytes — triggers Stage 1 alert
RATE_THRESHOLD_KBPS     = 800    # KB/s — triggers flood alert
AI_ESCALATION_THRESHOLD = 50     # packets from a host before AI analysis
AI_COOLDOWN_SECONDS     = 30     # min seconds between AI calls per host
DASHBOARD_PORT          = 5000   # Flask web server port
THROUGHPUT_WINDOW       = 1      # seconds per throughput sample
```

---

## Usage

```bash
# Start the system (Windows — run terminal as Administrator)
python sniffer.py

# Start the system (Linux)
sudo python3 sniffer.py
```

Then open your browser at:

```
http://localhost:5000
```

The dashboard will begin populating immediately as packets are captured. The AI verdicts appear in the Host Inventory tab once each host crosses the 50-packet threshold.

---

## API Reference

The Flask server exposes the following REST endpoints (all `GET`, JSON responses):

| Endpoint | Description |
|---|---|
| `GET /` | Serves the main SOC dashboard HTML |
| `GET /api/stats` | Total packets, active alert count, protocol breakdown |
| `GET /api/packets` | Last 100 captured packet summaries |
| `GET /api/alerts` | Recent anomaly alert log (all severities) |
| `GET /api/throughput` | Time-series throughput data for chart rendering |
| `GET /api/protocols` | Protocol distribution counts (TCP/UDP/ICMP/Other) |
| `POST /api/log/normal` | Appends current network state to CSV with label `0` (Normal) |
| `POST /api/log/attack` | Appends current network state to CSV with label `1` (Attack) |

---

## Dataset Logging

Use the **Log Normal** and **Log Attack** buttons on the dashboard to build a labeled training dataset for offline machine learning:

```csv
timestamp, src_ip, packet_count, byte_count, avg_iat_us, throughput_kbps,
tcp_ratio, udp_ratio, icmp_ratio, max_payload, avg_payload, label
```

- `label = 0` → Normal traffic
- `label = 1` → Attack / suspicious traffic

The exported CSV is compatible with scikit-learn, PyTorch, and standard ML pipelines. Recommended benchmark datasets for augmentation: **CICIDS2017**, **NSL-KDD**.

---

## Project Structure

```
pbl-main/
│
├── sniffer.py              # Main application — packet capture + analysis engine
├── .env                    # API keys (git-ignored, create manually)
├── .gitignore
├── requirements.txt
│
├── templates/
│   └── index.html          # SOC dashboard HTML (Jinja2 template)
│
├── static/
│   ├── css/
│   │   └── style.css       # Dashboard styles
│   └── js/
│       └── dashboard.js    # Chart.js + AJAX polling logic
│
└── network_log.csv         # Auto-generated ML training dataset (git-ignored)
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Packet Capture | [Scapy 2.5.x](https://scapy.net) + [Npcap](https://npcap.com) |
| Web Framework | [Flask 2.x/3.x](https://flask.palletsprojects.com) |
| AI Analysis | [Groq LPU](https://groq.com) — LLaMA 3.3 70B |
| Frontend Charts | [Chart.js 4.x](https://chartjs.org) |
| UI Framework | [Bootstrap 5](https://getbootstrap.com) |
| Secret Management | [python-dotenv](https://pypi.org/project/python-dotenv/) |
| Concurrency | Python `threading` module |
| Language | Python 3.10+ |

---

## Academic Context

This project was developed as a **Problem-Based Learning (PBL)** capstone for:

> **Bachelor of Technology — Computer Science and Information Technology (Cyber Security)**  
> School of Computer Science and Information Technology  
> Symbiosis Skills and Professional University, Pune  
> Academic Year: 2025–26

**Subjects integrated:**

| Subject | Application |
|---|---|
| Python Programming | Threading, Scapy API, Flask routes, data structures |
| Computer Networks | OSI model, TCP/IP dissection, throughput calculation |
| Cyber Security | Anomaly detection theory, attack taxonomy, heuristic design |
| Operating Systems | Concurrent threads, shared memory, thread-safe buffers |
| Web Technologies | REST API, AJAX polling, Chart.js, Bootstrap dashboard |
| Software Engineering | Modular architecture, documentation, SDLC |

---

## Limitations

- **Encrypted traffic blindness** — TLS/SSL payload contents are not inspectable; only metadata anomalies can be detected in encrypted streams
- **Single interface** — monitors one NIC at a time; multi-segment networks require separate instances
- **No persistent storage** — packet and alert logs are in-memory only and lost on restart
- **Python GIL bottleneck** — under multi-gigabit loads, Python threading may become a bottleneck
- **Threshold tuning required** — default values may produce false positives in environments with legitimate large transfers (e.g., video conferencing, cloud backup)

---

## Future Scope

- [ ] Scikit-learn / Random Forest classifier trained on logged CSV data
- [ ] SQLite or InfluxDB persistent storage for historical analysis
- [ ] Email / SMS alerting via `smtplib` + Twilio
- [ ] Multi-interface and distributed monitoring agents
- [ ] PCAP file export (`scapy.wrpcap`) for Wireshark forensics
- [ ] Docker containerization (`Dockerfile` + `docker-compose.yml`)
- [ ] Snort rule syntax parser for signature-based hybrid detection
- [ ] Full IPv6 support

---

## Contributing

Contributions, bug reports, and feature requests are welcome via [GitHub Issues](https://github.com/dedfish101/pbl-main/issues) and Pull Requests.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'Add your feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

<p align="center">
  Made with ❤️ at SSPU Pune &nbsp;|&nbsp; B.Tech CSIT Cyber Security &nbsp;|&nbsp; 2025–26
</p>