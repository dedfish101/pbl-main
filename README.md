# Native Packet Capture System & Behavioral NIDS

A lightweight Network Intrusion Detection System (NIDS) built with Python, Scapy, and Flask. It captures raw network traffic, performs real-time throughput calculations, and flags anomalous behaviors (like large payloads).

## Windows Setup Instructions
1. Install [Python 3.10+](https://www.python.org/downloads/) (Check "Add Python to PATH").
2. Install [Npcap](https://nmap.org/npcap/) (**Must check "Install Npcap in WinPcap API-compatible Mode"**).
3. Double-click `setup.bat` to install all Python dependencies.
4. Open `sniffer.py` and update the `sniff()` interface index to match your active Wi-Fi/Ethernet card.

## Running the Engine
Right-click `run.bat` and select **Run as Administrator**. Navigate to `http://127.0.0.1:5000` to view the live dashboard.