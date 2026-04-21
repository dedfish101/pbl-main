import time
import threading
import socket
from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, DNS, DNSRR, get_working_ifaces, IPv6, UDP, get_if_hwaddr
from scapy.all import conf
from scapy.arch.windows import get_windows_if_list
from scapy.all import IPv6, TCP
from ipwhois import IPWhois
import csv
import os
from groq import Groq
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
load_dotenv()
api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=api_key)
DATASET_FILE = "nids_training_data.csv"
SNIFF_IFACE_INDEX = 11          # MediaTek MT7921 Wi-Fi 6 — DO NOT CHANGE
MAX_ALERTS = 150                 # Cap in-memory alert log

# ---------------------------------------------------------------------------
# FLASK APP
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ---------------------------------------------------------------------------
# AI lock 
# ---------------------------------------------------------------------------
ai_lock = threading.Lock() # Add this at the top with other globals

def get_groq_analysis(ip):
    # Only allow one AI request to happen at a time across the whole system
    if not ai_lock.acquire(blocking=False):
        return 

    try:
        stats = network_stats.get(ip)
        # ... your existing Groq code ...
    finally:
        # Wait 3 seconds before allowing another AI request to prevent spam
        time.sleep(3) 
        ai_lock.release()

# ---------------------------------------------------------------------------
# GLOBAL STATE  (all dict mutations are GIL-protected; list.append is atomic)
# ---------------------------------------------------------------------------
network_stats  = {}   # ip -> stats dict
dns_table      = {}
whois_cache    = {}
bandwidth_log  = {}
alert_log      = []   # Live alert log — append-only, GIL-safe

# ---------------------------------------------------------------------------
# NETWORK IDENTITY
# ---------------------------------------------------------------------------
try:
    my_mac = get_if_hwaddr(conf.ifaces.dev_from_index(SNIFF_IFACE_INDEX))
except Exception:
    my_mac = "00:00:00:00:00:00"

def get_internal_ip():
    """Robust self-IP detection via UDP trick (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

my_ip = get_internal_ip()
print(f"[*] My IP  : {my_ip}")
print(f"[*] My MAC : {my_mac}")

# ---------------------------------------------------------------------------
# ALERT LOG HELPER
# ---------------------------------------------------------------------------
def add_alert(ip, severity, message):
    """
    Thread-safe alert append.
    severity: 'critical' | 'warning' | 'info'
    GIL guarantees list.append() is atomic — no lock needed.
    """
    hostname = network_stats.get(ip, {}).get("hostname", ip)
    # Avoid hostname == raw IP in the label (looks redundant)
    display = hostname if hostname != ip else ip

    alert = {
        "timestamp": time.strftime("%H:%M:%S"),
        "ip":        ip,
        "hostname":  display,
        "severity":  severity,
        "message":   message,
    }
    alert_log.append(alert)

    # Trim oldest entries to cap memory (del on list is O(n) but infrequent)
    if len(alert_log) > MAX_ALERTS:
        del alert_log[0]

# ---------------------------------------------------------------------------
# WHOIS / HOSTNAME HELPERS
# ---------------------------------------------------------------------------
def get_hostname_passive(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

def get_org_name(ip):
    if ip.startswith(("192.168.", "10.", "127.", "172.16.", "fe80:")):
        return "Local Network"
    if ip in whois_cache:
        return whois_cache[ip]
    try:
        obj     = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        org     = results.get('asn_description', 'Unknown Organization')
        whois_cache[ip] = org
        return org
    except Exception:
        return "Unknown"

def async_whois_lookup(ip):
    """Run WHOIS in a daemon thread so the sniffer never blocks."""
    name = get_org_name(ip)
    if ip in network_stats:
        network_stats[ip]["hostname"] = name

def get_service_name(port, proto="tcp"):
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return f"Port {port}"

# ---------------------------------------------------------------------------
# PACKET PROCESSOR  (runs on Scapy sniffer thread — must stay non-blocking)
# ---------------------------------------------------------------------------
def process_packet(pkt):
    # MAC-based outbound detection (Windows hardware-offload workaround)
    is_outbound = (pkt.src == my_mac)

    ip_layer = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
    if not ip_layer:
        return

    src, dst   = ip_layer.src, ip_layer.dst
    target_ip  = dst if is_outbound else src

    # Skip loopback / self traffic
    if target_ip in (my_ip, "127.0.0.1", "::1"):
        return

    now = time.time()

    # ── Initialise entry for new IP ──────────────────────────────────────
    if target_ip not in network_stats:
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "Other")
        network_stats[target_ip] = {
            "hostname":         target_ip,
            "in":               0,
            "out":              0,
            "bytes":            0,
            "last_seen":        now,
            "protocol":         proto,
            "packet_times":     [],
            "avg_iat":          0,
            "last_packet_time": now,
            "flags":            [],
            "kb_per_sec":       0,
        }
        threading.Thread(target=async_whois_lookup, args=(target_ip,),
                         daemon=True).start()
        add_alert(target_ip, "info",
                  f"New host discovered — protocol {proto}")

    stats = network_stats[target_ip]

    # ── Behavioural timing (IAT) ─────────────────────────────────────────
    iat = now - stats["last_packet_time"]
    stats["packet_times"].append(iat)
    if len(stats["packet_times"]) > 20:
        stats["packet_times"].pop(0)
    stats["avg_iat"]          = sum(stats["packet_times"]) / len(stats["packet_times"])
    stats["last_packet_time"] = now

    # ── Byte / direction counters ────────────────────────────────────────
    stats["bytes"]     += len(pkt)
    stats["last_seen"]  = now
    stats["out" if is_outbound else "in"] += 1

    # ── Anomaly detection ────────────────────────────────────────────────
    check_anomalies(target_ip, pkt)

# ---------------------------------------------------------------------------
# PACKET SNIFFER LAUNCHER
# ---------------------------------------------------------------------------
def start_sniffing():
    interfaces = get_windows_if_list()
    for i in interfaces:
        print(f"  Index: {i['index']} | Name: {i['name']} | IP: {i['ips']}")

    target_iface = conf.ifaces.dev_from_index(SNIFF_IFACE_INDEX)
    print(f"[*] Sniffing on → {target_iface}")
    sniff(iface=target_iface, prn=process_packet, store=False)

# ---------------------------------------------------------------------------
# BANDWIDTH CALCULATOR  (1-second ticker, separate daemon thread)
# ---------------------------------------------------------------------------
def calculate_rates():
    while True:
        time.sleep(1)
        now = time.time()
        for ip, stats in list(network_stats.items()):   # list() — concurrency fix
            if ip not in bandwidth_log:
                bandwidth_log[ip] = {"last_bytes": 0, "last_time": now}

            bytes_diff = stats["bytes"] - bandwidth_log[ip]["last_bytes"]
            time_diff  = now            - bandwidth_log[ip]["last_time"]

            rate             = (bytes_diff / 1024) / time_diff if time_diff > 0 else 0
            stats["kb_per_sec"] = round(rate, 2)

            bandwidth_log[ip]["last_bytes"] = stats["bytes"]
            bandwidth_log[ip]["last_time"]  = now

# ---------------------------------------------------------------------------
# ANOMALY DETECTION  (local rules + Groq escalation)
# ---------------------------------------------------------------------------
def check_anomalies(target_ip, pkt):
    stats = network_stats[target_ip]

    # ── Rule 1: High-Rate Flood ──────────────────────────────────────────
    flood_by_speed = stats.get("kb_per_sec", 0) > 800
    flood_by_iat   = stats["in"] > 200 and stats["avg_iat"] < 0.002
    if (flood_by_speed or flood_by_iat) and "High Rate Flood" not in stats["flags"]:
        stats["flags"].append("High Rate Flood")
        add_alert(
            target_ip, "critical",
            f"High-rate flood — {stats.get('kb_per_sec', 0):.1f} KB/s  |  "
            f"Avg IAT {stats['avg_iat']:.4f}s"
        )

    # ── Rule 2: Large Payload ────────────────────────────────────────────
    if len(pkt) > 1450 and "Large Payload" not in stats["flags"]:
        stats["flags"].append("Large Payload")
        add_alert(
            target_ip, "warning",
            f"Oversized packet detected — {len(pkt)} bytes"
        )

    # ── Rule 3: Port Scan Heuristic ──────────────────────────────────────
    # High outbound count with very few inbound responses = scan-like
    if (stats["out"] > 100 and stats["in"] < 5
            and "Port Scan Suspected" not in stats["flags"]):
        stats["flags"].append("Port Scan Suspected")
        add_alert(
            target_ip, "warning",
            f"Port scan heuristic — {stats['out']} out / {stats['in']} in"
        )

    # ── Rule 4: Groq AI Escalation (after 50 packets of evidence) ────────
    if stats["in"] > 50 and "ai_verdict" not in stats:
        threading.Thread(target=get_groq_analysis, args=(target_ip,),
                         daemon=True).start()

# ---------------------------------------------------------------------------
# GROQ AI ANALYSIS  (daemon thread — never blocks sniffer)
# ---------------------------------------------------------------------------
def get_groq_analysis(ip):
    # Only allow one AI request to happen at a time across the whole system
    if not ai_lock.acquire(blocking=False):
        return 

    try:
        stats = network_stats.get(ip)
        if not stats:
            return

        prompt = (
            f"Analyze network behavior for IP {ip}: "
            f"Protocol {stats['protocol']}, "
            f"Inbound packets {stats['in']}, Outbound packets {stats['out']}, "
            f"Avg inter-arrival time {stats['avg_iat']:.6f}s, "
            f"Speed {stats.get('kb_per_sec', 0):.2f} KB/s, "
            f"Existing flags: {stats['flags']}. "
            f"Give a single-sentence security verdict."
        )
        
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
        )
        
        verdict = completion.choices[0].message.content.strip()
        stats["ai_verdict"] = verdict
        add_alert(ip, "info", f"[AI] {verdict[:140]}")

    except Exception as e:
        stats["ai_verdict"] = "AI Analysis Rate Limited"
        add_alert(ip, "info", "[AI] Rate limit hit — waiting for cool-down")
    
    finally:
        # Wait 3 seconds before allowing another AI request to prevent API spam
        time.sleep(3) 
        ai_lock.release()

# ---------------------------------------------------------------------------
# TRAINING DATA PERSISTENCE
# ---------------------------------------------------------------------------
def save_to_dataset(ip, stats, label):
    file_exists = os.path.isfile(DATASET_FILE)
    proto_map   = {"TCP": 1, "UDP": 2, "Other": 0}

    features = {
        "ip_address":  ip,
        "total_in":    stats["in"],
        "total_out":   stats["out"],
        "total_bytes": stats["bytes"],
        "kb_per_sec":  stats.get("kb_per_sec", 0),
        "avg_iat":     stats.get("avg_iat", 0),
        "protocol":    proto_map.get(stats["protocol"], 0),
        "is_malicious": label,
    }

    with open(DATASET_FILE, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=features.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(features)

# ---------------------------------------------------------------------------
# FLASK ROUTES
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    total_bytes = sum(d.get("bytes", 0) for d in list(network_stats.values()))
    total_mb    = round(total_bytes / (1024 * 1024), 2)

    proto_dist = {"TCP": 0, "UDP": 0, "Other": 0}
    
    # NEW LOGIC: Track active threats only
    active_threat_score = 0
    current_time = time.time()

    for stats in list(network_stats.values()):
        # 1. Update protocol distribution
        p = stats.get("protocol", "Other")
        proto_dist[p] = proto_dist.get(p, 0) + 1
        
        # 2. Only count threats from hosts active in the last 60 seconds
        if current_time - stats.get("last_seen", 0) < 60:
            flags = stats.get("flags", [])
            if "High Rate Flood" in flags:
                active_threat_score += 3  # Critical
            elif len(flags) > 0:
                active_threat_score += 1  # Warning

    # Compute dynamic threat level
    if active_threat_score == 0:
        threat_level = "green"
    elif active_threat_score < 3:
        threat_level = "yellow"
    else:
        threat_level = "red"

    return jsonify({
        "status": "Online",
        "total_mb": total_mb,
        "count": len(network_stats),
        "proto_dist": proto_dist,
        "threat_level": threat_level,
        "threat_flags": active_threat_score, # Matches the ID in index.html
        "data": dict(network_stats),
    })

@app.route('/api/alerts')
def get_alerts():
    """Return newest-first, capped at 50 for the UI."""
    return jsonify(list(reversed(alert_log[-50:])))


@app.route('/api/save_training/<int:label>')
def save_training(label):
    count = 0
    for ip, stats in list(network_stats.items()):
        if time.time() - stats['last_seen'] < 60:
            save_to_dataset(ip, stats, label)
            count += 1
    return jsonify({
        "status":       "Success",
        "logged_nodes": count,
        "mode":         "Malicious" if label else "Normal",
    })


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    threading.Thread(target=start_sniffing,   daemon=True).start()
    threading.Thread(target=calculate_rates,  daemon=True).start()
    print("[*] NIDS Engine online → http://127.0.0.1:5000")
    app.run(debug=True, port=5000, use_reloader=False)