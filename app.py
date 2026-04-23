import time
import threading
import socket
from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, IP, DNS, DNSRR, get_working_ifaces, IPv6, UDP, get_if_hwaddr
from scapy.all import conf
from scapy.arch.windows import get_windows_if_list
from scapy.all import IPv6, TCP
from ipwhois import IPWhois
import csv
import os
import json
from groq import Groq
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
load_dotenv()
api_key = os.getenv("GROQ_API_KEY")
client  = Groq(api_key=api_key)

DATASET_FILE      = "nids_training_data.csv"
SNIFF_IFACE_INDEX = 11       # MediaTek MT7921 Wi-Fi 6 — DO NOT CHANGE
MAX_ALERTS        = 150

# ---------------------------------------------------------------------------
# TUNABLE DETECTION PARAMETERS  (live-editable via /api/update_config)
# ---------------------------------------------------------------------------
FLOOD_KB_THRESHOLD = 800
AI_PACKET_LIMIT    = 50
IAT_SENSITIVITY    = 0.002

# ---------------------------------------------------------------------------
# WHITELIST / TRUSTED HOST REGISTRY
#
# Structure per entry:
#   whitelist[ip] = {
#       "label":        str,   # human name e.g. "Google DNS", "Home Router"
#       "reason":       str,   # why it's trusted e.g. "DNS resolver, always high volume"
#       "added_at":     float, # epoch timestamp
#       "bypass_flags": bool,  # True = skip ALL anomaly checks for this IP
#   }
#
# Subnet support: adding "192.168.1.0" trusts all 192.168.1.x hosts.
# Persisted to whitelist.json — survives engine restarts.
# GIL makes dict assignments atomic; no extra lock needed for simple reads.
# ---------------------------------------------------------------------------
WHITELIST_FILE = "whitelist.json"
whitelist      = {}


def load_whitelist():
    global whitelist
    if os.path.isfile(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, "r") as f:
                whitelist = json.load(f)
            print(f"[Whitelist] Loaded {len(whitelist)} trusted entries")
        except Exception as e:
            print(f"[Whitelist] Load failed: {e} — starting empty")
            whitelist = {}


def save_whitelist():
    try:
        with open(WHITELIST_FILE, "w") as f:
            json.dump(whitelist, f, indent=2)
    except Exception as e:
        print(f"[Whitelist] Save failed: {e}")


def is_whitelisted(ip):
    """
    Returns the whitelist entry dict if the IP (or its /24 subnet) is trusted.
    Returns None if not trusted.
    """
    if ip in whitelist:
        return whitelist[ip]
    # /24 subnet check: "192.168.1.55" matches entry "192.168.1.0"
    parts = ip.split(".")
    if len(parts) == 4:
        subnet = ".".join(parts[:3]) + ".0"
        if subnet in whitelist:
            return whitelist[subnet]
    return None


# ---------------------------------------------------------------------------
# FLASK APP
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ---------------------------------------------------------------------------
# GLOBAL STATE
# ---------------------------------------------------------------------------
network_stats = {}
dns_table     = {}
whois_cache   = {}
bandwidth_log = {}
alert_log     = []   # append-only, GIL-safe

# ---------------------------------------------------------------------------
# CONCURRENCY
# ---------------------------------------------------------------------------
ai_lock = threading.Lock()

# ---------------------------------------------------------------------------
# NETWORK IDENTITY
# ---------------------------------------------------------------------------
try:
    my_mac = get_if_hwaddr(conf.ifaces.dev_from_index(SNIFF_IFACE_INDEX))
except Exception:
    my_mac = "00:00:00:00:00:00"


def get_internal_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


my_ip = get_internal_ip()
print(f"[*] My IP  : {my_ip}")
print(f"[*] My MAC : {my_mac}")

# ---------------------------------------------------------------------------
# ALERT HELPER
# severity: 'critical' | 'warning' | 'info' | 'trusted'
# 'trusted' renders green in the UI
# ---------------------------------------------------------------------------
def add_alert(ip, severity, message):
    hostname = network_stats.get(ip, {}).get("hostname", ip)
    display  = hostname if hostname != ip else ip
    alert_log.append({
        "timestamp": time.strftime("%H:%M:%S"),
        "ip":        ip,
        "hostname":  display,
        "severity":  severity,
        "message":   message,
    })
    if len(alert_log) > MAX_ALERTS:
        del alert_log[0]

# ---------------------------------------------------------------------------
# WHOIS / HOSTNAME
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
        org     = results.get("asn_description", "Unknown Organization")
        whois_cache[ip] = org
        return org
    except Exception:
        return "Unknown"


def async_whois_lookup(ip):
    name = get_org_name(ip)
    if ip in network_stats:
        network_stats[ip]["hostname"] = name


def get_service_name(port, proto="tcp"):
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return f"Port {port}"

# ---------------------------------------------------------------------------
# PACKET PROCESSOR  (sniffer thread — must stay non-blocking)
# ---------------------------------------------------------------------------
def process_packet(pkt):
    # Windows MAC-based outbound detection (IP-based unreliable on MT7921)
    is_outbound = (pkt.src == my_mac)

    ip_layer = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
    if not ip_layer:
        return

    src, dst  = ip_layer.src, ip_layer.dst
    target_ip = dst if is_outbound else src

    if target_ip in (my_ip, "127.0.0.1", "::1"):
        return

    now      = time.time()
    wl_entry = is_whitelisted(target_ip)
    trusted  = wl_entry is not None

    # Initialise entry for new IP
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
            "trusted":          trusted,
            "trust_label":      wl_entry["label"]  if trusted else "",
            "trust_reason":     wl_entry["reason"] if trusted else "",
        }
        threading.Thread(target=async_whois_lookup, args=(target_ip,),
                         daemon=True).start()
        if trusted:
            add_alert(target_ip, "trusted",
                      f"Trusted host active — {wl_entry['label']} ({wl_entry['reason']})")
        else:
            add_alert(target_ip, "info",
                      f"New host discovered — protocol {proto}")

    stats = network_stats[target_ip]

    # Dynamic trust sync: if user whitelisted after first packet, apply immediately
    if trusted and not stats["trusted"]:
        stats["trusted"]      = True
        stats["trust_label"]  = wl_entry["label"]
        stats["trust_reason"] = wl_entry["reason"]
        stats["flags"]        = []   # clear flags raised before whitelisting
        add_alert(target_ip, "trusted",
                  f"Host retroactively trusted — {wl_entry['label']}")
    elif not trusted and stats["trusted"]:
        stats["trusted"]      = False
        stats["trust_label"]  = ""
        stats["trust_reason"] = ""

    # Behavioural timing (IAT rolling window of 20 packets)
    iat = now - stats["last_packet_time"]
    stats["packet_times"].append(iat)
    if len(stats["packet_times"]) > 20:
        stats["packet_times"].pop(0)
    stats["avg_iat"]          = sum(stats["packet_times"]) / len(stats["packet_times"])
    stats["last_packet_time"] = now

    stats["bytes"]    += len(pkt)
    stats["last_seen"] = now
    stats["out" if is_outbound else "in"] += 1

    # WHITELIST GATE: bypass ALL anomaly checks for trusted hosts
    if trusted and wl_entry.get("bypass_flags", True):
        return

    check_anomalies(target_ip, pkt)

# ---------------------------------------------------------------------------
# SNIFFER LAUNCHER
# ---------------------------------------------------------------------------
def start_sniffing():
    interfaces = get_windows_if_list()
    for i in interfaces:
        print(f"  Index: {i['index']} | Name: {i['name']} | IP: {i['ips']}")
    target_iface = conf.ifaces.dev_from_index(SNIFF_IFACE_INDEX)
    print(f"[*] Sniffing on → {target_iface}")
    sniff(iface=target_iface, prn=process_packet, store=False)

# ---------------------------------------------------------------------------
# BANDWIDTH CALCULATOR  (1-second daemon)
# ---------------------------------------------------------------------------
def calculate_rates():
    while True:
        time.sleep(1)
        now = time.time()
        for ip, stats in list(network_stats.items()):   # list() concurrency fix
            if ip not in bandwidth_log:
                bandwidth_log[ip] = {"last_bytes": 0, "last_time": now}
            bytes_diff          = stats["bytes"] - bandwidth_log[ip]["last_bytes"]
            time_diff           = now            - bandwidth_log[ip]["last_time"]
            rate                = (bytes_diff / 1024) / time_diff if time_diff > 0 else 0
            stats["kb_per_sec"] = round(rate, 2)
            bandwidth_log[ip]["last_bytes"] = stats["bytes"]
            bandwidth_log[ip]["last_time"]  = now

# ---------------------------------------------------------------------------
# ANOMALY DETECTION
# Only reaches here if the host is NOT whitelisted (gate in process_packet)
# ---------------------------------------------------------------------------
def check_anomalies(target_ip, pkt):
    stats = network_stats[target_ip]

    # Rule 1: High-Rate Flood
    flood_by_speed = stats.get("kb_per_sec", 0) > FLOOD_KB_THRESHOLD
    flood_by_iat   = stats["in"] > 200 and stats["avg_iat"] < IAT_SENSITIVITY
    if (flood_by_speed or flood_by_iat) and "High Rate Flood" not in stats["flags"]:
        stats["flags"].append("High Rate Flood")
        add_alert(
            target_ip, "critical",
            f"High-rate flood — {stats.get('kb_per_sec', 0):.1f} KB/s  "
            f"|  Avg IAT {stats['avg_iat']:.4f}s"
        )

    # Rule 2: Large Payload
    if len(pkt) > 1450 and "Large Payload" not in stats["flags"]:
        stats["flags"].append("Large Payload")
        add_alert(target_ip, "warning",
                  f"Oversized packet detected — {len(pkt)} bytes")

    # Rule 3: Port Scan Heuristic
    if (stats["out"] > 100 and stats["in"] < 5
            and "Port Scan Suspected" not in stats["flags"]):
        stats["flags"].append("Port Scan Suspected")
        add_alert(target_ip, "warning",
                  f"Port scan heuristic — {stats['out']} out / {stats['in']} in")

    # Rule 4: Groq AI Escalation
    if stats["in"] > AI_PACKET_LIMIT and "ai_verdict" not in stats:
        threading.Thread(target=get_groq_analysis, args=(target_ip,),
                         daemon=True).start()

# ---------------------------------------------------------------------------
# GROQ AI ANALYSIS
# ---------------------------------------------------------------------------
def get_groq_analysis(ip):
    if not ai_lock.acquire(blocking=False):
        return

    try:
        stats = network_stats.get(ip)
        if not stats:
            return

        prompt = (
            f"Analyze network behavior for IP {ip}: "
            f"Protocol {stats['protocol']}, "
            f"Inbound {stats['in']} packets, Outbound {stats['out']} packets, "
            f"Total bytes {stats['bytes']}, "
            f"Avg inter-arrival time {stats['avg_iat']:.6f}s, "
            f"Speed {stats.get('kb_per_sec', 0):.2f} KB/s, "
            f"Flags: {stats['flags']}. "
            f"Give a 2-3 sentence security verdict covering intent, risk level, and action."
        )
        completion          = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
        )
        verdict             = completion.choices[0].message.content.strip()
        stats["ai_verdict"] = verdict
        add_alert(ip, "info", f"[AI] {verdict[:140]}")

    except Exception:
        if ip in network_stats:
            network_stats[ip]["ai_verdict"] = "AI Analysis Rate Limited"
        add_alert(ip, "info", "[AI] Rate limit hit — cooling down")

    finally:
        time.sleep(3)
        ai_lock.release()

# ---------------------------------------------------------------------------
# TRAINING DATA
# ---------------------------------------------------------------------------
def save_to_dataset(ip, stats, label):
    file_exists = os.path.isfile(DATASET_FILE)
    proto_map   = {"TCP": 1, "UDP": 2, "Other": 0}
    features    = {
        "ip_address":   ip,
        "total_in":     stats["in"],
        "total_out":    stats["out"],
        "total_bytes":  stats["bytes"],
        "kb_per_sec":   stats.get("kb_per_sec", 0),
        "avg_iat":      stats.get("avg_iat", 0),
        "protocol":     proto_map.get(stats["protocol"], 0),
        "is_malicious": label,
    }
    with open(DATASET_FILE, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=features.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(features)

# ---------------------------------------------------------------------------
# FLASK ROUTES
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def get_stats():
    total_bytes  = sum(d.get("bytes", 0) for d in list(network_stats.values()))
    total_mb     = round(total_bytes / (1024 * 1024), 2)
    proto_dist   = {"TCP": 0, "UDP": 0, "Other": 0}
    
    anomaly_penalty = 0
    now = time.time()

    for stats in list(network_stats.values()):
        p = stats.get("protocol", "Other")
        proto_dist[p] = proto_dist.get(p, 0) + 1
        
        if not stats.get("trusted", False) and now - stats.get("last_seen", 0) < 60:
            flags = stats.get("flags", [])
            if "High Rate Flood" in flags:
                anomaly_penalty += 40
            elif len(flags) > 0:
                anomaly_penalty += 10

    # Calculate Stability
    stability_score = max(0, 100 - anomaly_penalty)
    
    if stability_score == 100:
        net_status, color_key = "Synchronized", "green"
    elif stability_score > 60:
        net_status, color_key = "Jitter Detected", "yellow"
    else:
        net_status, color_key = "Desynchronized", "red"

    # CRITICAL: These keys MUST match the JS fetch call exactly
    return jsonify({
        "status": "Online",
        "total_mb": total_mb,
        "count": len(network_stats),
        "proto_dist": proto_dist,
        "stability_score": stability_score,
        "net_status": net_status,
        "color_key": color_key,
        "data": dict(network_stats)
    })

@app.route("/api/alerts")
def get_alerts():
    return jsonify(list(reversed(alert_log[-50:])))


@app.route("/api/config")
def get_config():
    return jsonify({
        "flood_kb":   FLOOD_KB_THRESHOLD,
        "ai_packets": AI_PACKET_LIMIT,
        "iat_sens":   IAT_SENSITIVITY,
    })


@app.route("/api/update_config", methods=["POST"])
def update_config():
    global FLOOD_KB_THRESHOLD, AI_PACKET_LIMIT, IAT_SENSITIVITY
    data    = request.get_json(silent=True) or {}
    changed = {}
    if "flood_kb" in data:
        val = float(data["flood_kb"])
        if 50 <= val <= 5000:
            FLOOD_KB_THRESHOLD = val
            changed["flood_kb"] = val
    if "ai_packets" in data:
        val = int(data["ai_packets"])
        if 5 <= val <= 500:
            AI_PACKET_LIMIT = val
            changed["ai_packets"] = val
    if "iat_sens" in data:
        val = float(data["iat_sens"])
        if 0.0001 <= val <= 0.1:
            IAT_SENSITIVITY = val
            changed["iat_sens"] = val
    print(f"[Config] Updated: {changed}")
    return jsonify({
        "status":  "ok",
        "applied": changed,
        "current": {
            "flood_kb":   FLOOD_KB_THRESHOLD,
            "ai_packets": AI_PACKET_LIMIT,
            "iat_sens":   IAT_SENSITIVITY,
        },
    })


# ── Whitelist routes ────────────────────────────────────────────────────────

@app.route("/api/whitelist", methods=["GET"])
def get_whitelist():
    """Return whitelist merged with live traffic stats."""
    result = {}
    for ip, entry in list(whitelist.items()):
        stats = network_stats.get(ip, {})
        result[ip] = {
            **entry,
            "kb_per_sec": stats.get("kb_per_sec", 0),
            "bytes":      stats.get("bytes", 0),
            "last_seen":  stats.get("last_seen", 0),
            "protocol":   stats.get("protocol", "—"),
        }
    return jsonify(result)


@app.route("/api/whitelist/add", methods=["POST"])
def add_to_whitelist():
    """
    Add an IP or /24 subnet to the trusted list.
    Body: { "ip": "8.8.8.8", "label": "Google DNS",
            "reason": "DNS resolver", "bypass_flags": true }
    """
    data   = request.get_json(silent=True) or {}
    ip     = data.get("ip", "").strip()
    label  = data.get("label",  "Trusted Host").strip()
    reason = data.get("reason", "Manually approved").strip()
    bypass = data.get("bypass_flags", True)

    if not ip:
        return jsonify({"status": "error", "message": "IP is required"}), 400

    whitelist[ip] = {
        "label":        label,
        "reason":       reason,
        "added_at":     time.time(),
        "bypass_flags": bypass,
    }
    save_whitelist()

    if ip in network_stats:
        network_stats[ip]["trusted"]      = True
        network_stats[ip]["trust_label"]  = label
        network_stats[ip]["trust_reason"] = reason
        network_stats[ip]["flags"]        = []   # clear prior flags

    add_alert(ip, "trusted", f"Added to whitelist — {label} ({reason})")
    print(f"[Whitelist] + {ip} | {label} | {reason}")
    return jsonify({"status": "ok", "ip": ip, "entry": whitelist[ip]})


@app.route("/api/whitelist/remove", methods=["POST"])
def remove_from_whitelist():
    """Body: { "ip": "8.8.8.8" }"""
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "IP is required"}), 400
    if ip not in whitelist:
        return jsonify({"status": "error", "message": "IP not in whitelist"}), 404

    removed_label = whitelist[ip]["label"]
    del whitelist[ip]
    save_whitelist()

    if ip in network_stats:
        network_stats[ip]["trusted"]      = False
        network_stats[ip]["trust_label"]  = ""
        network_stats[ip]["trust_reason"] = ""

    add_alert(ip, "warning", f"Trust revoked — {removed_label} now monitored")
    print(f"[Whitelist] - {ip} | {removed_label}")
    return jsonify({"status": "ok", "removed": ip})


@app.route("/api/whitelist/quick_add/<ip>", methods=["POST"])
def quick_add_whitelist(ip):
    """
    One-click trust from the Host Inventory table row.
    Auto-derives label from the host's resolved WHOIS name.
    """
    data       = request.get_json(silent=True) or {}
    stats      = network_stats.get(ip, {})
    auto_label = stats.get("hostname", ip)
    if auto_label == ip:
        auto_label = "Trusted Host"

    label  = data.get("label",  auto_label).strip()
    reason = data.get("reason", "Quick-trusted from Host Inventory").strip()

    whitelist[ip] = {
        "label":        label,
        "reason":       reason,
        "added_at":     time.time(),
        "bypass_flags": True,
    }
    save_whitelist()

    if ip in network_stats:
        network_stats[ip]["trusted"]      = True
        network_stats[ip]["trust_label"]  = label
        network_stats[ip]["trust_reason"] = reason
        network_stats[ip]["flags"]        = []

    add_alert(ip, "trusted", f"Quick-trusted — {label}")
    return jsonify({"status": "ok", "ip": ip, "label": label})


@app.route("/api/whitelist/quick_remove/<ip>", methods=["POST"])
def quick_remove_whitelist(ip):
    """One-click untrust from the Host Inventory table row."""
    if ip not in whitelist:
        return jsonify({"status": "error", "message": "Not whitelisted"}), 404
    label = whitelist[ip]["label"]
    del whitelist[ip]
    save_whitelist()
    if ip in network_stats:
        network_stats[ip]["trusted"]      = False
        network_stats[ip]["trust_label"]  = ""
        network_stats[ip]["trust_reason"] = ""
    add_alert(ip, "warning", f"Trust revoked — {label} now monitored")
    return jsonify({"status": "ok", "removed": ip})


@app.route("/api/save_training/<int:label>")
def save_training(label):
    count = 0
    for ip, stats in list(network_stats.items()):
        if time.time() - stats["last_seen"] < 60:
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
if __name__ == "__main__":
    load_whitelist()   # restore persisted trusted hosts BEFORE sniffing starts
    threading.Thread(target=start_sniffing,  daemon=True).start()
    threading.Thread(target=calculate_rates, daemon=True).start()
    print("[*] NIDS Engine online → http://127.0.0.1:5000")
    app.run(debug=True, port=5000, use_reloader=False)