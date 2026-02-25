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

DATASET_FILE = "nids_training_data.csv"

app = Flask(__name__)

network_stats = {}
dns_table = {}
whois_cache = {}
bandwidth_log = {}

try:
    my_mac = get_if_hwaddr(conf.ifaces.dev_from_index(11)) # Use your Wi-Fi index
except:
    my_mac = "00:00:00:00:00:00"

# ROBUST IP DETECTION
def get_internal_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually send data, just finds the interface used to reach the internet
        s.connect(('8.8.8.8', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

my_ip = get_internal_ip()
print(f"[*] Target IP: {my_ip}")

def get_hostname_passive(ip):
    """Fallback: Try to resolve the IP if we didn't sniff the DNS query."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip
    
def get_org_name(ip):
    # Skip private/local IPs
    if ip.startswith(("192.168.", "10.", "127.", "172.16.", "fe80:")):
        return "Local Network"
    
    if ip in whois_cache:
        return whois_cache[ip]

    try:
        # Perform the lookup
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        # Extract the Organization/Network name
        org = results.get('asn_description', 'Unknown Organization')
        whois_cache[ip] = org
        return org
    except:
        return "Unknown"

# We run this in a thread so the UI doesn't freeze
def async_whois_lookup(ip):
    name = get_org_name(ip)
    if ip in network_stats:
        network_stats[ip]["hostname"] = name

def get_service_name(port, proto="tcp"):
    try:
        # Translates port (e.g. 443) to service name (e.g. 'https')
        return socket.getservbyport(port, proto)
    except:
        return f"Port {port}" # Fallback to just showing the port number

def process_packet(pkt):
    # --- MAC-BASED OUTBOUND DETECTION ---
    # If the source MAC is yours, the packet is leaving your PC (Outbound)
    is_outbound = False
    if pkt.src == my_mac:
        is_outbound = True

    # Identify the IP layer (v4 or v6)
    ip_layer = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
    
    if ip_layer:
        src, dst = ip_layer.src, ip_layer.dst
        
        # If outbound, we track the destination (where you are talking to)
        # If inbound, we track the source (who is talking to you)
        target_ip = dst if is_outbound else src
        
        # Skip internal traffic (your PC talking to itself)
        if target_ip == my_ip or target_ip == "127.0.0.1" or target_ip == "::1":
            return

        now = time.time()
        
        # Initialize stats for new IPs
        if target_ip not in network_stats:
            network_stats[target_ip] = {
                "hostname": target_ip,
                "in": 0, "out": 0, "bytes": 0,
                "last_seen": now,
                "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other",
                "packet_times": [],
                "avg_iat": 0,
                "last_packet_time": now
            }
            threading.Thread(target=async_whois_lookup, args=(target_ip,), daemon=True).start()
        
        # Update Behavioral Timing (IAT)
        iat = now - network_stats[target_ip]["last_packet_time"]
        network_stats[target_ip]["packet_times"].append(iat)
        if len(network_stats[target_ip]["packet_times"]) > 20:
            network_stats[target_ip]["packet_times"].pop(0)
        
        network_stats[target_ip]["avg_iat"] = sum(network_stats[target_ip]["packet_times"]) / len(network_stats[target_ip]["packet_times"])
        network_stats[target_ip]["last_packet_time"] = now

        # Update Byte Counts and Directions
        network_stats[target_ip]["bytes"] += len(pkt)
        network_stats[target_ip]["last_seen"] = now
        
        direction = "out" if is_outbound else "in"
        network_stats[target_ip][direction] += 1
        
        # Run anomaly checks
        check_anomalies(target_ip, pkt)

def start_sniffing():
    # This will print all Windows interfaces so you can find the right one
    interfaces = get_windows_if_list()
    for i in interfaces:
        print(f"Index: {i['index']} | Name: {i['name']} | IP: {i['ips']}")

    # CHANGE THIS: Use the Index number of your Wi-Fi card (usually 1, 2, or 3)
    # If your Wi-Fi is Index 5, change it to iface=conf.ifaces.dev_from_index(5)
    target_iface = conf.ifaces.dev_from_index(11) 
    print(f"[*] Starting Sniffer on {target_iface}...")
    sniff(iface=target_iface, prn=process_packet, store=False)

def calculate_rates():
    """Background task to update KB/s for every IP."""
    while True:
        time.sleep(1) # Calculate every second
        now = time.time()
        for ip, stats in network_stats.items():
            if ip not in bandwidth_log:
                bandwidth_log[ip] = {"last_bytes": 0, "last_time": now}
            
            # Calculate Delta
            bytes_diff = stats["bytes"] - bandwidth_log[ip]["last_bytes"]
            time_diff = now - bandwidth_log[ip]["last_time"]
            
            # Rate in KB/s
            rate = (bytes_diff / 1024) / time_diff if time_diff > 0 else 0
            stats["kb_per_sec"] = round(rate, 2)
            
            # Update log
            bandwidth_log[ip]["last_bytes"] = stats["bytes"]
            bandwidth_log[ip]["last_time"] = now

def check_anomalies(target_ip, pkt):
    if "flags" not in network_stats[target_ip]:
        network_stats[target_ip]["flags"] = []

    # 1. Large Packet Detection (Potential Data Exfiltration)
    if len(pkt) > 1450: # Standard MTU is ~1500
        if "Large Packets" not in network_stats[target_ip]["flags"]:
            network_stats[target_ip]["flags"].append("Large Payload")

def save_to_dataset(ip, stats, label):
    file_exists = os.path.isfile(DATASET_FILE)
    proto_map = {"TCP": 1, "UDP": 2, "Other": 0}
    
    features = {
        "ip_address": ip,
        "total_in": stats["in"],
        "total_out": stats["out"],
        "total_bytes": stats["bytes"],
        "kb_per_sec": stats.get("kb_per_sec", 0),
        "avg_iat": stats.get("avg_iat", 0), # CRITICAL FOR ML
        "protocol": proto_map.get(stats["protocol"], 0),
        "is_malicious": label 
    }

    with open(DATASET_FILE, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=features.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(features)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    # 1. Calculate Total Session Volume (Cumulative across all time)
    total_bytes = sum(d.get("bytes", 0) for d in network_stats.values())
    total_mb = round(total_bytes / (1024 * 1024), 2)
    
    # 2. Filter for Active Devices (to keep the table clean)
    current_time = time.time()
    active_devices = {
        ip: data for ip, data in network_stats.items() 
        if current_time - data.get("last_seen", 0) < 60
    }

    # 3. Return the payload
    return jsonify({
        "status": "Online",
        "total_session_volume_mb": round(sum(d.get("bytes", 0) for d in network_stats.values()) / (1024*1024), 2),
        "count": len(network_stats), # This is the active node count
        "data": network_stats})

@app.route('/api/save_training/<int:label>')
def save_training(label):
    """
    Call this with /api/save_training/0 for Normal
    Call this with /api/save_training/1 for Attack (Kali)
    """
    count = 0
    for ip, stats in network_stats.items():
        # Only log devices that have seen recent traffic
        if time.time() - stats['last_seen'] < 60:
            save_to_dataset(ip, stats, label)
            count += 1
    return jsonify({"status": "Success", "logged_nodes": count, "mode": "Malicious" if label else "Normal"})


if __name__ == '__main__':
    # 1. Start the native packet capture (Blue Team engine)
    threading.Thread(target=start_sniffing, daemon=True).start()
    
    # 2. START THIS: The behavioral rate calculator (The "Analysis" engine)
    # Without this, your throughput will always show 0 KB/s
    threading.Thread(target=calculate_rates, daemon=True).start()

    print(f"[*] Native Packet Capture System online at http://127.0.0.1:5000")
    
    # 3. Run the Flask API
    app.run(debug=True, port=5000, use_reloader=False)

