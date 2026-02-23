import time
import threading
import socket
from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, DNS, DNSRR, get_working_ifaces, IPv6, UDP
from scapy.all import conf
from scapy.arch.windows import get_windows_if_list
from scapy.all import IPv6, TCP
from ipwhois import IPWhois


app = Flask(__name__)

network_stats = {}
dns_table = {}
whois_cache = {}
bandwidth_log = {}

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
    ip_layer = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
    
    if ip_layer:
        src, dst = ip_layer.src, ip_layer.dst
        target_ip = dst if src == my_ip else src
        
        if target_ip != my_ip:
            if target_ip not in network_stats:
                # Backend initialization with more "features"
                network_stats[target_ip] = {
                    "hostname": target_ip,
                    "in": 0, "out": 0,
                    "bytes": 0,
                    "last_seen": time.time(),
                    "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
                }
                threading.Thread(target=async_whois_lookup, args=(target_ip,), daemon=True).start()
            
            if pkt.haslayer(TCP):
                # Use the destination port to identify the service
                service = get_service_name(pkt[TCP].dport, "tcp")
                network_stats[target_ip]["service"] = service
                network_stats[target_ip]["protocol"] = "TCP"
            elif pkt.haslayer(UDP):
                service = get_service_name(pkt[UDP].dport, "udp")
                network_stats[target_ip]["service"] = service
                network_stats[target_ip]["protocol"] = "UDP"

            # Mechanical updates
            network_stats[target_ip]["bytes"] += len(pkt)
            network_stats[target_ip]["last_seen"] = time.time()
            
            direction = "out" if src == my_ip else "in"
            network_stats[target_ip][direction] += 1

def start_sniffing():
    # This will print all Windows interfaces so you can find the right one
    interfaces = get_windows_if_list()
    for i in interfaces:
        print(f"Index: {i['index']} | Name: {i['name']} | IP: {i['ips']}")

    # CHANGE THIS: Use the Index number of your Wi-Fi card (usually 1, 2, or 3)
    # If your Wi-Fi is Index 5, change it to iface=conf.ifaces.dev_from_index(5)
    print("[*] Starting Sniffer on default interface...")
    sniff(prn=process_packet, store=False)

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


if __name__ == '__main__':
    # 1. Start the native packet capture (Blue Team engine)
    threading.Thread(target=start_sniffing, daemon=True).start()
    
    # 2. START THIS: The behavioral rate calculator (The "Analysis" engine)
    # Without this, your throughput will always show 0 KB/s
    threading.Thread(target=calculate_rates, daemon=True).start()

    print(f"[*] Native Packet Capture System online at http://127.0.0.1:5000")
    
    # 3. Run the Flask API
    app.run(debug=True, port=5000, use_reloader=False)