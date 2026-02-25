from scapy.all import show_interfaces, conf
from scapy.arch.windows import get_windows_if_list

print("--- SCAPY INTERFACES ---")
show_interfaces()

print("\n--- DETAILED WINDOWS LIST ---")
interfaces = get_windows_if_list()
for i in interfaces:
    print(f"Index: {i['index']} | Name: {i['name']} | IP: {i['ips']}")