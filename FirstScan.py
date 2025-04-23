import pyshark
import netifaces
import csv
from datetime import datetime
import nmap
import os
import time

# Ensure the path to Nmap is accessible (adjust if your install location differs)
os.environ["PATH"] += os.pathsep + "C:\\Program Files (x86)\\Nmap\\"

def get_network_interfaces():
    try:
        from pyshark.tshark.tshark import get_tshark_interfaces
        interfaces = get_tshark_interfaces()

        interface_map = {}
        for i in interfaces:
            if isinstance(i, dict):
                name = i.get('name')
                description = i.get('description', name)
            else:
                name = i
                description = i

            ip = get_ip_for_interface(name)
            if ip not in ["No IP", "Unknown"]:
                full_desc = f"{description} (IP: {ip})"
                interface_map[full_desc] = name

        return interface_map
    except Exception:
        return {}

def get_ip_for_interface(iface_name):
    try:
        iface_list = netifaces.interfaces()
        for iface in iface_list:
            if iface in iface_name:
                addrs = netifaces.ifaddresses(iface)
                ip_info = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'No IP')
                return ip_info
    except:
        pass
    return "Unknown"

def save_combined_csv(packets, nmap_results, filename=None):
    if not filename:
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"combined_scan_{now}.csv"

    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([
            "Type", "No", "Timestamp", "Source IP", "Destination IP", "Source Port",
            "Destination Port", "Transport Layer", "Protocol", "TTL",
            "MAC Src", "MAC Dst", "Length", "Info",
            "Host", "State", "Nmap Protocol", "Port", "Service", "Product", "Version"
        ])

        for i, packet in enumerate(packets, 1):
            try:
                timestamp = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
                src_ip = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                transport = packet.transport_layer or 'N/A'
                src_port = getattr(packet[transport], 'srcport', 'N/A') if transport != 'N/A' else 'N/A'
                dst_port = getattr(packet[transport], 'dstport', 'N/A') if transport != 'N/A' else 'N/A'
                ttl = packet.ip.ttl if hasattr(packet, 'ip') else 'N/A'
                eth_src = packet.eth.src if hasattr(packet, 'eth') else 'N/A'
                eth_dst = packet.eth.dst if hasattr(packet, 'eth') else 'N/A'
                proto = packet.highest_layer
                length = packet.length
                info = str(packet)

                writer.writerow([
                    "Packet", i, timestamp, src_ip, dst_ip, src_port, dst_port,
                    transport, proto, ttl, eth_src, eth_dst, length, info,
                    "", "", "", "", "", "", ""
                ])
            except Exception:
                pass

        for i, result in enumerate(nmap_results, 1):
            writer.writerow([
                "Nmap", i, "", "", "", "", "", "", "", "", "", "", "", "",
                result.get("host"), result.get("state"), result.get("protocol"),
                result.get("port"), result.get("service"), result.get("product"), result.get("version")
            ])

def run_nmap_scan(target_subnet):
    scanner = nmap.PortScanner()
    results = []
    print(f"Running Nmap scan on {target_subnet} (light scan mode)...")
    try:
        start_time = time.time()
        # Light scan with ping discovery and top 100 ports
        scanner.scan(hosts=target_subnet, arguments='-T4 -F')
        total_hosts = len(scanner.all_hosts())
        print(f"Discovered {total_hosts} host(s). Parsing results...")
        for idx, host in enumerate(scanner.all_hosts(), 1):
            print(f"[{idx}/{total_hosts}] Processing {host}...")
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    service = scanner[host][proto][port]
                    results.append({
                        "host": host,
                        "state": scanner[host].state(),
                        "protocol": proto,
                        "port": port,
                        "service": service.get('name', 'unknown'),
                        "product": service.get('product', 'unknown'),
                        "version": service.get('version', 'unknown')
                    })
            if idx % 1 == 0:
                elapsed = int(time.time() - start_time)
                print(f"Elapsed: {elapsed}s - Scanned {idx}/{total_hosts} hosts")
    except Exception as e:
        print(f"Nmap scan failed: {e}")
    return results

def scan_network(interface, packet_count=50):
    try:
        capture = pyshark.LiveCapture(interface=interface)
        packets = []
        for packet in capture.sniff_continuously(packet_count=packet_count):
            try:
                packets.append(packet)
            except Exception:
                pass
        return packets
    except Exception:
        return []

def start_full_scan(interface_label: str, packet_count: int = 50):
    interface_map = get_network_interfaces()
    selected_interface = interface_map.get(interface_label)

    if not selected_interface:
        raise ValueError("Invalid interface selected.")

    interface_ip = get_ip_for_interface(selected_interface)
    packets = scan_network(selected_interface, packet_count)

    nmap_results = []
    if interface_ip not in ["Unknown", "No IP"]:
        subnet = '.'.join(interface_ip.split('.')[:3]) + ".0/24"
        nmap_results = run_nmap_scan(subnet)

    save_combined_csv(packets, nmap_results)

if __name__ == "__main__":
    interfaces = get_network_interfaces()
    if not interfaces:
        print("No usable network interfaces with valid IP found.")
        exit()

    print("Available network interfaces:")
    options = list(interfaces.keys())
    for i, desc in enumerate(options):
        print(f"{i + 1}: {desc}")

    try:
        choice = int(input("Select an interface by number: ")) - 1
        selected = options[choice]
        start_full_scan(selected)
        print("Scan complete. Combined CSV file has been saved.")
    except Exception as e:
        print(f"Error: {e}")
