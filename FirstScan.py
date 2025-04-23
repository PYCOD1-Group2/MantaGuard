import pyshark
import netifaces
import csv
from datetime import datetime
import nmap

def get_network_interfaces():
    try:
        from pyshark.tshark.tshark import get_tshark_interfaces
        interfaces = get_tshark_interfaces()

        interface_map = {}
        for i in interfaces:
            if isinstance(i, dict):
                name = i.get('name')
                description = i.get('description', name)
            else:  # fallback if it's just a string
                name = i
                description = i

            ip = get_ip_for_interface(name)
            full_desc = f"{description} (IP: {ip})"
            interface_map[full_desc] = name

        return interface_map
    except Exception as e:
        print(f"Failed to retrieve interfaces: {e}")
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

def save_packets_to_csv(packets, filename=None):
    if not filename:
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"packet_capture_{now}.csv"

    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([
            "No", "Timestamp", "Source IP", "Destination IP", "Source Port",
            "Destination Port", "Transport Layer", "Protocol", "TTL",
            "MAC Src", "MAC Dst", "Length", "Info"
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
                    i, timestamp, src_ip, dst_ip, src_port, dst_port,
                    transport, proto, ttl, eth_src, eth_dst, length, info
                ])
            except Exception as e:
                print(f"Failed to write packet {i}: {e}")

def run_nmap_scan(target_subnet):
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"nmap_scan_{now}.csv"
    scanner = nmap.PortScanner()
    print(f"Running Nmap scan on {target_subnet}...")
    try:
        scanner.scan(hosts=target_subnet, arguments='-sS -sV')
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Host", "State", "Protocol", "Port", "Service", "Product", "Version"])
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        service = scanner[host][proto][port]
                        writer.writerow([
                            host,
                            scanner[host].state(),
                            proto,
                            port,
                            service.get('name', 'unknown'),
                            service.get('product', 'unknown'),
                            service.get('version', 'unknown')
                        ])
        print(f"Nmap scan saved to {filename}")
    except Exception as e:
        print(f"Nmap scan failed: {e}")

def scan_network(interface, packet_count=50):
    print(f"Starting network scan on interface {interface}...")
    try:
        capture = pyshark.LiveCapture(interface=interface)
        packets = []

        for packet in capture.sniff_continuously(packet_count=packet_count):
            try:
                packets.append(packet)
                print(f"Packet Captured: {packet}")
            except Exception as e:
                print(f"Error processing packet: {e}")

        print(f"Scan completed. Captured {len(packets)} packets.")
        save_packets_to_csv(packets)
        return packets
    except Exception as e:
        print(f"Error: {e}")
        return []

def main():
    interface_map = get_network_interfaces()
    if not interface_map:
        print("No network interfaces found or unable to list them.")
        return

    print("Available network interfaces:")
    descriptions = list(interface_map.keys())
    for i, desc in enumerate(descriptions):
        print(f"{i + 1}: {desc}")

    while True:
        try:
            choice = int(input("Select an interface by number: ")) - 1
            if 0 <= choice < len(descriptions):
                selected_description = descriptions[choice]
                selected_interface = interface_map[selected_description]
                interface_ip = get_ip_for_interface(selected_interface)
                break
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

    packet_count = 50  # Number of packets to capture
    scan_network(selected_interface, packet_count)

    # Derive subnet to scan for Nmap (assume /24 subnet)
    if interface_ip != "Unknown" and interface_ip != "No IP":
        subnet = '.'.join(interface_ip.split('.')[:3]) + ".0/24"
        run_nmap_scan(subnet)
    else:
        print("Could not determine subnet for Nmap scan.")

if __name__ == "__main__":
    main()
