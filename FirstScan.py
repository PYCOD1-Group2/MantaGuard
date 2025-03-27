import pyshark
import netifaces
import csv
from datetime import datetime

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

def save_packets_to_csv(packets, filename="packet_capture.csv"):
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["No", "Timestamp", "Source", "Destination", "Protocol", "Length", "Info"])
        
        for i, packet in enumerate(packets, 1):
            try:
                timestamp = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")
                src = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
                dst = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
                proto = packet.highest_layer
                length = packet.length
                info = str(packet)
                writer.writerow([i, timestamp, src, dst, proto, length, info])
            except Exception as e:
                print(f"Failed to write packet {i}: {e}")

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
                break
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

    packet_count = 50  # Number of packets to capture
    scan_network(selected_interface, packet_count)

if __name__ == "__main__":
    main()
