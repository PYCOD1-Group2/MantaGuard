import pyshark

def get_network_interfaces():
    try:
        import netifaces
        return netifaces.interfaces()
    except ImportError:
        print("netifaces module not found. Install it using: pip install netifaces")
        return []

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
        return packets
    except Exception as e:
        print(f"Error: {e}")
        return []

def main():
    interfaces = get_network_interfaces()
    if not interfaces:
        print("No network interfaces found or unable to list them.")
        return
    
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}: {iface}")
    
    while True:
        try:
            choice = int(input("Select an interface by number: ")) - 1
            if 0 <= choice < len(interfaces):
                interface = interfaces[choice]
                break
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

    packet_count = 50  # Number of packets to capture
    scan_network(interface, packet_count)

if __name__ == "__main__":
    main()
