import pyshark

def scan_network(interface="eth0", packet_count=50):
    print(f"Starting network scan on interface {interface}...")
    try:
        # Capture packets in real-time
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
    interface = "eth0"  # Change this to match your network interface
    packet_count = 50  # Number of packets to capture
    scan_network(interface, packet_count)

if __name__ == "__main__":
    main()
