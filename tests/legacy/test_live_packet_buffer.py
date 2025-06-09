#!/usr/bin/env python3
# test_live_packet_buffer.py - Test the RollingPacketBuffer class

import os
import sys
import time
from live_packet_buffer import initialize_buffer, on_anomaly

def main():
    """
    Test the RollingPacketBuffer by capturing packets and simulating an anomaly.
    """
    if len(sys.argv) < 2:
        print("Usage: python test_live_packet_buffer.py <interface>")
        print("Example: python test_live_packet_buffer.py Wi-Fi")
        sys.exit(1)

    interface = sys.argv[1]

    try:
        print(f"Initializing packet buffer on interface '{interface}'...")
        buffer = initialize_buffer(interface)

        # Capture packets for a few seconds
        print("Capturing packets for 10 seconds...")
        time.sleep(10)

        # Get the number of packets captured so far
        packets = buffer.get_last_n(5000)
        print(f"Captured {len(packets)} packets so far")

        # Check timestamps of a few packets if available
        if packets:
            print("\nSample packet timestamps:")
            for i in range(min(3, len(packets))):
                timestamp = buffer.get_packet_timestamp(packets[i])
                print(f"Packet {i+1}: {timestamp}")

        # Simulate an anomaly detection
        print("Simulating anomaly detection...")
        saved_file = on_anomaly("test_anomaly")

        if saved_file:
            print(f"Anomaly packets saved to: {saved_file}")
            print(f"File exists: {os.path.exists(saved_file)}")
            print(f"File size: {os.path.getsize(saved_file)} bytes")
        else:
            print("Failed to save anomaly packets")

        # Stop the packet capture
        print("Stopping packet capture...")
        buffer.stop_capture()
        print("Test completed successfully")

    except Exception as e:
        print(f"Error during test: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
