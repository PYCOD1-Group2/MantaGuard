#!/usr/bin/env python3
# live_packet_buffer.py - Maintain a rolling buffer of the last 5000 packets using PyShark

import os
import sys
import time
import threading
import pyshark
from collections import deque
from datetime import datetime

class RollingPacketBuffer:
    """
    Maintains a rolling buffer of the last 5000 packets captured from a network interface.

    This class uses PyShark to capture packets in a background thread and stores them
    in a circular buffer (deque). It provides methods to retrieve the most recent packets
    and save them to a .pcap file when anomalies are detected.
    """

    def __init__(self, interface, buffer_size=5000):
        """
        Initialize the RollingPacketBuffer.

        Args:
            interface (str): Network interface to capture packets on (e.g., 'eth0', 'Wi-Fi')
            buffer_size (int): Maximum number of packets to keep in the buffer (default: 5000)
        """
        self.interface = interface
        self.buffer = deque(maxlen=buffer_size)
        self.running = False
        self.capture_thread = None
        self.lock = threading.Lock()

        # Create forensics directory if it doesn't exist
        self.forensics_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forensics')
        if not os.path.exists(self.forensics_dir):
            os.makedirs(self.forensics_dir)

    def start_capture(self):
        """
        Start capturing packets in a background thread.
        """
        if self.running:
            print("Packet capture is already running.")
            return

        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        print(f"Started packet capture on interface '{self.interface}'")

    def stop_capture(self):
        """
        Stop the packet capture thread.
        """
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            print("Packet capture stopped.")

    def _capture_packets(self):
        """
        Background thread function that captures packets and adds them to the buffer.
        """
        try:
            # Initialize the capture
            capture = pyshark.LiveCapture(interface=self.interface)

            # Start capturing packets
            for packet in capture.sniff_continuously():
                if not self.running:
                    break

                # Store the packet with its timestamp
                # PyShark packets already have timestamps accessible via packet.sniff_time
                # This will allow later alignment with Zeek UIDs
                with self.lock:
                    self.buffer.append(packet)
        except Exception as e:
            print(f"Error during packet capture: {str(e)}")
            self.running = False

    def get_last_n(self, n):
        """
        Retrieve the most recent n packets from the buffer.

        Args:
            n (int): Number of packets to retrieve

        Returns:
            list: List of the most recent n packets
        """
        with self.lock:
            # Convert to list and get the last n packets
            return list(self.buffer)[-n:] if n < len(self.buffer) else list(self.buffer)

    def get_packet_timestamp(self, packet):
        """
        Get the timestamp of a packet.

        Args:
            packet: PyShark packet object

        Returns:
            datetime: Timestamp of the packet
        """
        return packet.sniff_time if hasattr(packet, 'sniff_time') else None

    def save_packets(self, packets, filename):
        """
        Save the specified packets to a .pcap file.

        Args:
            packets (list): List of packets to save
            filename (str): Name of the output file

        Returns:
            str: Path to the saved file
        """
        if not packets:
            print("No packets to save.")
            return None

        # Ensure the filename has .pcap extension
        if not filename.endswith('.pcap'):
            filename += '.pcap'

        # Create full path
        output_path = os.path.join(self.forensics_dir, filename)

        try:
            # Create a temporary capture file
            temp_cap = pyshark.FileCapture(output_file=output_path)

            # Add each packet to the file
            for packet in packets:
                temp_cap._write_packet(packet)

            # Close the file
            temp_cap.close()

            print(f"Saved {len(packets)} packets to {output_path}")
            return output_path
        except Exception as e:
            print(f"Error saving packets: {str(e)}")
            return None

def on_anomaly(uid):
    """
    Function to be called when an anomaly is detected.

    This function retrieves the last 500 packets from the buffer and saves them
    to a .pcap file in the forensics directory with the format uid_TIMESTAMP.pcap.

    Args:
        uid (str): Unique identifier for the anomaly

    Returns:
        str: Path to the saved .pcap file or None if saving failed
    """
    global packet_buffer

    if not packet_buffer:
        print("Packet buffer not initialized. Call initialize_buffer() first.")
        return None

    # Get the last 500 packets
    packets = packet_buffer.get_last_n(500)

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{uid}_{timestamp}.pcap"

    # Save the packets
    return packet_buffer.save_packets(packets, filename)

def initialize_buffer(interface, buffer_size=5000):
    """
    Initialize the global packet buffer and start capturing packets.

    Args:
        interface (str): Network interface to capture packets on
        buffer_size (int): Maximum number of packets to keep in the buffer

    Returns:
        RollingPacketBuffer: The initialized packet buffer
    """
    global packet_buffer

    packet_buffer = RollingPacketBuffer(interface, buffer_size)
    packet_buffer.start_capture()
    return packet_buffer

# Global packet buffer instance
packet_buffer = None

if __name__ == "__main__":
    # Example usage
    if len(sys.argv) < 2:
        print("Usage: python live_packet_buffer.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]

    try:
        # Initialize the packet buffer
        buffer = initialize_buffer(interface)

        print("Capturing packets. Press Ctrl+C to stop...")

        # Simulate an anomaly detection after 10 seconds
        time.sleep(10)
        saved_file = on_anomaly("test_anomaly")

        if saved_file:
            print(f"Anomaly packets saved to: {saved_file}")

        # Keep running until interrupted
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        if packet_buffer:
            packet_buffer.stop_capture()
        print("Done.")
    except Exception as e:
        print(f"Error: {str(e)}")
        if packet_buffer:
            packet_buffer.stop_capture()
        sys.exit(1)
