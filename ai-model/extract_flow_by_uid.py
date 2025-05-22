#!/usr/bin/env python3
"""
extract_flow_by_uid.py - Extract the full network connection associated with a Zeek UID from a PCAP file.

This script searches for a specific UID in a Zeek conn.log file, extracts the 5-tuple
(source IP, source port, destination IP, destination port, protocol), and uses TShark
to extract the matching packets from the original PCAP file.

Usage:
    python extract_flow_by_uid.py --uid <uid> --conn-log <path/to/conn.log> --pcap <path/to/original.pcap>
"""

import argparse
import os
import subprocess
import sys
import datetime
import shutil
from typing import Dict, Optional, Tuple


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract the full network connection associated with a Zeek UID from a PCAP file."
    )
    parser.add_argument("--uid", required=True, help="Zeek UID to extract")
    parser.add_argument("--conn-log", required=True, help="Path to Zeek conn.log file")
    parser.add_argument("--pcap", required=True, help="Path to original PCAP file")

    return parser.parse_args()


def find_uid_in_conn_log(conn_log_path: str, target_uid: str) -> Optional[Dict[str, str]]:
    """
    Search for a specific UID in a Zeek conn.log file and extract the 5-tuple.

    Args:
        conn_log_path: Path to the Zeek conn.log file
        target_uid: The UID to search for

    Returns:
        Dictionary containing the 5-tuple (source IP, source port, destination IP, 
        destination port, protocol) or None if UID not found
    """
    try:
        # Check if file exists
        if not os.path.exists(conn_log_path):
            print(f"Error: conn.log file not found: {conn_log_path}")
            return None

        # Check if file is readable
        if not os.access(conn_log_path, os.R_OK):
            print(f"Error: conn.log file is not readable: {conn_log_path}")
            return None

        # Check file size
        if os.path.getsize(conn_log_path) == 0:
            print(f"Error: conn.log file is empty: {conn_log_path}")
            return None

        with open(conn_log_path, 'r') as f:
            # Skip comment lines and find the fields line
            fields_line = None
            for line in f:
                if line.startswith('#fields'):
                    fields_line = line.strip()
                    break

            if not fields_line:
                print(f"Error: Could not find #fields line in conn.log: {conn_log_path}")
                print("This may not be a valid Zeek conn.log file or it may have a different format.")
                return None

            # Parse field names
            field_names = fields_line.replace('#fields', '').strip().split('\t')

            # Find indices for the fields we need
            required_fields = ['uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto']
            field_indices = {}

            missing_fields = []
            for field in required_fields:
                try:
                    field_indices[field] = field_names.index(field)
                except ValueError:
                    missing_fields.append(field)

            if missing_fields:
                print(f"Error: Required fields not found in conn.log: {', '.join(missing_fields)}")
                print(f"Available fields: {', '.join(field_names)}")
                return None

            # Reset file pointer and search for the UID
            f.seek(0)
            for line_num, line in enumerate(f, 1):
                if line.startswith('#'):
                    continue

                fields = line.strip().split('\t')

                # Check if line has enough fields
                max_idx = max(field_indices.values())
                if len(fields) <= max_idx:
                    print(f"Warning: Line {line_num} has fewer fields than expected. Skipping.")
                    continue

                if fields[field_indices['uid']] == target_uid:
                    # Found the UID, extract the 5-tuple
                    try:
                        return {
                            'id.orig_h': fields[field_indices['id.orig_h']],
                            'id.orig_p': fields[field_indices['id.orig_p']],
                            'id.resp_h': fields[field_indices['id.resp_h']],
                            'id.resp_p': fields[field_indices['id.resp_p']],
                            'proto': fields[field_indices['proto']].lower()  # tshark uses lowercase protocol names
                        }
                    except Exception as e:
                        print(f"Error extracting fields from line {line_num}: {e}")
                        print(f"Line content: {line.strip()}")
                        return None

            # UID not found
            print(f"Error: UID {target_uid} not found in {conn_log_path}")
            return None

    except UnicodeDecodeError:
        print(f"Error: conn.log file is not a valid text file: {conn_log_path}")
        return None
    except Exception as e:
        print(f"Error reading conn.log: {e}")
        return None


def build_tshark_filter(conn_tuple: Dict[str, str]) -> str:
    """
    Build a TShark display filter from a 5-tuple.

    Args:
        conn_tuple: Dictionary containing the 5-tuple

    Returns:
        TShark display filter string
    """
    src_ip = conn_tuple['id.orig_h']
    src_port = conn_tuple['id.orig_p']
    dst_ip = conn_tuple['id.resp_h']
    dst_port = conn_tuple['id.resp_p']
    proto = conn_tuple['proto'].lower()  # Ensure lowercase for consistency

    # Protocol number mapping (common protocols)
    proto_numbers = {
        'icmp': 1,
        'tcp': 6,
        'udp': 17,
        'sctp': 132
    }

    # Build the filter based on protocol
    if proto == 'icmp':
        # ICMP doesn't use ports, so we only filter by IP addresses
        filter_str = (
            f"(ip.src == {src_ip} && ip.dst == {dst_ip} && icmp) || "
            f"(ip.src == {dst_ip} && ip.dst == {src_ip} && icmp)"
        )
    elif proto in ['tcp', 'udp']:
        # TCP and UDP use ports
        filter_str = (
            f"(ip.src == {src_ip} && ip.dst == {dst_ip} && "
            f"{proto}.srcport == {src_port} && {proto}.dstport == {dst_port}) || "
            f"(ip.src == {dst_ip} && ip.dst == {src_ip} && "
            f"{proto}.srcport == {dst_port} && {proto}.dstport == {src_port})"
        )
    else:
        # For other protocols, use IP addresses and protocol number if available
        proto_num = proto_numbers.get(proto)
        if proto_num:
            filter_str = (
                f"(ip.src == {src_ip} && ip.dst == {dst_ip} && ip.proto == {proto_num}) || "
                f"(ip.src == {dst_ip} && ip.dst == {src_ip} && ip.proto == {proto_num})"
            )
        else:
            # If protocol number is unknown, just use IP addresses
            filter_str = (
                f"(ip.src == {src_ip} && ip.dst == {dst_ip}) || "
                f"(ip.src == {dst_ip} && ip.dst == {src_ip})"
            )

    return filter_str


def check_tshark_installed() -> bool:
    """Check if TShark is installed on the system."""
    try:
        result = subprocess.run(
            ["which", "tshark"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def extract_packets(pcap_path: str, filter_str: str, output_path: str) -> Tuple[bool, str]:
    """
    Extract packets from a PCAP file using TShark.

    Args:
        pcap_path: Path to the original PCAP file
        filter_str: TShark display filter
        output_path: Path to save the extracted packets

    Returns:
        Tuple of (success, error_message)
    """
    # Check if TShark is installed
    if not check_tshark_installed():
        return False, "TShark is not installed. Please install it and try again."

    # Check if PCAP file exists
    if not os.path.exists(pcap_path):
        return False, f"PCAP file not found: {pcap_path}"

    # Check if PCAP file is readable
    if not os.access(pcap_path, os.R_OK):
        return False, f"PCAP file is not readable: {pcap_path}"

    # Check if PCAP file is empty
    if os.path.getsize(pcap_path) == 0:
        return False, f"PCAP file is empty: {pcap_path}"

    # Check if output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            return False, f"Failed to create output directory: {output_dir}. Error: {e}"

    # Check if output directory is writable
    if output_dir and not os.access(output_dir, os.W_OK):
        return False, f"Output directory is not writable: {output_dir}"

    try:
        # Create the command
        command = [
            "tshark", 
            "-r", pcap_path,
            "-Y", filter_str,
            "-w", output_path
        ]

        # Print the command for debugging
        print(f"Running command: {' '.join(command)}")

        # Run TShark
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Check if TShark returned an error
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return False, f"TShark error (code {result.returncode}): {error_msg}"

        # Check if the output file was created and has content
        if not os.path.exists(output_path):
            return False, f"TShark did not create the output file: {output_path}"

        if os.path.getsize(output_path) == 0:
            return False, f"No packets matched the filter. The output file is empty: {output_path}"

        # Success
        packet_count = get_packet_count(output_path)
        return True, f"Successfully extracted {packet_count} packets to {output_path}"
    except Exception as e:
        return False, f"Error running TShark: {str(e)}"


def get_packet_count(pcap_path: str) -> int:
    """
    Get the number of packets in a PCAP file using TShark.

    Args:
        pcap_path: Path to the PCAP file

    Returns:
        Number of packets in the PCAP file, or 0 if an error occurs
    """
    try:
        # Run TShark to count packets
        command = ["tshark", "-r", pcap_path, "-c", "1000000", "-T", "fields"]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Count the number of lines in the output
        if result.returncode == 0:
            return len(result.stdout.strip().split('\n'))
        else:
            return 0
    except Exception:
        return 0


def main():
    """Main function."""
    # Parse command-line arguments
    args = parse_arguments()

    # Check if files exist
    if not os.path.exists(args.conn_log):
        print(f"Error: conn.log file not found: {args.conn_log}")
        sys.exit(1)

    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)

    # Find the UID in the conn.log
    print(f"Searching for UID {args.uid} in {args.conn_log}...")
    conn_tuple = find_uid_in_conn_log(args.conn_log, args.uid)

    if not conn_tuple:
        print(f"Error: UID {args.uid} not found in {args.conn_log}")
        sys.exit(1)

    # Print the 5-tuple
    print("\nExtracted 5-tuple:")
    print(f"  Source IP:   {conn_tuple['id.orig_h']}")
    print(f"  Source Port: {conn_tuple['id.orig_p']}")
    print(f"  Dest IP:     {conn_tuple['id.resp_h']}")
    print(f"  Dest Port:   {conn_tuple['id.resp_p']}")
    print(f"  Protocol:    {conn_tuple['proto']}")

    # Build the TShark filter
    filter_str = build_tshark_filter(conn_tuple)
    print(f"\nTShark filter: {filter_str}")

    # Create the output directory if it doesn't exist
    forensics_dir = os.path.join("ai-model", "forensics")
    os.makedirs(forensics_dir, exist_ok=True)

    # Generate the output filename with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{args.uid}_{timestamp}.pcap"
    output_path = os.path.join(forensics_dir, output_filename)

    # Extract the packets
    print(f"\nExtracting packets from {args.pcap}...")
    success, error_message = extract_packets(args.pcap, filter_str, output_path)

    if not success:
        print(f"Error: {error_message}")
        sys.exit(1)

    print(f"\nSuccess! Extracted packets saved to: {output_path}")


if __name__ == "__main__":
    main()
