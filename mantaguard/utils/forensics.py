#!/usr/bin/env python3
"""
Forensics utilities for MantaGuard.

Extract network flows and connections from PCAP files based on Zeek UIDs
for detailed forensic analysis.
"""

import argparse
import os
import subprocess
import sys
import datetime
import shutil
from pathlib import Path
from typing import Dict, Optional, Tuple

from mantaguard.utils.config import config
from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory

logger = get_logger(__name__)


class ForensicsExtractor:
    """Network forensics extraction utilities."""
    
    def __init__(self):
        self.tshark_available = self._check_tshark_installed()
        if not self.tshark_available:
            logger.warning("TShark not available - PCAP extraction will not work")
    
    def extract_flow_by_uid(
        self,
        uid: str,
        conn_log_path: str,
        pcap_path: str,
        analysis_dir: Optional[str] = None
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Extract network flow for a specific Zeek UID from a PCAP file.
        
        Args:
            uid: Zeek UID to extract
            conn_log_path: Path to Zeek conn.log file
            pcap_path: Path to original PCAP file
            analysis_dir: Optional analysis directory for organizing output
            
        Returns:
            Tuple of (success, message, output_path)
        """
        logger.info(f"Extracting flow for UID: {uid}")
        
        # Validate input files
        if not Path(conn_log_path).exists():
            return False, f"conn.log file not found: {conn_log_path}", None
        
        if not Path(pcap_path).exists():
            return False, f"PCAP file not found: {pcap_path}", None
        
        if not self.tshark_available:
            return False, "TShark is not installed", None
        
        # Find the UID in conn.log
        conn_tuple = self._find_uid_in_conn_log(conn_log_path, uid)
        if not conn_tuple:
            return False, f"UID {uid} not found in conn.log", None
        
        # Build TShark filter
        filter_str = self._build_tshark_filter(conn_tuple)
        logger.debug(f"TShark filter: {filter_str}")
        
        # Determine output path
        output_path = self._get_output_path(uid, analysis_dir)
        
        # Extract packets
        success, message = self._extract_packets(pcap_path, filter_str, output_path)
        
        if success:
            logger.info(f"Successfully extracted flow for UID {uid} to {output_path}")
            return True, message, str(output_path)
        else:
            logger.error(f"Failed to extract flow for UID {uid}: {message}")
            return False, message, None
    
    def _find_uid_in_conn_log(self, conn_log_path: str, target_uid: str) -> Optional[Dict[str, str]]:
        """
        Search for a specific UID in a Zeek conn.log file and extract the 5-tuple.
        
        Args:
            conn_log_path: Path to the Zeek conn.log file
            target_uid: The UID to search for
            
        Returns:
            Dictionary containing the 5-tuple or None if UID not found
        """
        try:
            conn_log_path = Path(conn_log_path)
            
            # Validate file
            if not conn_log_path.exists():
                logger.error(f"conn.log file not found: {conn_log_path}")
                return None
            
            if conn_log_path.stat().st_size == 0:
                logger.error(f"conn.log file is empty: {conn_log_path}")
                return None
            
            with open(conn_log_path, 'r') as f:
                # Find fields line
                fields_line = None
                for line in f:
                    if line.startswith('#fields'):
                        fields_line = line.strip()
                        break
                
                if not fields_line:
                    logger.error(f"Could not find #fields line in conn.log: {conn_log_path}")
                    return None
                
                # Parse field names
                field_names = fields_line.replace('#fields', '').strip().split('\t')
                
                # Find required field indices
                required_fields = ['uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto']
                field_indices = {}
                missing_fields = []
                
                for field in required_fields:
                    try:
                        field_indices[field] = field_names.index(field)
                    except ValueError:
                        missing_fields.append(field)
                
                if missing_fields:
                    logger.error(f"Required fields not found in conn.log: {missing_fields}")
                    return None
                
                # Search for the UID
                f.seek(0)
                for line_num, line in enumerate(f, 1):
                    if line.startswith('#'):
                        continue
                    
                    fields = line.strip().split('\t')
                    
                    # Check if line has enough fields
                    max_idx = max(field_indices.values())
                    if len(fields) <= max_idx:
                        continue
                    
                    if fields[field_indices['uid']] == target_uid:
                        # Found the UID, extract the 5-tuple
                        try:
                            return {
                                'id.orig_h': fields[field_indices['id.orig_h']],
                                'id.orig_p': fields[field_indices['id.orig_p']],
                                'id.resp_h': fields[field_indices['id.resp_h']],
                                'id.resp_p': fields[field_indices['id.resp_p']],
                                'proto': fields[field_indices['proto']].lower()
                            }
                        except Exception as e:
                            logger.error(f"Error extracting fields from line {line_num}: {e}")
                            return None
                
                # UID not found
                logger.warning(f"UID {target_uid} not found in {conn_log_path}")
                return None
                
        except UnicodeDecodeError:
            logger.error(f"conn.log file is not valid text: {conn_log_path}")
            return None
        except Exception as e:
            logger.error(f"Error reading conn.log: {e}")
            return None
    
    def _build_tshark_filter(self, conn_tuple: Dict[str, str]) -> str:
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
        proto = conn_tuple['proto'].lower()
        
        # Protocol number mapping
        proto_numbers = {
            'icmp': 1,
            'tcp': 6,
            'udp': 17,
            'sctp': 132
        }
        
        # Build filter based on protocol
        if proto == 'icmp':
            # ICMP doesn't use ports
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
            # Other protocols
            proto_num = proto_numbers.get(proto)
            if proto_num:
                filter_str = (
                    f"(ip.src == {src_ip} && ip.dst == {dst_ip} && ip.proto == {proto_num}) || "
                    f"(ip.src == {dst_ip} && ip.dst == {src_ip} && ip.proto == {proto_num})"
                )
            else:
                # Fallback to IP addresses only
                filter_str = (
                    f"(ip.src == {src_ip} && ip.dst == {dst_ip}) || "
                    f"(ip.src == {dst_ip} && ip.dst == {src_ip})"
                )
        
        return filter_str
    
    def _check_tshark_installed(self) -> bool:
        """Check if TShark is installed on the system."""
        try:
            result = subprocess.run(
                ["which", "tshark"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            is_installed = result.returncode == 0
            if is_installed:
                logger.debug("TShark is available")
            else:
                logger.warning("TShark is not installed")
            return is_installed
        except Exception as e:
            logger.error(f"Error checking for TShark: {e}")
            return False
    
    def _get_output_path(self, uid: str, analysis_dir: Optional[str] = None) -> Path:
        """
        Get the output path for the extracted PCAP file.
        
        Args:
            uid: Zeek UID
            analysis_dir: Optional analysis directory
            
        Returns:
            Path for the output file
        """
        forensics_dir = config.get_forensics_dir()
        
        if analysis_dir:
            # Create subdirectory matching the analysis
            analysis_dir_name = Path(analysis_dir).name
            output_dir = forensics_dir / analysis_dir_name
        else:
            # Use timestamp-based directory
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = forensics_dir / timestamp
        
        safe_create_directory(output_dir)
        return output_dir / f"{uid}.pcap"
    
    def _extract_packets(self, pcap_path: str, filter_str: str, output_path: Path) -> Tuple[bool, str]:
        """
        Extract packets from a PCAP file using TShark.
        
        Args:
            pcap_path: Path to the original PCAP file
            filter_str: TShark display filter
            output_path: Path to save the extracted packets
            
        Returns:
            Tuple of (success, message)
        """
        pcap_path = Path(pcap_path)
        
        # Validate input file
        if not pcap_path.exists():
            return False, f"PCAP file not found: {pcap_path}"
        
        if pcap_path.stat().st_size == 0:
            return False, f"PCAP file is empty: {pcap_path}"
        
        # Ensure output directory exists
        safe_create_directory(output_path.parent)
        
        try:
            # Build TShark command
            command = [
                "tshark", 
                "-r", str(pcap_path),
                "-Y", filter_str,
                "-w", str(output_path)
            ]
            
            logger.debug(f"Running TShark command: {' '.join(command)}")
            
            # Run TShark
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Check for errors
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                return False, f"TShark error (code {result.returncode}): {error_msg}"
            
            # Check if output file was created
            if not output_path.exists():
                return False, f"TShark did not create output file: {output_path}"
            
            if output_path.stat().st_size == 0:
                return False, "No packets matched the filter - empty output file"
            
            # Get packet count for success message
            packet_count = self._get_packet_count(output_path)
            return True, f"Successfully extracted {packet_count} packets"
            
        except subprocess.TimeoutExpired:
            return False, "TShark extraction timed out after 5 minutes"
        except Exception as e:
            return False, f"Error running TShark: {str(e)}"
    
    def _get_packet_count(self, pcap_path: Path) -> int:
        """
        Get the number of packets in a PCAP file using TShark.
        
        Args:
            pcap_path: Path to the PCAP file
            
        Returns:
            Number of packets in the file
        """
        try:
            command = ["tshark", "-r", str(pcap_path), "-c", "1000000", "-T", "fields"]
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return len(result.stdout.strip().split('\n'))
            else:
                return 0
        except Exception:
            return 0


# Global extractor instance
_extractor = ForensicsExtractor()


# Legacy function for backward compatibility
def extract_flow_by_uid(
    uid: str,
    conn_log_path: str,
    pcap_path: str,
    analysis_dir: Optional[str] = None
) -> Tuple[bool, str, Optional[str]]:
    """
    Legacy function for backward compatibility.
    
    Args:
        uid: Zeek UID to extract
        conn_log_path: Path to Zeek conn.log file
        pcap_path: Path to original PCAP file
        analysis_dir: Optional analysis directory
        
    Returns:
        Tuple of (success, message, output_path)
    """
    return _extractor.extract_flow_by_uid(uid, conn_log_path, pcap_path, analysis_dir)


def main():
    """Command-line interface for forensics extraction."""
    parser = argparse.ArgumentParser(
        description="Extract network flow associated with a Zeek UID from a PCAP file."
    )
    parser.add_argument("--uid", required=True, help="Zeek UID to extract")
    parser.add_argument("--conn-log", required=True, help="Path to Zeek conn.log file")
    parser.add_argument("--pcap", required=True, help="Path to original PCAP file")
    parser.add_argument("--analysis-dir", help="Path to the analysis directory")
    
    args = parser.parse_args()
    
    # Extract the flow
    success, message, output_path = _extractor.extract_flow_by_uid(
        args.uid, args.conn_log, args.pcap, args.analysis_dir
    )
    
    if success:
        print(f"Success! {message}")
        print(f"Output file: {output_path}")
        sys.exit(0)
    else:
        print(f"Error: {message}")
        sys.exit(1)


if __name__ == "__main__":
    main()