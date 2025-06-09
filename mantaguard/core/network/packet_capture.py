#!/usr/bin/env python3
"""
Network packet capture functionality for MantaGuard.

Handles live packet capture from network interfaces using multiple methods
including tshark and pyshark with proper error handling and metadata creation.
"""

import os
import sys
import time
import subprocess
import pyshark
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from mantaguard.utils.config import config
from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory

logger = get_logger(__name__)


class PacketCapture:
    """Network packet capture handler."""
    
    def __init__(self):
        self.capture_methods = ['tshark', 'pyshark']
        self.default_method = 'tshark'
    
    def run_capture(
        self, 
        interface: str, 
        duration: int, 
        output_path: Optional[str] = None,
        method: Optional[str] = None
    ) -> str:
        """
        Capture live packets on a given interface for a specified duration.

        Args:
            interface: Network interface to capture packets on (e.g., 'eth0', 'Wi-Fi')
            duration: Duration in seconds to capture packets
            output_path: Path where the PCAP file will be saved. If None, auto-generates path.
            method: Capture method to use ('tshark' or 'pyshark'). If None, uses default.

        Returns:
            Path to the saved PCAP file

        Raises:
            Exception: If packet capture fails with all available methods
        """
        # Generate output path if not provided
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = config.get_pcaps_dir() / f"capture_{timestamp}.pcap"
        else:
            output_path = Path(output_path)

        # Ensure output directory exists
        safe_create_directory(output_path.parent)

        logger.info(f"Starting packet capture on interface '{interface}' for {duration} seconds")
        logger.debug(f"Output path: {output_path}")

        # Determine capture method
        capture_method = method or self.default_method
        
        try:
            if capture_method == 'tshark':
                result_path = self._capture_with_tshark(interface, duration, output_path)
            elif capture_method == 'pyshark':
                result_path = self._capture_with_pyshark(interface, duration, output_path)
            else:
                raise ValueError(f"Unknown capture method: {capture_method}")
            
            # Create metadata for the captured PCAP
            self._create_capture_metadata(result_path, interface, duration, capture_method)
            
            return str(result_path)
            
        except Exception as e:
            logger.error(f"Primary capture method '{capture_method}' failed: {e}")
            
            # Try fallback method if primary failed
            fallback_methods = [m for m in self.capture_methods if m != capture_method]
            
            for fallback_method in fallback_methods:
                try:
                    logger.info(f"Trying fallback capture method: {fallback_method}")
                    
                    if fallback_method == 'tshark':
                        result_path = self._capture_with_tshark(interface, duration, output_path)
                    elif fallback_method == 'pyshark':
                        result_path = self._capture_with_pyshark(interface, duration, output_path)
                    
                    # Create metadata for the captured PCAP
                    self._create_capture_metadata(result_path, interface, duration, fallback_method)
                    
                    return str(result_path)
                    
                except Exception as fallback_error:
                    logger.error(f"Fallback method '{fallback_method}' also failed: {fallback_error}")
                    continue
            
            # If all methods failed, raise the original exception
            raise Exception(f"All capture methods failed. Last error: {str(e)}")

    def _capture_with_tshark(self, interface: str, duration: int, output_path: Path) -> Path:
        """
        Capture packets using tshark.
        
        Args:
            interface: Network interface to capture from
            duration: Capture duration in seconds  
            output_path: Output file path
            
        Returns:
            Path to captured file
            
        Raises:
            Exception: If tshark capture fails
        """
        logger.debug(f"Using tshark for packet capture")
        
        # Build tshark command
        tshark_cmd = f"tshark -i {interface} -a duration:{duration} -w {output_path}"
        logger.debug(f"Running command: {tshark_cmd}")

        try:
            # Run tshark with timeout (add buffer to duration)
            process = subprocess.run(
                tshark_cmd, 
                shell=True, 
                timeout=duration + 10,
                capture_output=True,
                text=True
            )

            if process.returncode != 0 and process.returncode != 124:  # 124 is timeout exit code
                error_msg = f"tshark failed with return code {process.returncode}"
                if process.stderr:
                    error_msg += f": {process.stderr}"
                raise Exception(error_msg)

            logger.info(f"tshark capture completed successfully")
            return output_path

        except subprocess.TimeoutExpired:
            logger.info(f"tshark capture completed (timeout after {duration + 10} seconds)")
            return output_path
        except Exception as e:
            logger.error(f"tshark capture failed: {e}")
            raise

    def _capture_with_pyshark(self, interface: str, duration: int, output_path: Path) -> Path:
        """
        Capture packets using pyshark as fallback.
        
        Args:
            interface: Network interface to capture from
            duration: Capture duration in seconds
            output_path: Output file path
            
        Returns:
            Path to captured file
            
        Raises:
            Exception: If pyshark capture fails
        """
        logger.debug(f"Using pyshark for packet capture")
        
        try:
            # Initialize the capture
            capture = pyshark.LiveCapture(interface=interface, output_file=str(output_path))

            logger.debug(f"Starting pyshark capture for {duration} seconds")
            # Use sniff with timeout
            capture.sniff(packet_count=1000, timeout=duration)

            # Close the capture
            capture.close()

            logger.info(f"pyshark capture completed successfully")
            return output_path

        except Exception as e:
            logger.error(f"pyshark capture failed: {e}")
            raise

    def _create_capture_metadata(
        self, 
        pcap_path: Path, 
        interface: str, 
        duration: int, 
        method: str
    ) -> None:
        """
        Create metadata for the captured PCAP file.
        
        Args:
            pcap_path: Path to the captured PCAP file
            interface: Network interface used for capture
            duration: Capture duration in seconds
            method: Capture method used
        """
        try:
            # Import metadata functions
            from mantaguard.data.models.metadata import create_metadata

            # Create metadata
            create_metadata(
                pcap_path=str(pcap_path),
                origin_type="timed_capture",
                interface=interface,
                duration_seconds=duration,
                capture_method=method
            )
            logger.debug(f"Created metadata for capture: {pcap_path}")
            
        except Exception as e:
            logger.warning(f"Failed to create capture metadata: {e}")


# Legacy function for backward compatibility
def run_capture(interface: str, duration: int, output_path: str) -> str:
    """
    Legacy function for backward compatibility.
    
    Args:
        interface: Network interface to capture packets on
        duration: Duration in seconds to capture packets  
        output_path: Path where the PCAP file will be saved
        
    Returns:
        Path to the saved PCAP file
    """
    capture = PacketCapture()
    return capture.run_capture(interface, duration, output_path)