"""
Network utility functions for MantaGuard.
"""

import netifaces
from typing import List
from .logger import get_logger

logger = get_logger(__name__)


def get_network_interfaces() -> List[str]:
    """
    Get available network interfaces on the system.
    
    Returns:
        List of network interface names
    """
    try:
        interfaces = netifaces.interfaces()
        # Filter out loopback interface for better UX
        filtered_interfaces = [iface for iface in interfaces if iface != 'lo']
        # If no interfaces after filtering, return all
        result = filtered_interfaces if filtered_interfaces else interfaces
        logger.debug(f"Found network interfaces: {result}")
        return result
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        # Fallback to common interface names if netifaces fails
        fallback = ['eth0', 'wlan0', 'enp0s3', 'wlp3s0']
        logger.warning(f"Using fallback interfaces: {fallback}")
        return fallback


def validate_interface(interface: str) -> bool:
    """
    Validate if a network interface exists on the system.
    
    Args:
        interface: Network interface name to validate
        
    Returns:
        True if interface exists, False otherwise
    """
    try:
        available_interfaces = get_network_interfaces()
        is_valid = interface in available_interfaces
        logger.debug(f"Interface {interface} validation: {is_valid}")
        return is_valid
    except Exception as e:
        logger.error(f"Error validating interface {interface}: {e}")
        return False