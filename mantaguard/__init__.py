"""
MantaGuard - Network Security Analysis and Anomaly Detection Platform

A comprehensive cybersecurity tool for network traffic analysis, anomaly detection,
and forensic investigation.
"""

__version__ = "0.2.0"
__author__ = "MantaGuard Team"
__description__ = "Network Security Analysis and Anomaly Detection Platform"

# Main package imports
from mantaguard.core import network, ai, security
from mantaguard.utils import config

__all__ = [
    "network",
    "ai", 
    "security",
    "config",
]