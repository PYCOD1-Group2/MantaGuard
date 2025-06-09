#!/usr/bin/env python3
"""
PCAP file metadata management for MantaGuard.

This module handles the creation, updating, and retrieval of metadata
for PCAP files to track their origin and analysis results.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List, Tuple

from mantaguard.utils.config import config
from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory

logger = get_logger(__name__)


def get_metadata_path(pcap_path: str) -> Path:
    """
    Get the metadata file path for a given PCAP file.
    
    Args:
        pcap_path: Path to the PCAP file
        
    Returns:
        Path to the corresponding metadata JSON file
    """
    # Get the base path without extension and add .json
    pcap_path = Path(pcap_path)
    base_path = pcap_path.with_suffix('')
    return base_path.with_suffix('.json')


def create_metadata(
    pcap_path: str,
    origin_type: str,
    interface: Optional[str] = None,
    duration_seconds: Optional[int] = None,
    original_filename: Optional[str] = None,
    file_size_bytes: Optional[int] = None,
    capture_method: Optional[str] = None
) -> Dict:
    """
    Create metadata for a PCAP file.
    
    Args:
        pcap_path: Path to the PCAP file
        origin_type: 'timed_capture' or 'upload'
        interface: Network interface for timed captures
        duration_seconds: Capture duration for timed captures
        original_filename: Original filename for uploads
        file_size_bytes: File size in bytes
        capture_method: Method used for capture (tshark, pyshark)
        
    Returns:
        Created metadata dictionary
    """
    pcap_path = Path(pcap_path)
    pcap_filename = pcap_path.name
    timestamp = datetime.now().isoformat() + 'Z'
    
    metadata = {
        "pcap_filename": pcap_filename,
        "pcap_path": str(pcap_path.absolute()),
        "origin_type": origin_type,
        "timestamp": timestamp,
        "metadata": {},
        "analysis_results": []
    }
    
    # Add origin-specific metadata
    if origin_type == "timed_capture":
        metadata["metadata"] = {
            "interface": interface,
            "duration_seconds": duration_seconds,
            "capture_method": capture_method or "tshark"
        }
    elif origin_type == "upload":
        metadata["metadata"] = {
            "original_filename": original_filename,
            "file_size_bytes": file_size_bytes or (pcap_path.stat().st_size if pcap_path.exists() else None),
            "upload_source": "user_upload"
        }
    
    # Save metadata to file
    metadata_path = get_metadata_path(pcap_path)
    if save_metadata(metadata_path, metadata):
        logger.debug(f"Created metadata for PCAP: {pcap_path}")
    else:
        logger.warning(f"Failed to save metadata for PCAP: {pcap_path}")
    
    return metadata


def update_metadata_with_analysis(
    pcap_path: str,
    analysis_dir: str,
    csv_path: str,
    anomaly_count: int,
    total_connections: int
) -> Optional[Dict]:
    """
    Update PCAP metadata with analysis results.
    
    Args:
        pcap_path: Path to the PCAP file
        analysis_dir: Path to the analysis results directory
        csv_path: Path to the prediction results CSV
        anomaly_count: Number of anomalies detected
        total_connections: Total number of connections analyzed
        
    Returns:
        Updated metadata dictionary, or None if metadata file not found
    """
    metadata_path = get_metadata_path(pcap_path)
    
    if not metadata_path.exists():
        logger.warning(f"No metadata file found for {pcap_path}")
        return None
    
    metadata = load_metadata(pcap_path)
    if not metadata:
        return None
    
    # Create analysis result entry
    analysis_result = {
        "analysis_dir": str(Path(analysis_dir).absolute()),
        "csv_path": str(Path(csv_path).absolute()),
        "anomaly_count": anomaly_count,
        "total_connections": total_connections,
        "analysis_timestamp": datetime.now().isoformat() + 'Z',
        "analysis_id": Path(analysis_dir).name
    }
    
    # Add to analysis results list
    metadata["analysis_results"].append(analysis_result)
    
    # Save updated metadata
    if save_metadata(metadata_path, metadata):
        logger.debug(f"Updated metadata with analysis results for {pcap_path}")
    else:
        logger.warning(f"Failed to update metadata for {pcap_path}")
    
    return metadata


def load_metadata(pcap_path: str) -> Optional[Dict]:
    """
    Load metadata for a PCAP file.
    
    Args:
        pcap_path: Path to the PCAP file
        
    Returns:
        Metadata dictionary, or None if not found or invalid
    """
    metadata_path = get_metadata_path(pcap_path)
    
    if not metadata_path.exists():
        return None
    
    try:
        with open(metadata_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading metadata from {metadata_path}: {e}")
        return None


def save_metadata(metadata_path: Path, metadata: Dict) -> bool:
    """
    Save metadata to a JSON file.
    
    Args:
        metadata_path: Path to save the metadata file
        metadata: Metadata dictionary to save
        
    Returns:
        True if successful, False otherwise
    """
    try:
        safe_create_directory(metadata_path.parent)
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2, sort_keys=True)
        return True
    except (IOError, TypeError) as e:
        logger.error(f"Error saving metadata to {metadata_path}: {e}")
        return False


def get_pcap_origin_info(pcap_path: str) -> Dict:
    """
    Get human-readable origin information for a PCAP file.
    
    Args:
        pcap_path: Path to the PCAP file
        
    Returns:
        Origin information with keys 'source_type', 'description', 'details'
    """
    metadata = load_metadata(pcap_path)
    
    if not metadata:
        # Fallback: try to determine from filename
        filename = Path(pcap_path).name
        if filename.startswith('capture_'):
            return {
                'source_type': 'timed_capture',
                'description': 'Network Capture',
                'details': 'Timed network capture (metadata unavailable)'
            }
        elif filename.startswith('uploaded_'):
            return {
                'source_type': 'upload',
                'description': 'File Upload',
                'details': 'Uploaded PCAP file (metadata unavailable)'
            }
        else:
            return {
                'source_type': 'unknown',
                'description': 'Unknown Source',
                'details': 'Origin unknown'
            }
    
    origin_type = metadata.get('origin_type', 'unknown')
    metadata_info = metadata.get('metadata', {})
    
    if origin_type == 'timed_capture':
        interface = metadata_info.get('interface', 'unknown')
        duration = metadata_info.get('duration_seconds', 0)
        return {
            'source_type': 'timed_capture',
            'description': f'Captured on {interface}',
            'details': f'Network capture on interface {interface} for {duration} seconds'
        }
    elif origin_type == 'upload':
        original_filename = metadata_info.get('original_filename', 'unknown')
        return {
            'source_type': 'upload',
            'description': f'Uploaded: {original_filename}',
            'details': f'User uploaded file: {original_filename}'
        }
    else:
        return {
            'source_type': origin_type,
            'description': f'Source: {origin_type}',
            'details': f'PCAP from {origin_type}'
        }


def list_pcaps_with_metadata(pcap_dir: str) -> List[Tuple[str, Dict]]:
    """
    List all PCAP files in a directory with their metadata.
    
    Args:
        pcap_dir: Directory to search for PCAP files
        
    Returns:
        List of (pcap_path, metadata) tuples
    """
    pcaps_with_metadata = []
    pcap_dir = Path(pcap_dir)
    
    if not pcap_dir.exists():
        return pcaps_with_metadata
    
    for pcap_file in pcap_dir.glob('*.pcap*'):
        if pcap_file.suffix in ['.pcap', '.pcapng']:
            metadata = load_metadata(str(pcap_file))
            
            # If no metadata exists, create basic info from filename
            if not metadata:
                filename = pcap_file.name
                if filename.startswith('capture_'):
                    metadata = {
                        'pcap_filename': filename,
                        'origin_type': 'timed_capture',
                        'metadata': {'interface': 'unknown'},
                        'analysis_results': []
                    }
                elif filename.startswith('uploaded_'):
                    metadata = {
                        'pcap_filename': filename,
                        'origin_type': 'upload',
                        'metadata': {'original_filename': filename},
                        'analysis_results': []
                    }
                else:
                    metadata = {
                        'pcap_filename': filename,
                        'origin_type': 'unknown',
                        'metadata': {},
                        'analysis_results': []
                    }
            
            pcaps_with_metadata.append((str(pcap_file), metadata))
    
    # Sort by timestamp (newest first)
    pcaps_with_metadata.sort(
        key=lambda x: x[1].get('timestamp', ''), 
        reverse=True
    )
    
    return pcaps_with_metadata


def find_pcap_for_analysis(analysis_dir: str, pcap_dir: str) -> Optional[Tuple[str, Dict]]:
    """
    Find the PCAP file that generated a specific analysis.
    
    Args:
        analysis_dir: Path to the analysis directory
        pcap_dir: Directory containing PCAP files
        
    Returns:
        (pcap_path, metadata) if found, None otherwise
    """
    analysis_id = Path(analysis_dir).name
    
    # Search through all PCAP metadata files
    for pcap_path, metadata in list_pcaps_with_metadata(pcap_dir):
        for analysis_result in metadata.get('analysis_results', []):
            if analysis_result.get('analysis_id') == analysis_id:
                return (pcap_path, metadata)
    
    return None


def get_analysis_origin_info(analysis_dir: str, pcap_dir: str) -> Dict:
    """
    Get origin information for a specific analysis directory.
    
    Args:
        analysis_dir: Path to the analysis directory
        pcap_dir: Directory containing PCAP files
        
    Returns:
        Origin information for the analysis
    """
    result = find_pcap_for_analysis(analysis_dir, pcap_dir)
    
    if result:
        pcap_path, metadata = result
        return get_pcap_origin_info(pcap_path)
    else:
        return {
            'source_type': 'unknown',
            'description': 'Unknown Source',
            'details': 'Could not determine PCAP origin'
        }