"""
File and path utility functions for MantaGuard.
"""

import os
import shutil
import glob
from pathlib import Path
from typing import List, Optional
from .config import config
from .logger import get_logger

logger = get_logger(__name__)


def safe_create_directory(directory: Path) -> bool:
    """
    Safely create a directory with error handling.
    
    Args:
        directory: Path to directory to create
        
    Returns:
        True if successful, False otherwise
    """
    try:
        directory.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Created directory: {directory}")
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {directory}: {e}")
        return False


def safe_copy_file(src: Path, dst: Path) -> bool:
    """
    Safely copy a file with error handling.
    
    Args:
        src: Source file path
        dst: Destination file path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure destination directory exists
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        logger.debug(f"Copied file from {src} to {dst}")
        return True
    except Exception as e:
        logger.error(f"Failed to copy file from {src} to {dst}: {e}")
        return False


def safe_move_file(src: Path, dst: Path) -> bool:
    """
    Safely move a file with error handling.
    
    Args:
        src: Source file path
        dst: Destination file path
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure destination directory exists
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        logger.info(f"Moved file from {src} to {dst}")
        return True
    except Exception as e:
        logger.error(f"Failed to move file from {src} to {dst}: {e}")
        return False


def find_files_by_pattern(directory: Path, pattern: str) -> List[Path]:
    """
    Find files matching a pattern in a directory.
    
    Args:
        directory: Directory to search in
        pattern: Glob pattern to match
        
    Returns:
        List of matching file paths
    """
    try:
        search_pattern = directory / pattern
        matches = [Path(f) for f in glob.glob(str(search_pattern))]
        logger.debug(f"Found {len(matches)} files matching pattern {pattern} in {directory}")
        return matches
    except Exception as e:
        logger.error(f"Error searching for pattern {pattern} in {directory}: {e}")
        return []


def get_latest_file(directory: Path, pattern: str = "*") -> Optional[Path]:
    """
    Get the most recently modified file matching a pattern.
    
    Args:
        directory: Directory to search in
        pattern: Glob pattern to match (default: all files)
        
    Returns:
        Path to the latest file, or None if no files found
    """
    try:
        files = find_files_by_pattern(directory, pattern)
        if not files:
            return None
        
        latest_file = max(files, key=lambda f: f.stat().st_mtime)
        logger.debug(f"Latest file in {directory}: {latest_file}")
        return latest_file
    except Exception as e:
        logger.error(f"Error finding latest file in {directory}: {e}")
        return None


def cleanup_old_files(directory: Path, pattern: str, keep_count: int = 5) -> int:
    """
    Clean up old files, keeping only the most recent ones.
    
    Args:
        directory: Directory to clean up
        pattern: Glob pattern to match
        keep_count: Number of recent files to keep
        
    Returns:
        Number of files deleted
    """
    try:
        files = find_files_by_pattern(directory, pattern)
        if len(files) <= keep_count:
            return 0
        
        # Sort by modification time (newest first)
        files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        
        # Delete old files
        files_to_delete = files[keep_count:]
        deleted_count = 0
        
        for file_path in files_to_delete:
            try:
                file_path.unlink()
                deleted_count += 1
                logger.info(f"Deleted old file: {file_path}")
            except Exception as e:
                logger.error(f"Failed to delete file {file_path}: {e}")
        
        return deleted_count
    except Exception as e:
        logger.error(f"Error during cleanup of {directory}: {e}")
        return 0