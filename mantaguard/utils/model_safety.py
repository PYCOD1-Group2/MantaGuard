#!/usr/bin/env python3
"""
Model safety utilities for MantaGuard.

This module provides functionality to safely manage model training,
including backups, validation, and rollback capabilities.
"""

import os
import json
import shutil
import psutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import joblib
import threading
import time

from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory

logger = get_logger(__name__)

# Global lock for training operations
_training_lock = threading.Lock()
_current_training_task = None


class ModelSafetyManager:
    """Manages model safety operations including backups and validation."""
    
    def __init__(self, model_dir: str = None):
        """
        Initialize safety manager.
        
        Args:
            model_dir: Directory containing model files
        """
        if model_dir is None:
            project_root = Path(__file__).parent.parent.parent
            self.model_dir = project_root / "data" / "output" / "ocsvm_model"
        else:
            self.model_dir = Path(model_dir)
            
        self.retrained_dir = self.model_dir.parent / "retrained_model"
        self.backup_dir = self.model_dir.parent / "model_backups"
        
        # Ensure backup directory exists
        safe_create_directory(self.backup_dir)
    
    def check_system_resources(self, min_memory_gb: float = 1.0, min_disk_gb: float = 5.0) -> Dict:
        """
        Check if system has sufficient resources for training.
        
        Args:
            min_memory_gb: Minimum required memory in GB
            min_disk_gb: Minimum required disk space in GB
            
        Returns:
            Dictionary with resource check results
        """
        try:
            # Check memory
            memory = psutil.virtual_memory()
            available_memory_gb = memory.available / (1024**3)
            
            # Check disk space
            disk = psutil.disk_usage(str(self.model_dir))
            available_disk_gb = disk.free / (1024**3)
            
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            results = {
                'memory_available_gb': round(available_memory_gb, 2),
                'memory_sufficient': available_memory_gb >= min_memory_gb,
                'disk_available_gb': round(available_disk_gb, 2),
                'disk_sufficient': available_disk_gb >= min_disk_gb,
                'cpu_usage_percent': cpu_percent,
                'cpu_available': cpu_percent < 90,
                'overall_ready': (
                    available_memory_gb >= min_memory_gb and 
                    available_disk_gb >= min_disk_gb and 
                    cpu_percent < 90
                )
            }
            
            logger.info(f"Resource check: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Error checking system resources: {e}")
            return {
                'memory_available_gb': 0,
                'memory_sufficient': False,
                'disk_available_gb': 0,
                'disk_sufficient': False,
                'cpu_usage_percent': 100,
                'cpu_available': False,
                'overall_ready': False,
                'error': str(e)
            }
    
    def is_training_in_progress(self) -> bool:
        """Check if training is currently in progress."""
        return _current_training_task is not None
    
    def acquire_training_lock(self, task_id: str) -> bool:
        """
        Acquire training lock to prevent concurrent training.
        
        Args:
            task_id: Unique identifier for the training task
            
        Returns:
            True if lock acquired, False if another training is in progress
        """
        global _current_training_task
        
        with _training_lock:
            if _current_training_task is None:
                _current_training_task = task_id
                logger.info(f"Training lock acquired for task: {task_id}")
                return True
            else:
                logger.warning(f"Training already in progress: {_current_training_task}")
                return False
    
    def release_training_lock(self, task_id: str) -> None:
        """
        Release training lock.
        
        Args:
            task_id: Unique identifier for the training task
        """
        global _current_training_task
        
        with _training_lock:
            if _current_training_task == task_id:
                _current_training_task = None
                logger.info(f"Training lock released for task: {task_id}")
            else:
                logger.warning(f"Attempted to release lock for {task_id}, but current task is {_current_training_task}")
    
    def create_model_backup(self, backup_name: str = None) -> str:
        """
        Create a backup of current model files.
        
        Args:
            backup_name: Optional name for the backup
            
        Returns:
            Path to the backup directory
        """
        try:
            if backup_name is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"backup_{timestamp}"
            
            backup_path = self.backup_dir / backup_name
            safe_create_directory(backup_path)
            
            # Files to backup
            files_to_backup = [
                "ocsvm_model.pkl",
                "scaler.pkl", 
                "encoders.pkl",
                "labeled_anomalies.csv"
            ]
            
            backed_up_files = []
            for filename in files_to_backup:
                source = self.model_dir / filename
                if source.exists():
                    dest = backup_path / filename
                    shutil.copy2(source, dest)
                    backed_up_files.append(filename)
            
            # Also backup retrained models if they exist
            if self.retrained_dir.exists():
                retrained_backup = backup_path / "retrained_model"
                shutil.copytree(self.retrained_dir, retrained_backup, dirs_exist_ok=True)
            
            # Create backup metadata
            metadata = {
                'backup_name': backup_name,
                'created_at': datetime.now().isoformat(),
                'backed_up_files': backed_up_files,
                'has_retrained_models': self.retrained_dir.exists()
            }
            
            with open(backup_path / "backup_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Model backup created: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            logger.error(f"Error creating model backup: {e}")
            raise
    
    def list_backups(self) -> List[Dict]:
        """List available model backups."""
        backups = []
        
        try:
            if not self.backup_dir.exists():
                return backups
            
            for backup_path in self.backup_dir.iterdir():
                if backup_path.is_dir():
                    metadata_file = backup_path / "backup_metadata.json"
                    
                    if metadata_file.exists():
                        try:
                            with open(metadata_file, 'r') as f:
                                metadata = json.load(f)
                            backups.append({
                                'name': backup_path.name,
                                'path': str(backup_path),
                                'created_at': metadata.get('created_at', 'Unknown'),
                                'backed_up_files': metadata.get('backed_up_files', []),
                                'has_retrained_models': metadata.get('has_retrained_models', False)
                            })
                        except Exception as e:
                            logger.warning(f"Error reading backup metadata for {backup_path}: {e}")
                            # Add backup without metadata
                            backups.append({
                                'name': backup_path.name,
                                'path': str(backup_path),
                                'created_at': 'Unknown',
                                'backed_up_files': [],
                                'has_retrained_models': False
                            })
            
            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x['created_at'], reverse=True)
            
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
        
        return backups
    
    def restore_from_backup(self, backup_name: str) -> bool:
        """
        Restore model from a backup.
        
        Args:
            backup_name: Name of the backup to restore
            
        Returns:
            True if successful, False otherwise
        """
        try:
            backup_path = self.backup_dir / backup_name
            
            if not backup_path.exists():
                logger.error(f"Backup not found: {backup_name}")
                return False
            
            # Create a safety backup before restoring
            safety_backup = self.create_model_backup(f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            logger.info(f"Created safety backup before restore: {safety_backup}")
            
            # Load backup metadata
            metadata_file = backup_path / "backup_metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                files_to_restore = metadata.get('backed_up_files', [])
            else:
                # Fallback to discovering files
                files_to_restore = [f.name for f in backup_path.iterdir() if f.is_file() and f.suffix == '.pkl']
            
            # Restore files
            restored_files = []
            for filename in files_to_restore:
                source = backup_path / filename
                dest = self.model_dir / filename
                
                if source.exists():
                    shutil.copy2(source, dest)
                    restored_files.append(filename)
            
            # Restore retrained models if they exist in backup
            retrained_backup = backup_path / "retrained_model"
            if retrained_backup.exists():
                if self.retrained_dir.exists():
                    shutil.rmtree(self.retrained_dir)
                shutil.copytree(retrained_backup, self.retrained_dir)
            
            logger.info(f"Model restored from backup: {backup_name}")
            logger.info(f"Restored files: {restored_files}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring from backup: {e}")
            return False
    
    def validate_model_files(self, model_version: str = None) -> Dict:
        """
        Validate model files for integrity.
        
        Args:
            model_version: Model version to validate (e.g., 'v2', 'v3')
            
        Returns:
            Dictionary with validation results
        """
        try:
            # Determine file paths
            if model_version and model_version != 'base':
                model_path = self.retrained_dir / f"ocsvm_model_{model_version}.pkl"
                scaler_path = self.retrained_dir / f"scaler_{model_version}.pkl"
                encoders_path = self.retrained_dir / f"encoders_{model_version}.pkl"
            else:
                model_path = self.model_dir / "ocsvm_model.pkl"
                scaler_path = self.model_dir / "scaler.pkl"
                encoders_path = self.model_dir / "encoders.pkl"
            
            validation_results = {
                'model_exists': model_path.exists(),
                'scaler_exists': scaler_path.exists(),
                'encoders_exists': encoders_path.exists(),
                'files_readable': True,
                'model_loadable': False,
                'scaler_loadable': False,
                'encoders_loadable': False
            }
            
            # Test file readability and loadability
            try:
                if validation_results['model_exists']:
                    model = joblib.load(model_path)
                    validation_results['model_loadable'] = True
                    validation_results['model_type'] = type(model).__name__
            except Exception as e:
                logger.warning(f"Model file not loadable: {e}")
                validation_results['model_error'] = str(e)
            
            try:
                if validation_results['scaler_exists']:
                    scaler = joblib.load(scaler_path)
                    validation_results['scaler_loadable'] = True
                    validation_results['scaler_type'] = type(scaler).__name__
            except Exception as e:
                logger.warning(f"Scaler file not loadable: {e}")
                validation_results['scaler_error'] = str(e)
            
            try:
                if validation_results['encoders_exists']:
                    encoders = joblib.load(encoders_path)
                    validation_results['encoders_loadable'] = True
                    validation_results['encoders_count'] = len(encoders) if isinstance(encoders, dict) else 0
            except Exception as e:
                logger.warning(f"Encoders file not loadable: {e}")
                validation_results['encoders_error'] = str(e)
            
            # Overall validation
            validation_results['is_valid'] = (
                validation_results['model_loadable'] and 
                validation_results['scaler_loadable'] and 
                validation_results['encoders_loadable']
            )
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Error validating model files: {e}")
            return {
                'is_valid': False,
                'error': str(e)
            }
    
    def cleanup_old_backups(self, keep_count: int = 10) -> int:
        """
        Clean up old backups, keeping only the most recent ones.
        
        Args:
            keep_count: Number of backups to keep
            
        Returns:
            Number of backups deleted
        """
        try:
            backups = self.list_backups()
            
            if len(backups) <= keep_count:
                return 0
            
            backups_to_delete = backups[keep_count:]
            deleted_count = 0
            
            for backup in backups_to_delete:
                try:
                    backup_path = Path(backup['path'])
                    if backup_path.exists():
                        shutil.rmtree(backup_path)
                        deleted_count += 1
                        logger.info(f"Deleted old backup: {backup['name']}")
                except Exception as e:
                    logger.warning(f"Failed to delete backup {backup['name']}: {e}")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up old backups: {e}")
            return 0