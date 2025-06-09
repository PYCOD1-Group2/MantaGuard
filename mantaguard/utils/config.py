"""
Centralized configuration management for MantaGuard.

This module provides centralized path management and configuration
to eliminate hardcoded paths throughout the application.
"""

import os
from pathlib import Path
from typing import Dict, Any
import base64


class MantaGuardConfig:
    """Centralized configuration for MantaGuard application."""
    
    def __init__(self):
        # Project root directory (where pyproject.toml is located)
        self.PROJECT_ROOT = Path(__file__).parent.parent.parent
        
        # Data directories (outside the package)
        self.DATA_DIR = self.PROJECT_ROOT / "data"
        self.MODELS_DIR = self.DATA_DIR / "models"
        self.PCAPS_DIR = self.DATA_DIR / "pcaps"
        self.ANALYSIS_DIR = self.DATA_DIR / "analysis"
        self.FORENSICS_DIR = self.DATA_DIR / "forensics"
        self.LOGS_DIR = self.DATA_DIR / "logs"
        
        
        # Web application directories
        self.TEMPLATES_DIR = self.PROJECT_ROOT / "templates"
        self.STATIC_DIR = self.PROJECT_ROOT / "content"
        
        # Configuration directories
        self.CONFIG_DIR = self.PROJECT_ROOT / "config"
        
        # Ensure directories exist
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure all required directories exist."""
        directories = [
            self.DATA_DIR,
            self.MODELS_DIR,
            self.PCAPS_DIR,
            self.ANALYSIS_DIR,
            self.FORENSICS_DIR,
            self.LOGS_DIR,
            self.CONFIG_DIR,
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def get_analysis_results_dir(self) -> Path:
        """Get the analysis results directory."""
        # Check current data/output structure first
        current_results = self.DATA_DIR / "output" / "analysis_results"
        if current_results.exists():
            return current_results
        return self.ANALYSIS_DIR / "results"
    
    def get_pcaps_dir(self) -> Path:
        """Get the PCAP files directory."""
        return self.PCAPS_DIR
    
    def get_forensics_dir(self) -> Path:
        """Get the forensics directory."""
        return self.FORENSICS_DIR
    
    def get_models_dir(self) -> Path:
        """Get the models directory."""
        # Check current data/output structure first
        current_models = self.DATA_DIR / "output" / "ocsvm_model"
        if current_models.exists():
            return current_models
        return self.MODELS_DIR / "current"
    
    def get_retrained_models_dir(self) -> Path:
        """Get the retrained models directory."""
        # Check current data/output structure first
        current_retrained = self.DATA_DIR / "output" / "retrained_model"
        if current_retrained.exists():
            return current_retrained
        return self.MODELS_DIR / "retrained"


# Global configuration instance
config = MantaGuardConfig()


def get_base64_of_bin_file(file_path: str) -> str:
    """
    Convert binary file to base64 string.
    
    Args:
        file_path: Relative path from project root or absolute path
        
    Returns:
        Base64 encoded string of the file
    """
    # Handle relative paths from project root
    if not os.path.isabs(file_path):
        file_path = config.PROJECT_ROOT / file_path
    
    with open(file_path, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()


def ensure_directories() -> Path:
    """
    Ensure required directories exist.
    
    Returns:
        Path to analysis results directory
    """
    config._ensure_directories()
    return config.get_analysis_results_dir()


def get_project_root() -> Path:
    """Get the project root directory."""
    return config.PROJECT_ROOT



# Environment-specific settings
class EnvironmentConfig:
    """Environment-specific configuration settings."""
    
    def __init__(self):
        self.FLASK_ENV = os.getenv('FLASK_ENV', 'development')
        self.DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
        self.SECRET_KEY = os.getenv('SECRET_KEY', 'mantaguard_secret_key_change_in_production')
        self.HOST = os.getenv('HOST', '0.0.0.0')
        self.PORT = int(os.getenv('PORT', 5000))


env_config = EnvironmentConfig()