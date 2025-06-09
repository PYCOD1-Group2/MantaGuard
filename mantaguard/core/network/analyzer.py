#!/usr/bin/env python3
"""
Network analysis functionality for MantaGuard.

Handles PCAP file analysis using Zeek and ML models for anomaly detection.
"""

import os
import sys
import subprocess
import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

from mantaguard.utils.config import config
from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory

logger = get_logger(__name__)


class NetworkAnalyzer:
    """Network traffic analyzer using Zeek and ML models."""
    
    def __init__(self, model_dir: Optional[str] = None, model_version: Optional[str] = None):
        """
        Initialize the network analyzer.
        
        Args:
            model_dir: Directory containing ML model files. If None, uses default.
            model_version: Version suffix for model files. If None, auto-detects latest.
        """
        self.model_dir = Path(model_dir) if model_dir else config.get_retrained_models_dir()
        self.model_version = model_version
        self.model = None
        self.scaler = None
        self.encoders = None
        
        # Auto-detect latest version if not specified
        if self.model_version is None:
            self.model_version = self._get_latest_model_version()
            
        self._load_models()
    
    def _get_latest_model_version(self) -> str:
        """
        Auto-detect the latest available model version.
        
        Returns:
            Latest model version string (e.g., 'v3', 'v2', or '' for base)
        """
        try:
            import re
            
            # Look for all model files in the directory
            model_files = list(self.model_dir.glob("ocsvm_model*.pkl"))
            
            if not model_files:
                logger.warning(f"No model files found in {self.model_dir}")
                return ''
            
            # Extract version numbers from filenames
            versions = []
            version_pattern = re.compile(r'ocsvm_model_v(\d+)\.pkl')
            
            for model_file in model_files:
                filename = model_file.name
                if filename == 'ocsvm_model.pkl':
                    # Base version (no suffix)
                    versions.append((0, ''))
                else:
                    match = version_pattern.match(filename)
                    if match:
                        version_num = int(match.group(1))
                        version_str = f'v{version_num}'
                        versions.append((version_num, version_str))
            
            if not versions:
                logger.warning("No valid model versions found")
                return ''
            
            # Sort by version number and get the latest
            versions.sort(key=lambda x: x[0], reverse=True)
            latest_version = versions[0][1]
            
            logger.info(f"Auto-detected latest model version: {latest_version or 'base'}")
            
            # Verify that all required files exist for this version
            if self._verify_model_files_exist(latest_version):
                return latest_version
            else:
                # Fall back to next available version
                for _, fallback_version in versions[1:]:
                    if self._verify_model_files_exist(fallback_version):
                        logger.warning(f"Latest version incomplete, using fallback: {fallback_version or 'base'}")
                        return fallback_version
                
                logger.error("No complete model version found")
                return ''
                
        except Exception as e:
            logger.error(f"Error detecting latest model version: {e}")
            return 'v2'  # Default fallback
    
    def _verify_model_files_exist(self, version: str) -> bool:
        """
        Verify that all required model files exist for a given version.
        
        Args:
            version: Version string (e.g., 'v2', 'v3', or '' for base)
            
        Returns:
            True if all required files exist, False otherwise
        """
        try:
            version_suffix = f"_{version}" if version else ""
            
            required_files = [
                f'ocsvm_model{version_suffix}.pkl',
                f'scaler{version_suffix}.pkl', 
                f'encoders{version_suffix}.pkl'
            ]
            
            for filename in required_files:
                filepath = self.model_dir / filename
                if not filepath.exists():
                    logger.debug(f"Missing model file: {filepath}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error verifying model files for version {version}: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the currently loaded model.
        
        Returns:
            Dictionary with model information
        """
        return {
            'model_dir': str(self.model_dir),
            'version': self.model_version or 'base',
            'model_loaded': self.model is not None,
            'scaler_loaded': self.scaler is not None,
            'encoders_loaded': self.encoders is not None,
            'available_versions': self.get_available_versions()
        }
    
    def get_available_versions(self) -> List[str]:
        """
        Get list of all available model versions in the model directory.
        
        Returns:
            List of available version strings, sorted from newest to oldest
        """
        try:
            import re
            
            model_files = list(self.model_dir.glob("ocsvm_model*.pkl"))
            versions = []
            version_pattern = re.compile(r'ocsvm_model_v(\d+)\.pkl')
            
            for model_file in model_files:
                filename = model_file.name
                if filename == 'ocsvm_model.pkl':
                    # Check if base version is complete
                    if self._verify_model_files_exist(''):
                        versions.append((0, 'base'))
                else:
                    match = version_pattern.match(filename)
                    if match:
                        version_num = int(match.group(1))
                        version_str = f'v{version_num}'
                        # Only include if complete
                        if self._verify_model_files_exist(version_str):
                            versions.append((version_num, version_str))
            
            # Sort by version number (newest first) and return version strings
            versions.sort(key=lambda x: x[0], reverse=True)
            return [v[1] for v in versions]
            
        except Exception as e:
            logger.error(f"Error getting available versions: {e}")
            return []
    
    def _load_models(self) -> None:
        """Load ML models, scaler, and encoders."""
        try:
            # Determine model file paths
            version_suffix = f"_{self.model_version}" if self.model_version else ""
            
            model_path = self.model_dir / f'ocsvm_model{version_suffix}.pkl'
            scaler_path = self.model_dir / f'scaler{version_suffix}.pkl'
            encoders_path = self.model_dir / f'encoders{version_suffix}.pkl'
            
            # Try v2 model first, then fallback to base model
            if not model_path.exists() and self.model_version:
                logger.warning(f"Model version '{self.model_version}' not found, trying base model")
                model_path = self.model_dir / 'ocsvm_model.pkl'
                scaler_path = self.model_dir / 'scaler.pkl'
                encoders_path = self.model_dir / 'encoders.pkl'
                self.model_version = ''
            
            # Check if model files exist
            missing_files = []
            for path, name in [(model_path, 'model'), (scaler_path, 'scaler'), (encoders_path, 'encoders')]:
                if not path.exists():
                    missing_files.append(f"{name} ({path})")
            
            if missing_files:
                raise FileNotFoundError(f"Model files not found: {', '.join(missing_files)}")
            
            # Load model components
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.encoders = joblib.load(encoders_path)
            
            logger.info(f"Loaded ML model from {self.model_dir}, version: {self.model_version or 'base'}")
            
        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")
            raise

    def analyze_pcap_with_zeek(
        self, 
        pcap_path: str,
        analysis_dir: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], str]:
        """
        Analyze a PCAP file with Zeek and ML model for anomaly detection.

        Args:
            pcap_path: Path to the PCAP file to analyze
            analysis_dir: Optional custom analysis directory

        Returns:
            Tuple of (results list, analysis directory path)
            Results list contains dictionaries with fields: uid, timestamp, score, prediction

        Raises:
            FileNotFoundError: If the PCAP file doesn't exist
            Exception: If Zeek analysis fails
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        logger.info(f"Starting PCAP analysis: {pcap_path}")

        # Create analysis directory
        if analysis_dir is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_dir = config.get_analysis_results_dir() / timestamp
        else:
            analysis_dir = Path(analysis_dir)
            
        safe_create_directory(analysis_dir)

        # Create Zeek logs subdirectory
        zeek_logs_dir = analysis_dir / "zeek_logs"
        safe_create_directory(zeek_logs_dir)

        conn_log_path = zeek_logs_dir / "conn.log"

        try:
            # Run Zeek analysis
            self._run_zeek_analysis(pcap_path, zeek_logs_dir)
            
            # Load and process Zeek logs
            try:
                from mantaguard.core.ai.parsers import load_conn_log
                df = load_conn_log(str(conn_log_path))
            except ImportError as e:
                logger.error(f"Failed to import Zeek loader: {e}")
                raise Exception("Zeek loader module not available")
            
            if df.empty:
                logger.warning("No connections found in the PCAP file")
                return [], str(analysis_dir)

            logger.info(f"Loaded {len(df)} connections from Zeek analysis")

            # Perform ML analysis
            results = self._perform_ml_analysis(df)
            
            # Update metadata if available
            self._update_analysis_metadata(pcap_path, analysis_dir, results)

            logger.info(f"Analysis complete. Found {sum(1 for r in results if r['prediction'] == 'anomaly')} anomalies out of {len(results)} connections")

            return results, str(analysis_dir)

        except Exception as e:
            logger.error(f"Error during PCAP analysis: {e}")
            raise

    def _run_zeek_analysis(self, pcap_path: Path, zeek_logs_dir: Path) -> None:
        """
        Run Zeek analysis on a PCAP file.
        
        Args:
            pcap_path: Path to PCAP file
            zeek_logs_dir: Directory to store Zeek logs
            
        Raises:
            Exception: If Zeek analysis fails
        """
        logger.debug("Starting Zeek analysis")
        
        # Convert to absolute paths
        abs_pcap_path = pcap_path.absolute()
        abs_zeek_dir = zeek_logs_dir.absolute()

        # Build Zeek command
        zeek_cmd = f"cd {abs_zeek_dir} && zeek -r {abs_pcap_path}"
        logger.debug(f"Running Zeek command: {zeek_cmd}")

        try:
            # Run Zeek with proper error handling
            result = subprocess.run(
                zeek_cmd, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                error_msg = f"Zeek analysis failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f": {result.stderr}"
                logger.error(error_msg)
                raise subprocess.CalledProcessError(result.returncode, zeek_cmd, result.stderr)

            # Verify conn.log was created
            conn_log_path = zeek_logs_dir / "conn.log"
            if not conn_log_path.exists():
                raise FileNotFoundError(f"Zeek did not generate conn.log at {conn_log_path}")

            logger.debug("Zeek analysis completed successfully")

        except subprocess.TimeoutExpired:
            logger.error("Zeek analysis timed out after 5 minutes")
            raise Exception("Zeek analysis timed out")
        except Exception as e:
            logger.error(f"Zeek analysis failed: {e}")
            raise

    def _perform_ml_analysis(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Perform ML analysis on Zeek connection data.
        
        Args:
            df: DataFrame containing Zeek connection data
            
        Returns:
            List of analysis results
        """
        logger.debug("Starting ML analysis")
        
        # Convert to feature vectors  
        try:
            from mantaguard.core.ai.parsers import zeek_to_features
            X, _, unknown_values = zeek_to_features(df, self.encoders)
        except ImportError as e:
            logger.error(f"Failed to import zeek_to_features: {e}")
            raise Exception("Feature extraction module not available")

        # Handle unknown categorical values
        self._handle_unknown_values(unknown_values)

        # Handle NaN values
        if np.isnan(X).any():
            logger.debug("Found NaN values in feature matrix, filling with zeros")
            X = np.nan_to_num(X, nan=0.0)

        # Scale features and make predictions
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)

        # Create results
        results = []
        for i in range(len(df)):
            # Get timestamp and UID
            timestamp = (df.iloc[i]['ts'].isoformat() if 'ts' in df.columns 
                        else datetime.now().isoformat())
            uid = df.iloc[i]['uid'] if 'uid' in df.columns else f"unknown-{i}"

            # Determine label (1 = normal, -1 = anomaly)
            label = "normal" if predictions[i] == 1 else "anomaly"

            results.append({
                'uid': uid,
                'timestamp': timestamp,
                'score': float(scores[i]),
                'prediction': label
            })

        logger.debug(f"ML analysis completed for {len(results)} connections")
        return results

    def _handle_unknown_values(self, unknown_values: Dict[str, List]) -> None:
        """
        Handle unknown categorical values found during analysis.
        
        Args:
            unknown_values: Dictionary of unknown values by column
        """
        has_unknown = any(len(values) > 0 for values in unknown_values.values())
        
        if has_unknown:
            logger.warning("Unknown categorical values found and encoded as -1")
            
            # Update unknown categories file
            self._update_unknown_categories(unknown_values)
            
            # Log unknown values
            for col, values in unknown_values.items():
                if values:
                    logger.warning(f"Unknown values in column '{col}': {values}")

    def _update_unknown_categories(self, unknown_values: Dict[str, List]) -> None:
        """
        Update the unknown categories tracking file.
        
        Args:
            unknown_values: Dictionary of unknown categorical values
        """
        try:
            # Determine unknown categories file path
            filename = config.PROJECT_ROOT / "mantaguard" / "data" / "unknown_categories.json"
            
            # Load existing unknown values if file exists
            merged_unknown_values = unknown_values.copy()
            
            if filename.exists():
                try:
                    with open(filename, 'r') as f:
                        existing_unknown_values = json.load(f)

                    # Merge with current unknown values
                    for col, values in existing_unknown_values.items():
                        if col in merged_unknown_values:
                            # Combine lists and remove duplicates
                            merged_unknown_values[col] = list(set(merged_unknown_values[col] + values))
                        else:
                            merged_unknown_values[col] = values
                            
                except Exception as e:
                    logger.warning(f"Could not read existing unknown categories file: {e}")

            # Ensure directory exists
            safe_create_directory(filename.parent)

            # Write merged unknown values to file
            with open(filename, 'w') as f:
                json.dump(merged_unknown_values, f, indent=2)
                
            logger.debug(f"Updated unknown categories file: {filename}")
            
        except Exception as e:
            logger.warning(f"Could not update unknown categories file: {e}")

    def _update_analysis_metadata(
        self, 
        pcap_path: Path, 
        analysis_dir: Path, 
        results: List[Dict[str, Any]]
    ) -> None:
        """
        Update PCAP metadata with analysis results.
        
        Args:
            pcap_path: Path to analyzed PCAP file
            analysis_dir: Analysis output directory
            results: Analysis results
        """
        try:
            # Import metadata functions
            from mantaguard.data.models.metadata import update_metadata_with_analysis

            # Calculate statistics
            anomaly_count = sum(1 for r in results if r['prediction'] == 'anomaly')
            total_connections = len(results)
            csv_path = analysis_dir / 'prediction_results.csv'

            # Update metadata
            update_metadata_with_analysis(
                pcap_path=str(pcap_path),
                analysis_dir=str(analysis_dir),
                csv_path=str(csv_path),
                anomaly_count=anomaly_count,
                total_connections=total_connections
            )
            logger.debug("Updated PCAP metadata with analysis results")
            
        except Exception as e:
            logger.warning(f"Failed to update PCAP metadata: {e}")


# Legacy function for backward compatibility
def analyze_pcap_with_zeek(
    pcap_path: str, 
    model_dir: Optional[str] = None, 
    model_version: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Legacy function for backward compatibility.
    
    Args:
        pcap_path: Path to the PCAP file to analyze
        model_dir: Directory containing ML model files
        model_version: Version suffix for model files. If None, auto-detects latest.
        
    Returns:
        Tuple of (results list, analysis directory path)
    """
    analyzer = NetworkAnalyzer(model_dir, model_version)
    return analyzer.analyze_pcap_with_zeek(pcap_path)