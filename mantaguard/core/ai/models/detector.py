#!/usr/bin/env python3
"""
Real-time anomaly detection for network traffic.

This module provides functionality to monitor live Zeek conn.log files
and classify connections in real-time for anomaly detection.
"""

import argparse
import csv
import json
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

from mantaguard.utils.config import config
from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory
from mantaguard.core.ai.parsers.zeek_loader import load_conn_log, zeek_to_features

logger = get_logger(__name__)


class RealtimeDetector:
    """Real-time anomaly detector for network traffic."""
    
    def __init__(
        self,
        model_dir: Optional[str] = None,
        model_version: Optional[str] = None
    ):
        """
        Initialize the real-time detector.
        
        Args:
            model_dir: Directory containing model files (optional)
            model_version: Version suffix for model files (optional)
        """
        self.model_dir = model_dir or str(config.get_models_dir() / "retrained_model")
        self.model_version = model_version
        self.model = None
        self.scaler = None
        self.encoders = None
        self._load_models()
    
    def _load_models(self) -> bool:
        """
        Load the trained model, scaler, and encoders.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            model_dir = Path(self.model_dir)
            
            # Determine model file names based on version
            if self.model_version:
                model_file = f'ocsvm_model_{self.model_version}.pkl'
                scaler_file = f'scaler_{self.model_version}.pkl'
                encoders_file = f'encoders_{self.model_version}.pkl'
            else:
                # Auto-detect: try v2 first, then fallback to base
                v2_model = model_dir / 'ocsvm_model_v2.pkl'
                if v2_model.exists():
                    model_file = 'ocsvm_model_v2.pkl'
                    scaler_file = 'scaler_v2.pkl'
                    encoders_file = 'encoders_v2.pkl'
                    logger.info("Using v2 model files")
                else:
                    model_file = 'ocsvm_model.pkl'
                    scaler_file = 'scaler.pkl'
                    encoders_file = 'encoders.pkl'
                    logger.info("Using base model files")
            
            # Load model components
            model_path = model_dir / model_file
            scaler_path = model_dir / scaler_file
            encoders_path = model_dir / encoders_file
            
            # Validate files exist
            for path in [model_path, scaler_path, encoders_path]:
                if not path.exists():
                    raise FileNotFoundError(f"Model file not found: {path}")
            
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.encoders = joblib.load(encoders_path)
            
            logger.info(f"Models loaded successfully from {model_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False
    
    def predict_connection(self, connection_data: pd.Series) -> Tuple[float, str]:
        """
        Predict whether a single connection is anomalous.
        
        Args:
            connection_data: Pandas Series containing connection data
            
        Returns:
            Tuple of (anomaly_score, prediction)
        """
        if self.model is None:
            raise RuntimeError("Models not loaded. Call _load_models() first.")
        
        try:
            # Convert series to DataFrame for processing
            df = pd.DataFrame([connection_data])
            
            # Convert to features
            X, _, unknown_values = zeek_to_features(df, self.encoders)
            
            # Check for unknown values
            for col, values in unknown_values.items():
                if values:
                    logger.warning(f"Unknown values in column '{col}': {values}")
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Handle NaN values
            if np.isnan(X_scaled).any():
                logger.warning("NaN values detected in scaled features, replacing with zeros")
                X_scaled = np.nan_to_num(X_scaled, nan=0.0)
            
            # Make prediction
            score = self.model.decision_function(X_scaled)[0]
            prediction = 'anomaly' if self.model.predict(X_scaled)[0] == -1 else 'normal'
            
            return score, prediction
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return 0.0, 'error'
    
    def monitor_log_file(
        self,
        log_path: str,
        output_csv: Optional[str] = None,
        output_db: Optional[str] = None,
        poll_interval: float = 1.0
    ) -> None:
        """
        Monitor a live Zeek conn.log file for real-time anomaly detection.
        
        Args:
            log_path: Path to the live Zeek conn.log file
            output_csv: Path to CSV file for storing results (optional)
            output_db: Path to SQLite database for storing results (optional)
            poll_interval: Polling interval in seconds
        """
        log_path = Path(log_path)
        
        if not log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")
        
        logger.info(f"Starting real-time monitoring of {log_path}")
        logger.info(f"Poll interval: {poll_interval} seconds")
        
        # Initialize storage
        csv_writer = None
        db_conn = None
        
        if output_csv:
            self._init_csv_storage(output_csv)
        
        if output_db:
            db_conn = self._init_db_storage(output_db)
        
        # Track file position
        last_position = 0
        
        try:
            while True:
                try:
                    # Check for new lines in the log file
                    new_lines = self._read_new_lines(log_path, last_position)
                    
                    if new_lines:
                        for line, position in new_lines:
                            self._process_log_line(
                                line, output_csv, db_conn
                            )
                            last_position = position
                    
                    time.sleep(poll_interval)
                    
                except KeyboardInterrupt:
                    logger.info("Monitoring stopped by user")
                    break
                except Exception as e:
                    logger.error(f"Error during monitoring: {e}")
                    time.sleep(poll_interval)
                    
        finally:
            if db_conn:
                db_conn.close()
    
    def _read_new_lines(self, log_path: Path, last_position: int) -> List[Tuple[str, int]]:
        """
        Read new lines from the log file since the last position.
        
        Args:
            log_path: Path to the log file
            last_position: Last read position in the file
            
        Returns:
            List of (line_content, new_position) tuples
        """
        new_lines = []
        
        try:
            with open(log_path, 'r') as f:
                f.seek(last_position)
                
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        new_lines.append((line.strip(), f.tell()))
                    else:
                        last_position = f.tell()
        
        except Exception as e:
            logger.error(f"Error reading log file: {e}")
        
        return new_lines
    
    def _process_log_line(
        self,
        line: str,
        output_csv: Optional[str] = None,
        db_conn: Optional[sqlite3.Connection] = None
    ) -> None:
        """
        Process a single log line for anomaly detection.
        
        Args:
            line: Log line content
            output_csv: Path to CSV output file (optional)
            db_conn: SQLite database connection (optional)
        """
        try:
            # Parse the log line (simplified - would need proper Zeek log parsing)
            fields = line.split('\t')
            
            # Create a mock DataFrame row for prediction
            # Note: This is simplified - would need proper field mapping
            connection_data = pd.Series({
                'ts': fields[0] if len(fields) > 0 else '',
                'uid': fields[1] if len(fields) > 1 else '',
                # Add more fields as needed based on Zeek format
            })
            
            # Make prediction
            score, prediction = self.predict_connection(connection_data)
            
            if prediction == 'anomaly':
                logger.warning(f"ANOMALY DETECTED: UID {connection_data.get('uid', 'unknown')}, Score: {score:.6f}")
                
                # Store the anomaly
                self._store_anomaly(
                    connection_data, score, prediction, output_csv, db_conn
                )
            else:
                logger.debug(f"Normal connection: UID {connection_data.get('uid', 'unknown')}, Score: {score:.6f}")
                
        except Exception as e:
            logger.error(f"Error processing log line: {e}")
    
    def _init_csv_storage(self, csv_path: str) -> None:
        """
        Initialize CSV storage for anomalies.
        
        Args:
            csv_path: Path to the CSV file
        """
        csv_path = Path(csv_path)
        safe_create_directory(csv_path.parent)
        
        # Create CSV with headers if it doesn't exist
        if not csv_path.exists():
            with open(csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'uid', 'score', 'prediction', 'detected_at'
                ])
    
    def _init_db_storage(self, db_path: str) -> sqlite3.Connection:
        """
        Initialize SQLite database storage for anomalies.
        
        Args:
            db_path: Path to the SQLite database
            
        Returns:
            SQLite connection object
        """
        db_path = Path(db_path)
        safe_create_directory(db_path.parent)
        
        conn = sqlite3.connect(str(db_path))
        
        # Create table if it doesn't exist
        conn.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                uid TEXT,
                score REAL,
                prediction TEXT,
                detected_at TEXT,
                raw_data TEXT
            )
        ''')
        conn.commit()
        
        return conn
    
    def _store_anomaly(
        self,
        connection_data: pd.Series,
        score: float,
        prediction: str,
        csv_path: Optional[str] = None,
        db_conn: Optional[sqlite3.Connection] = None
    ) -> None:
        """
        Store an anomaly in CSV and/or database.
        
        Args:
            connection_data: Connection data
            score: Anomaly score
            prediction: Prediction result
            csv_path: Path to CSV file (optional)
            db_conn: Database connection (optional)
        """
        detected_at = datetime.now().isoformat()
        
        # Store in CSV
        if csv_path:
            try:
                with open(csv_path, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        connection_data.get('ts', ''),
                        connection_data.get('uid', ''),
                        score,
                        prediction,
                        detected_at
                    ])
            except Exception as e:
                logger.error(f"Error writing to CSV: {e}")
        
        # Store in database
        if db_conn:
            try:
                db_conn.execute(
                    'INSERT INTO anomalies (timestamp, uid, score, prediction, detected_at, raw_data) VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        connection_data.get('ts', ''),
                        connection_data.get('uid', ''),
                        score,
                        prediction,
                        detected_at,
                        json.dumps(connection_data.to_dict())
                    )
                )
                db_conn.commit()
            except Exception as e:
                logger.error(f"Error writing to database: {e}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Monitor a live Zeek conn.log and classify each new line as normal or anomaly.'
    )
    parser.add_argument('--log', help='Path to live Zeek conn.log file')
    parser.add_argument('--csv', help='Path to CSV file for storing labeled anomalies')
    parser.add_argument('--sqlite', help='Path to SQLite database for storing labeled anomalies')
    parser.add_argument('--model-dir', help='Directory containing model files')
    parser.add_argument('--model-version', help='Version suffix for model files')
    parser.add_argument('--poll-interval', type=float, default=1.0, help='Polling interval in seconds')
    parser.add_argument('--no-csv', action='store_true', help='Disable CSV storage')
    parser.add_argument('--no-sqlite', action='store_true', help='Disable SQLite storage')
    return parser.parse_args()


def main():
    """Main function for command-line usage."""
    args = parse_args()
    
    # Set defaults
    log_path = args.log or str(config.DATA_DIR / "current" / "conn.log")
    csv_path = None if args.no_csv else (args.csv or str(config.DATA_DIR / "labeled_anomalies.csv"))
    db_path = None if args.no_sqlite else (args.sqlite or str(config.DATA_DIR / "labeled_anomalies.db"))
    
    try:
        # Create detector
        detector = RealtimeDetector(
            model_dir=args.model_dir,
            model_version=args.model_version
        )
        
        # Start monitoring
        detector.monitor_log_file(
            log_path,
            output_csv=csv_path,
            output_db=db_path,
            poll_interval=args.poll_interval
        )
        
    except Exception as e:
        logger.error(f"Real-time detection failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()