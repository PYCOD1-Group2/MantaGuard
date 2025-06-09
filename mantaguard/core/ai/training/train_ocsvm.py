#!/usr/bin/env python3
"""
Train a OneClassSVM model on Zeek conn.log data.

This module provides functionality to train an initial OneClassSVM model
for anomaly detection from normal network traffic data.
"""

import argparse
import sys
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from mantaguard.utils.config import config
from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory
from mantaguard.core.ai.parsers.zeek_loader import load_conn_log, zeek_to_features

logger = get_logger(__name__)


class OCSVMTrainer:
    """OneClassSVM model trainer for anomaly detection."""
    
    def __init__(self, nu: float = 0.01, gamma: str = 'scale', kernel: str = 'rbf'):
        """
        Initialize the OCSVM trainer.
        
        Args:
            nu: An upper bound on the fraction of training errors
            gamma: Kernel coefficient for 'rbf', 'poly' and 'sigmoid'
            kernel: Specifies the kernel type to be used in the algorithm
        """
        self.nu = nu
        self.gamma = gamma
        self.kernel = kernel
        self.model = None
        self.scaler = None
        self.encoders = None
    
    def train(
        self, 
        conn_log_path: str, 
        output_dir: str = None
    ) -> Tuple[OneClassSVM, StandardScaler, dict]:
        """
        Train an OneClassSVM model on Zeek conn.log data.
        
        Args:
            conn_log_path: Path to Zeek conn.log file containing normal traffic
            output_dir: Directory to save model files (optional)
            
        Returns:
            Tuple of (model, scaler, encoders)
        """
        logger.info(f"Loading Zeek conn.log from: {conn_log_path}")
        
        # Validate input file
        conn_log_path = Path(conn_log_path)
        if not conn_log_path.exists():
            raise FileNotFoundError(f"Log file not found: {conn_log_path}")
        
        try:
            # Load the Zeek conn.log file
            df = load_conn_log(str(conn_log_path))
            logger.info(f"Loaded DataFrame with shape: {df.shape}")
            
            # Convert to features
            X, encoders, unknown_values = zeek_to_features(df)
            logger.info(f"Created feature matrix with shape: {X.shape}")
            
            # Apply standard scaling
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            logger.info("Applied standard scaling to features")
            
            # Train OneClassSVM model
            logger.info("Training OneClassSVM model...")
            model = OneClassSVM(kernel=self.kernel, nu=self.nu, gamma=self.gamma)
            model.fit(X_scaled)
            logger.info("Model training completed")
            
            # Store trained components
            self.model = model
            self.scaler = scaler
            self.encoders = encoders
            
            # Save models if output directory specified
            if output_dir:
                self.save_models(output_dir)
            
            # Print training stats
            logger.info(f"Training completed - Samples: {X.shape[0]}, Features: {X.shape[1]}")
            
            return model, scaler, encoders
            
        except Exception as e:
            logger.error(f"Error during training: {e}")
            raise
    
    def save_models(self, output_dir: str) -> bool:
        """
        Save trained model, scaler, and encoders to files.
        
        Args:
            output_dir: Directory to save model files
            
        Returns:
            True if successful, False otherwise
        """
        try:
            output_dir = Path(output_dir)
            safe_create_directory(output_dir)
            
            # Define file paths
            model_path = output_dir / 'ocsvm_model.pkl'
            scaler_path = output_dir / 'scaler.pkl'
            encoders_path = output_dir / 'encoders.pkl'
            
            # Save components
            joblib.dump(self.model, model_path)
            joblib.dump(self.scaler, scaler_path)
            joblib.dump(self.encoders, encoders_path)
            
            logger.info(f"Model files saved to {output_dir}:")
            logger.info(f"  - {model_path}")
            logger.info(f"  - {scaler_path}")
            logger.info(f"  - {encoders_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
            return False
    
    @classmethod
    def load_models(
        cls, 
        model_dir: str
    ) -> Tuple[OneClassSVM, StandardScaler, dict]:
        """
        Load trained model, scaler, and encoders from files.
        
        Args:
            model_dir: Directory containing model files
            
        Returns:
            Tuple of (model, scaler, encoders)
        """
        model_dir = Path(model_dir)
        
        model_path = model_dir / 'ocsvm_model.pkl'
        scaler_path = model_dir / 'scaler.pkl'
        encoders_path = model_dir / 'encoders.pkl'
        
        # Validate files exist
        for path in [model_path, scaler_path, encoders_path]:
            if not path.exists():
                raise FileNotFoundError(f"Model file not found: {path}")
        
        # Load components
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        encoders = joblib.load(encoders_path)
        
        return model, scaler, encoders


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Train a OneClassSVM model on Zeek conn.log data containing normal traffic.'
    )
    parser.add_argument('--log', required=True, help='Path to Zeek conn.log file containing normal traffic')
    parser.add_argument('--output-dir', help='Directory to save model files')
    parser.add_argument('--nu', type=float, default=0.01, help='Nu parameter for OneClassSVM (default: 0.01)')
    parser.add_argument('--gamma', default='scale', help='Gamma parameter for OneClassSVM (default: scale)')
    parser.add_argument('--kernel', default='rbf', help='Kernel for OneClassSVM (default: rbf)')
    return parser.parse_args()


def main():
    """Main function to train and save the OneClassSVM model."""
    # Parse command line arguments
    args = parse_args()
    
    # Set default output directory if not provided
    if not args.output_dir:
        args.output_dir = config.get_models_dir() / "ocsvm_model"
    
    try:
        # Create trainer and train model
        trainer = OCSVMTrainer(nu=args.nu, gamma=args.gamma, kernel=args.kernel)
        model, scaler, encoders = trainer.train(args.log, args.output_dir)
        
        logger.info("Training completed successfully")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()