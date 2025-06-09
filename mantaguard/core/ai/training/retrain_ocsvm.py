#!/usr/bin/env python3
"""
Retrain OneClassSVM model with normal data and optionally labeled feedback.

This module provides functionality to retrain existing OneClassSVM models
with new data, including labeled anomalies and unknown categories.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from mantaguard.utils.config import config
from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory
from mantaguard.core.ai.parsers.zeek_loader import load_conn_log, zeek_to_features

logger = get_logger(__name__)


class OCSVMRetrainer:
    """OneClassSVM model retrainer with feedback learning."""
    
    def __init__(self, nu: float = 0.01, gamma: str = 'scale', kernel: str = 'rbf'):
        """
        Initialize the OCSVM retrainer.
        
        Args:
            nu: An upper bound on the fraction of training errors
            gamma: Kernel coefficient for 'rbf', 'poly' and 'sigmoid'
            kernel: Specifies the kernel type to be used in the algorithm
        """
        self.nu = nu
        self.gamma = gamma
        self.kernel = kernel
    
    def load_labeled_anomalies(self, path: str) -> pd.DataFrame:
        """
        Load labeled anomalies from CSV file.
        
        Args:
            path: Path to the CSV file with labeled anomalies
            
        Returns:
            DataFrame containing the labeled anomalies
        """
        logger.info(f"Loading labeled anomalies from: {path}")
        df = pd.read_csv(path)
        
        # Convert timestamp columns to datetime
        for col in ['ts', 'timestamp']:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col])
        
        # Parse feature_vector column if it exists
        if 'feature_vector' in df.columns:
            # Convert string representation of list to actual numpy array
            df['feature_vector'] = df['feature_vector'].apply(
                lambda x: np.array(eval(x)) if isinstance(x, str) else x
            )
        
        logger.info(f"Loaded labeled anomalies with shape: {df.shape}")
        return df
    
    def expand_encoders(
        self, 
        encoders: Dict, 
        unknown_categories: Dict
    ) -> Tuple[Dict, int]:
        """
        Expand encoders with new unknown categories.
        
        Args:
            encoders: Original encoders dictionary
            unknown_categories: Dictionary of unknown categories to add
            
        Returns:
            Tuple of (updated_encoders, categories_added_count)
        """
        categories_added = 0
        updated_encoders = encoders.copy()
        
        # For each categorical column
        for col, values in unknown_categories.items():
            if col in updated_encoders:
                # Get the current mapping
                mapping = updated_encoders[col]
                
                # Skip if the column was missing during training
                if mapping.get('column_missing', False):
                    continue
                
                # Find the next available index (max + 1)
                next_idx = max(mapping.values()) + 1 if mapping else 0
                
                # Add new values to the mapping
                for value in values:
                    if value not in mapping:
                        mapping[value] = next_idx
                        next_idx += 1
                        categories_added += 1
        
        logger.info(f"Added {categories_added} new categories to encoders")
        return updated_encoders, categories_added
    
    def retrain(
        self,
        encoders_path: str,
        scaler_path: str,
        unknown_categories_path: str,
        base_normal_path: Optional[str] = None,
        labeled_anomalies_path: Optional[str] = None,
        output_dir: str = None
    ) -> Tuple[OneClassSVM, StandardScaler, Dict]:
        """
        Retrain OneClassSVM model with new data.
        
        Args:
            encoders_path: Path to original encoders.pkl file
            scaler_path: Path to original scaler.pkl file
            unknown_categories_path: Path to JSON file with unknown categories
            base_normal_path: Path to normal traffic data (optional)
            labeled_anomalies_path: Path to labeled anomalies CSV (optional)
            output_dir: Directory to save updated model files (optional)
            
        Returns:
            Tuple of (retrained_model, new_scaler, updated_encoders)
        """
        # Validate required files
        required_files = [encoders_path, scaler_path, unknown_categories_path]
        if labeled_anomalies_path:
            required_files.append(labeled_anomalies_path)
        if base_normal_path:
            required_files.append(base_normal_path)
        
        for file_path in required_files:
            if not Path(file_path).exists():
                raise FileNotFoundError(f"Required file not found: {file_path}")
        
        try:
            # Load original components
            logger.info(f"Loading original encoders from: {encoders_path}")
            encoders = joblib.load(encoders_path)
            
            logger.info(f"Loading original scaler from: {scaler_path}")
            scaler = joblib.load(scaler_path)
            
            # Load unknown categories
            logger.info(f"Loading unknown categories from: {unknown_categories_path}")
            with open(unknown_categories_path, 'r') as f:
                unknown_categories = json.load(f)
            
            # Expand encoders with new categories
            logger.info("Expanding encoders with new categories...")
            updated_encoders, categories_added = self.expand_encoders(
                encoders, unknown_categories
            )
            
            # Initialize variables for data processing
            X_labeled = None
            X_normal = None
            rows_from_labeled = 0
            rows_from_normal = 0
            
            # Process labeled anomalies if provided
            if labeled_anomalies_path:
                labeled_df = self.load_labeled_anomalies(labeled_anomalies_path)
                
                # Check if feature_vector column exists and use it directly
                if 'feature_vector' in labeled_df.columns:
                    logger.info("Using pre-computed feature vectors from labeled anomalies")
                    X_labeled = np.vstack(labeled_df['feature_vector'].values)
                    
                    # Handle dimension mismatch if normal data is provided
                    if base_normal_path:
                        normal_sample_df = load_conn_log(base_normal_path).head(1)
                        X_normal_sample, _, _ = zeek_to_features(
                            normal_sample_df, updated_encoders
                        )
                        normal_feature_dim = X_normal_sample.shape[1]
                        labeled_feature_dim = X_labeled.shape[1]
                        
                        logger.info(f"Normal data feature dimension: {normal_feature_dim}")
                        logger.info(f"Labeled anomalies feature dimension: {labeled_feature_dim}")
                        
                        # Adjust dimensions if needed
                        if normal_feature_dim != labeled_feature_dim:
                            logger.info("Adjusting labeled anomalies features to match normal data")
                            if normal_feature_dim > labeled_feature_dim:
                                # Pad with zeros
                                padding = np.zeros((
                                    X_labeled.shape[0], 
                                    normal_feature_dim - labeled_feature_dim
                                ))
                                X_labeled = np.hstack((X_labeled, padding))
                            else:
                                # Truncate to match normal data dimension
                                X_labeled = X_labeled[:, :normal_feature_dim]
                            
                            logger.info(f"Adjusted feature dimension: {X_labeled.shape[1]}")
                else:
                    # Use zeek_to_features for processing
                    X_labeled, _, unknown_values = zeek_to_features(
                        labeled_df, updated_encoders
                    )
                    
                    # Check for remaining unknown values
                    for col, values in unknown_values.items():
                        if values:
                            logger.warning(
                                f"New unknown values found in column '{col}': {values}"
                            )
                
                rows_from_labeled = X_labeled.shape[0]
            
            # Process normal data if provided
            if base_normal_path:
                logger.info(f"Loading normal data from: {base_normal_path}")
                normal_df = load_conn_log(base_normal_path)
                logger.info(f"Loaded normal data with shape: {normal_df.shape}")
                
                X_normal, _, _ = zeek_to_features(normal_df, updated_encoders)
                rows_from_normal = X_normal.shape[0]
            
            # Combine datasets
            if X_labeled is not None and X_normal is not None:
                logger.info("Combining normal data with labeled anomalies...")
                X_combined = np.vstack((X_normal, X_labeled))
            elif X_normal is not None:
                logger.info("Using only normal data for training...")
                X_combined = X_normal
            elif X_labeled is not None:
                logger.info("Using only labeled anomalies for training...")
                X_combined = X_labeled
            else:
                raise ValueError("Either base_normal_path or labeled_anomalies_path must be provided")
            
            # Handle NaN values
            logger.info("Checking for NaN values in the combined dataset...")
            nan_count = np.isnan(X_combined).sum()
            if nan_count > 0:
                logger.warning(f"Found {nan_count} NaN values. Replacing with zeros.")
                X_combined = np.nan_to_num(X_combined, nan=0.0)
            
            # Fit new scaler and train model
            logger.info("Fitting new scaler on combined dataset...")
            scaler_v2 = StandardScaler()
            X_combined_scaled = scaler_v2.fit_transform(X_combined)
            
            # Check for NaN values after scaling
            nan_count_after_scaling = np.isnan(X_combined_scaled).sum()
            if nan_count_after_scaling > 0:
                logger.warning(f"Found {nan_count_after_scaling} NaN values after scaling. Replacing with zeros.")
                X_combined_scaled = np.nan_to_num(X_combined_scaled, nan=0.0)
            
            # Train new model
            logger.info("Training new OneClassSVM model...")
            model_v2 = OneClassSVM(kernel=self.kernel, nu=self.nu, gamma=self.gamma)
            model_v2.fit(X_combined_scaled)
            logger.info("Model training completed")
            
            # Save models if output directory specified
            if output_dir:
                self.save_retrained_models(
                    output_dir, model_v2, scaler_v2, updated_encoders
                )
            
            # Print summary
            logger.info("Retraining Summary:")
            logger.info(f"Rows from normal data: {rows_from_normal}")
            logger.info(f"Rows from labeled anomalies: {rows_from_labeled}")
            logger.info(f"Total rows in combined dataset: {X_combined.shape[0]}")
            logger.info(f"Encoder categories added: {categories_added}")
            logger.info(f"Model training shape: {X_combined_scaled.shape}")
            
            return model_v2, scaler_v2, updated_encoders
            
        except Exception as e:
            logger.error(f"Error during retraining: {e}")
            raise
    
    def save_retrained_models(
        self,
        output_dir: str,
        model: OneClassSVM,
        scaler: StandardScaler,
        encoders: Dict
    ) -> bool:
        """
        Save retrained model components.
        
        Args:
            output_dir: Directory to save model files
            model: Retrained OneClassSVM model
            scaler: New StandardScaler
            encoders: Updated encoders dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            output_dir = Path(output_dir)
            safe_create_directory(output_dir)
            
            # Define file paths
            model_path = output_dir / 'ocsvm_model_v2.pkl'
            scaler_path = output_dir / 'scaler_v2.pkl'
            encoders_path = output_dir / 'encoders_v2.pkl'
            
            # Save components
            joblib.dump(model, model_path)
            joblib.dump(scaler, scaler_path)
            joblib.dump(encoders, encoders_path)
            
            logger.info(f"Retrained model files saved to {output_dir}:")
            logger.info(f"  - {model_path}")
            logger.info(f"  - {scaler_path}")
            logger.info(f"  - {encoders_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving retrained models: {e}")
            return False


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Retrain OneClassSVM model with normal data and optionally labeled feedback.'
    )
    parser.add_argument('--base-normal', help='Path to Zeek conn.log file containing original normal traffic')
    parser.add_argument('--labeled-anomalies', help='Path to CSV file with labeled anomalies (optional)')
    parser.add_argument('--unknown-categories', required=True, help='Path to JSON file with unknown categories')
    parser.add_argument('--encoders', required=True, help='Path to original encoders.pkl file')
    parser.add_argument('--scaler', required=True, help='Path to original scaler.pkl file')
    parser.add_argument('--output-dir', help='Directory to save updated model and files')
    parser.add_argument('--nu', type=float, default=0.01, help='Nu parameter for OneClassSVM (default: 0.01)')
    parser.add_argument('--gamma', default='scale', help='Gamma parameter for OneClassSVM (default: scale)')
    parser.add_argument('--kernel', default='rbf', help='Kernel for OneClassSVM (default: rbf)')
    return parser.parse_args()


def main():
    """Main function to retrain and save the OneClassSVM model."""
    # Parse command line arguments
    args = parse_args()
    
    # Set default output directory if not provided
    if not args.output_dir:
        args.output_dir = config.get_models_dir() / "retrained_model"
    
    try:
        # Create retrainer and retrain model
        retrainer = OCSVMRetrainer(nu=args.nu, gamma=args.gamma, kernel=args.kernel)
        model, scaler, encoders = retrainer.retrain(
            args.encoders,
            args.scaler,
            args.unknown_categories,
            args.base_normal,
            args.labeled_anomalies,
            args.output_dir
        )
        
        logger.info("Retraining completed successfully")
        
    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()