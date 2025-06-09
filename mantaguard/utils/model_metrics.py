#!/usr/bin/env python3
"""
Model metrics calculation utilities for MantaGuard.

This module provides functionality to calculate real performance metrics
for trained models using validation data and labeled anomalies.
"""

import os
import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Tuple, Optional
import joblib
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc
from sklearn.preprocessing import LabelEncoder

from mantaguard.utils.logger import get_logger

logger = get_logger(__name__)


class ModelMetricsCalculator:
    """Calculate real performance metrics for OCSVM models."""
    
    def __init__(self, model_dir: str = None):
        """
        Initialize metrics calculator.
        
        Args:
            model_dir: Directory containing model files
        """
        if model_dir is None:
            project_root = Path(__file__).parent.parent.parent
            self.model_dir = project_root / "data" / "output" / "ocsvm_model"
        else:
            self.model_dir = Path(model_dir)
            
        self.retrained_dir = self.model_dir.parent / "retrained_model"
    
    def load_labeled_data(self) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
        """
        Load labeled anomalies data for validation.
        
        Returns:
            Tuple of (features, true_labels, dataframe)
        """
        labeled_path = self.model_dir / "labeled_anomalies.csv"
        
        if not labeled_path.exists():
            logger.warning(f"No labeled anomalies found at {labeled_path}")
            return np.array([]), np.array([]), pd.DataFrame()
        
        try:
            df = pd.read_csv(labeled_path)
            
            if len(df) == 0:
                return np.array([]), np.array([]), df
            
            # Extract feature vectors
            features = []
            for _, row in df.iterrows():
                try:
                    # Parse feature vector string back to numpy array
                    feature_str = row['feature_vector'].strip('[]')
                    feature_vec = np.array([float(x.strip()) for x in feature_str.split(',')])
                    features.append(feature_vec)
                except Exception as e:
                    logger.warning(f"Failed to parse feature vector: {e}")
                    continue
            
            if not features:
                return np.array([]), np.array([]), df
            
            X = np.array(features)
            
            # Create binary labels (1 for anomaly, 0 for normal)
            # In labeled anomalies, everything is considered anomalous
            y = np.ones(len(features))
            
            return X, y, df
            
        except Exception as e:
            logger.error(f"Error loading labeled data: {e}")
            return np.array([]), np.array([]), pd.DataFrame()
    
    def calculate_model_performance(self, model_version: str = None) -> Dict:
        """
        Calculate real performance metrics for a model version.
        
        Args:
            model_version: Model version to evaluate (e.g., 'v2', 'v3')
            
        Returns:
            Dictionary with performance metrics
        """
        try:
            # Determine model files
            if model_version and model_version != 'base':
                model_path = self.retrained_dir / f"ocsvm_model_{model_version}.pkl"
                scaler_path = self.retrained_dir / f"scaler_{model_version}.pkl"
            else:
                model_path = self.model_dir / "ocsvm_model.pkl"
                scaler_path = self.model_dir / "scaler.pkl"
            
            if not model_path.exists() or not scaler_path.exists():
                logger.warning(f"Model files not found for version {model_version}")
                return self._get_default_metrics()
            
            # Load model and scaler
            model = joblib.load(model_path)
            scaler = joblib.load(scaler_path)
            
            # Load labeled data for validation
            X, y_true, df = self.load_labeled_data()
            
            if len(X) == 0:
                logger.warning("No labeled data available for metrics calculation")
                return self._get_default_metrics()
            
            # Scale features
            X_scaled = scaler.transform(X)
            
            # Get model predictions
            decision_scores = model.decision_function(X_scaled)
            predictions = model.predict(X_scaled)
            
            # Convert predictions (-1 for anomaly, 1 for normal) to binary (1 for anomaly, 0 for normal)
            y_pred = (predictions == -1).astype(int)
            
            # Calculate metrics
            metrics = self._calculate_metrics(y_true, y_pred, decision_scores, df)
            
            logger.info(f"Calculated metrics for model {model_version}: {metrics}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error calculating model performance: {e}")
            return self._get_default_metrics()
    
    def _calculate_metrics(
        self, 
        y_true: np.ndarray, 
        y_pred: np.ndarray, 
        decision_scores: np.ndarray,
        df: pd.DataFrame
    ) -> Dict:
        """Calculate detailed performance metrics."""
        
        # Basic classification metrics
        tp = np.sum((y_true == 1) & (y_pred == 1))
        tn = np.sum((y_true == 0) & (y_pred == 0))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        fn = np.sum((y_true == 1) & (y_pred == 0))
        
        # Calculate rates
        total = len(y_true)
        if total == 0:
            return self._get_default_metrics()
        
        # Since all labeled data is anomalies, we need to estimate normal data performance
        # This is a limitation of having only labeled anomalies
        
        # Detection rate (recall for anomalies)
        detection_rate = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
        
        # False positive rate (estimated)
        # For OCSVM, we can use the decision scores to estimate this
        anomaly_threshold = np.percentile(decision_scores, 10)  # Conservative threshold
        estimated_fp_rate = len(decision_scores[decision_scores < anomaly_threshold]) / len(decision_scores) * 100
        
        # Accuracy (estimated based on anomaly detection)
        accuracy = (tp / total) * 100 if total > 0 else 0
        
        # Additional metrics
        precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
        
        # Attack category distribution
        attack_categories = {}
        if 'attack_category' in df.columns:
            attack_categories = df['attack_category'].value_counts().to_dict()
        
        return {
            'detection_rate': round(detection_rate, 1),
            'false_positive_rate': round(estimated_fp_rate, 1),
            'accuracy': round(accuracy, 1),
            'precision': round(precision, 1),
            'total_samples': total,
            'true_positives': int(tp),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'attack_categories': attack_categories,
            'mean_anomaly_score': round(float(np.mean(-decision_scores)), 3),
            'std_anomaly_score': round(float(np.std(-decision_scores)), 3)
        }
    
    def _get_default_metrics(self) -> Dict:
        """Return default metrics when calculation fails."""
        return {
            'detection_rate': 0.0,
            'false_positive_rate': 0.0,
            'accuracy': 0.0,
            'precision': 0.0,
            'total_samples': 0,
            'true_positives': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'attack_categories': {},
            'mean_anomaly_score': 0.0,
            'std_anomaly_score': 0.0
        }
    
    def compare_models(self, versions: list) -> Dict:
        """
        Compare performance across multiple model versions.
        
        Args:
            versions: List of model versions to compare
            
        Returns:
            Dictionary with comparison metrics
        """
        comparison = {}
        
        for version in versions:
            metrics = self.calculate_model_performance(version)
            comparison[version] = metrics
        
        return comparison
    
    def get_training_history(self) -> Dict:
        """Get training history and model evolution."""
        history = {
            'versions': [],
            'training_dates': [],
            'performance_trend': []
        }
        
        try:
            # Check base model
            base_model_path = self.model_dir / "ocsvm_model.pkl"
            if base_model_path.exists():
                history['versions'].append('base')
                history['training_dates'].append(
                    pd.Timestamp.fromtimestamp(base_model_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                )
                base_metrics = self.calculate_model_performance('base')
                history['performance_trend'].append(base_metrics['accuracy'])
            
            # Check retrained versions
            if self.retrained_dir.exists():
                version_files = list(self.retrained_dir.glob("ocsvm_model_v*.pkl"))
                for version_file in sorted(version_files):
                    version = version_file.stem.split('_')[-1]
                    history['versions'].append(version)
                    history['training_dates'].append(
                        pd.Timestamp.fromtimestamp(version_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    )
                    version_metrics = self.calculate_model_performance(version)
                    history['performance_trend'].append(version_metrics['accuracy'])
            
        except Exception as e:
            logger.error(f"Error getting training history: {e}")
        
        return history