#!/usr/bin/env python3
"""
Hybrid classification pipeline for MantaGuard.

This module combines anomaly detection (OneClassSVM) with multi-class 
classification to provide both anomaly detection and attack categorization.
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Union
import json

from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory
from mantaguard.core.ai.models.multi_class_classifier import MultiClassNetworkClassifier
from mantaguard.data.storage.training_repository import TrainingRepository, TrainingConnection, ConfidenceLevel
from mantaguard.core.ai.parsers.zeek_loader import zeek_to_features

logger = get_logger(__name__)


class HybridNetworkClassifier:
    """
    Hybrid classifier combining anomaly detection with attack classification.
    
    Pipeline:
    1. Extract features from network connection
    2. Anomaly detection using OneClassSVM
    3. If anomaly detected, classify attack type using multi-class classifier
    4. Return comprehensive results with confidence scores
    """
    
    def __init__(self, model_dir: Optional[str] = None):
        """
        Initialize the hybrid classifier.
        
        Args:
            model_dir: Directory containing model files
        """
        if model_dir is None:
            project_root = Path(__file__).parent.parent.parent.parent.parent
            self.model_dir = project_root / "data" / "output" / "hybrid_models"
        else:
            self.model_dir = Path(model_dir)
            
        safe_create_directory(self.model_dir)
        
        # Component models
        self.anomaly_detector = None  # OneClassSVM
        self.attack_classifier = None  # MultiClassNetworkClassifier
        self.scaler = None
        self.encoders = None
        
        # Configuration
        self.anomaly_threshold = -0.5  # Threshold for anomaly detection
        self.classification_confidence_threshold = 0.7
        self.require_both_models = True
        
        # Model metadata
        self.model_info = {
            'anomaly_model_loaded': False,
            'classification_model_loaded': False,
            'last_updated': None
        }
    
    def load_models(
        self, 
        anomaly_version: str = "base",
        classification_version: str = "v1"
    ) -> bool:
        """
        Load both anomaly detection and classification models.
        
        Args:
            anomaly_version: Version of anomaly detection model
            classification_version: Version of classification model
            
        Returns:
            True if models loaded successfully
        """
        success = True
        
        # Load anomaly detection model (OneClassSVM)
        try:
            anomaly_success = self._load_anomaly_model(anomaly_version)
            self.model_info['anomaly_model_loaded'] = anomaly_success
            if not anomaly_success:
                logger.error(f"Failed to load anomaly model version {anomaly_version}")
                success = False
        except Exception as e:
            logger.error(f"Error loading anomaly model: {e}")
            success = False
        
        # Load classification model
        try:
            self.attack_classifier = MultiClassNetworkClassifier(str(self.model_dir))
            classification_success = self.attack_classifier.load_model(classification_version)
            self.model_info['classification_model_loaded'] = classification_success
            if not classification_success:
                logger.warning(f"Failed to load classification model version {classification_version}")
                if self.require_both_models:
                    success = False
        except Exception as e:
            logger.error(f"Error loading classification model: {e}")
            if self.require_both_models:
                success = False
        
        if success:
            self.model_info['last_updated'] = datetime.now().isoformat()
            logger.info("Hybrid classifier models loaded successfully")
        else:
            logger.error("Failed to load required models")
        
        return success
    
    def _load_anomaly_model(self, version: str = "base") -> bool:
        """Load OneClassSVM anomaly detection model."""
        try:
            # Try to load from retrained models first
            retrained_dir = self.model_dir.parent / "retrained_model"
            base_dir = self.model_dir.parent / "ocsvm_model"
            
            # Determine file paths based on version
            if version == "base":
                model_path = base_dir / "ocsvm_model.pkl"
                scaler_path = base_dir / "scaler.pkl"
                encoders_path = base_dir / "encoders.pkl"
            else:
                model_path = retrained_dir / f"ocsvm_model_{version}.pkl"
                scaler_path = retrained_dir / f"scaler_{version}.pkl"
                encoders_path = retrained_dir / f"encoders_{version}.pkl"
            
            # Check if files exist
            if not all(path.exists() for path in [model_path, scaler_path, encoders_path]):
                logger.warning(f"Anomaly model files not found for version {version}")
                return False
            
            # Load model components
            self.anomaly_detector = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.encoders = joblib.load(encoders_path)
            
            logger.info(f"Loaded anomaly detection model version {version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load anomaly model: {e}")
            return False
    
    def predict_connection(self, connection_data: Union[pd.Series, Dict]) -> Dict[str, Any]:
        """
        Perform hybrid prediction on a single connection.
        
        Args:
            connection_data: Connection data as pandas Series or dictionary
            
        Returns:
            Dictionary containing comprehensive prediction results
        """
        if not self.model_info['anomaly_model_loaded']:
            raise RuntimeError("Anomaly detection model not loaded")
        
        try:
            # Convert to DataFrame for feature extraction
            if isinstance(connection_data, dict):
                df = pd.DataFrame([connection_data])
            else:
                df = pd.DataFrame([connection_data])
            
            # Extract features
            X, _, unknown_values = zeek_to_features(df, self.encoders)
            
            # Check for unknown values
            if any(unknown_values.values()):
                logger.warning(f"Unknown values detected: {unknown_values}")
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Handle NaN values
            if np.isnan(X_scaled).any():
                logger.warning("NaN values detected, replacing with zeros")
                X_scaled = np.nan_to_num(X_scaled, nan=0.0)
            
            # Step 1: Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function(X_scaled)[0]
            is_anomaly = anomaly_score < self.anomaly_threshold
            anomaly_prediction = 'anomaly' if is_anomaly else 'normal'
            
            # Initialize result structure
            result = {
                'timestamp': datetime.now().isoformat(),
                'anomaly_detection': {
                    'score': float(anomaly_score),
                    'prediction': anomaly_prediction,
                    'is_anomaly': is_anomaly,
                    'threshold': self.anomaly_threshold
                },
                'classification': None,
                'final_prediction': {
                    'category': 'normal',
                    'subcategory': 'benign',
                    'confidence': 1.0,
                    'requires_manual_review': False
                },
                'feature_vector': X_scaled[0].tolist(),
                'unknown_values': unknown_values
            }
            
            # Step 2: If anomaly detected, classify attack type
            if is_anomaly and self.model_info['classification_model_loaded']:
                try:
                    classification_result = self.attack_classifier.predict(X_scaled[0])
                    
                    result['classification'] = {
                        'category': classification_result['category'],
                        'subcategory': classification_result['subcategory'],
                        'confidence': classification_result['confidence'],
                        'is_confident': classification_result['is_confident'],
                        'requires_review': classification_result['requires_review'],
                        'probabilities': classification_result['probabilities']
                    }
                    
                    # Update final prediction
                    result['final_prediction'] = {
                        'category': classification_result['category'],
                        'subcategory': classification_result['subcategory'],
                        'confidence': classification_result['confidence'],
                        'requires_manual_review': classification_result['requires_review']
                    }
                    
                except Exception as e:
                    logger.error(f"Classification failed: {e}")
                    # Fallback to unknown classification
                    result['classification'] = {
                        'category': 'unknown',
                        'subcategory': 'unknown',
                        'confidence': 0.0,
                        'is_confident': False,
                        'requires_review': True,
                        'error': str(e)
                    }
                    result['final_prediction'] = {
                        'category': 'unknown',
                        'subcategory': 'unknown',
                        'confidence': 0.0,
                        'requires_manual_review': True
                    }
            
            elif is_anomaly and not self.model_info['classification_model_loaded']:
                # Anomaly detected but no classification model available
                result['classification'] = {
                    'category': 'unknown',
                    'subcategory': 'unknown',
                    'confidence': 0.0,
                    'is_confident': False,
                    'requires_review': True,
                    'note': 'Classification model not available'
                }
                result['final_prediction'] = {
                    'category': 'unknown',
                    'subcategory': 'unknown',
                    'confidence': 0.0,
                    'requires_manual_review': True
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'anomaly_detection': None,
                'classification': None,
                'final_prediction': {
                    'category': 'error',
                    'subcategory': 'processing_failed',
                    'confidence': 0.0,
                    'requires_manual_review': True
                }
            }
    
    def batch_predict(self, connections: List[Union[pd.Series, Dict]]) -> List[Dict[str, Any]]:
        """
        Perform batch prediction on multiple connections.
        
        Args:
            connections: List of connection data
            
        Returns:
            List of prediction results
        """
        results = []
        for i, connection in enumerate(connections):
            try:
                result = self.predict_connection(connection)
                result['batch_index'] = i
                results.append(result)
            except Exception as e:
                logger.error(f"Batch prediction failed for connection {i}: {e}")
                results.append({
                    'batch_index': i,
                    'error': str(e),
                    'final_prediction': {
                        'category': 'error',
                        'subcategory': 'processing_failed',
                        'confidence': 0.0,
                        'requires_manual_review': True
                    }
                })
        
        return results
    
    def analyze_prediction_quality(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze the quality of prediction results.
        
        Args:
            results: List of prediction results
            
        Returns:
            Dictionary containing quality metrics
        """
        if not results:
            return {'error': 'No results to analyze'}
        
        total_predictions = len(results)
        successful_predictions = len([r for r in results if 'error' not in r])
        
        # Anomaly detection statistics
        anomalies_detected = len([
            r for r in results 
            if r.get('anomaly_detection', {}).get('is_anomaly', False)
        ])
        
        # Classification statistics (for anomalies)
        classified_anomalies = len([
            r for r in results 
            if (r.get('anomaly_detection', {}).get('is_anomaly', False) and 
                r.get('classification') is not None and
                'error' not in r.get('classification', {}))
        ])
        
        # Confidence statistics
        confident_classifications = len([
            r for r in results
            if (r.get('classification', {}).get('is_confident', False))
        ])
        
        # Manual review requirements
        requires_review = len([
            r for r in results
            if r.get('final_prediction', {}).get('requires_manual_review', False)
        ])
        
        # Category distribution
        categories = {}
        for result in results:
            category = result.get('final_prediction', {}).get('category', 'unknown')
            categories[category] = categories.get(category, 0) + 1
        
        return {
            'total_predictions': total_predictions,
            'successful_predictions': successful_predictions,
            'success_rate': successful_predictions / total_predictions if total_predictions > 0 else 0,
            'anomalies_detected': anomalies_detected,
            'anomaly_rate': anomalies_detected / total_predictions if total_predictions > 0 else 0,
            'classified_anomalies': classified_anomalies,
            'classification_rate': classified_anomalies / anomalies_detected if anomalies_detected > 0 else 0,
            'confident_classifications': confident_classifications,
            'confidence_rate': confident_classifications / classified_anomalies if classified_anomalies > 0 else 0,
            'requires_review': requires_review,
            'review_rate': requires_review / total_predictions if total_predictions > 0 else 0,
            'category_distribution': categories,
            'analyzed_at': datetime.now().isoformat()
        }
    
    def update_thresholds(
        self, 
        anomaly_threshold: Optional[float] = None,
        classification_confidence_threshold: Optional[float] = None
    ) -> None:
        """
        Update prediction thresholds.
        
        Args:
            anomaly_threshold: New anomaly detection threshold
            classification_confidence_threshold: New classification confidence threshold
        """
        if anomaly_threshold is not None:
            self.anomaly_threshold = anomaly_threshold
            logger.info(f"Anomaly threshold updated to {anomaly_threshold}")
        
        if classification_confidence_threshold is not None:
            self.classification_confidence_threshold = classification_confidence_threshold
            if self.attack_classifier:
                self.attack_classifier.update_confidence_threshold(classification_confidence_threshold)
            logger.info(f"Classification confidence threshold updated to {classification_confidence_threshold}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get comprehensive information about loaded models.
        
        Returns:
            Dictionary containing model information
        """
        info = {
            'hybrid_classifier': {
                'anomaly_threshold': self.anomaly_threshold,
                'classification_confidence_threshold': self.classification_confidence_threshold,
                'require_both_models': self.require_both_models,
                **self.model_info
            },
            'anomaly_model': {
                'loaded': self.model_info['anomaly_model_loaded'],
                'type': 'OneClassSVM',
                'threshold': self.anomaly_threshold
            },
            'classification_model': None
        }
        
        if self.attack_classifier:
            info['classification_model'] = self.attack_classifier.get_model_info()
        else:
            info['classification_model'] = {
                'loaded': False,
                'error': 'Classification model not initialized'
            }
        
        return info
    
    def save_configuration(self, config_name: str = "default") -> str:
        """
        Save hybrid classifier configuration.
        
        Args:
            config_name: Name for the configuration
            
        Returns:
            Path to saved configuration file
        """
        config_path = self.model_dir / f"hybrid_config_{config_name}.json"
        
        config = {
            'anomaly_threshold': self.anomaly_threshold,
            'classification_confidence_threshold': self.classification_confidence_threshold,
            'require_both_models': self.require_both_models,
            'model_info': self.model_info,
            'saved_at': datetime.now().isoformat()
        }
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Configuration saved to {config_path}")
        return str(config_path)
    
    def load_configuration(self, config_name: str = "default") -> bool:
        """
        Load hybrid classifier configuration.
        
        Args:
            config_name: Name of the configuration to load
            
        Returns:
            True if successful
        """
        try:
            config_path = self.model_dir / f"hybrid_config_{config_name}.json"
            
            if not config_path.exists():
                logger.error(f"Configuration file not found: {config_path}")
                return False
            
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            self.anomaly_threshold = config.get('anomaly_threshold', -0.5)
            self.classification_confidence_threshold = config.get('classification_confidence_threshold', 0.7)
            self.require_both_models = config.get('require_both_models', True)
            
            logger.info(f"Configuration loaded from {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False
    
    def process_live_connections(
        self, 
        connections_df: pd.DataFrame,
        store_results: bool = True,
        repository: Optional[TrainingRepository] = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Process live network connections through the hybrid pipeline.
        
        Args:
            connections_df: DataFrame containing connection data
            store_results: Whether to store results in repository
            repository: TrainingRepository instance for storage
            
        Returns:
            Tuple of (prediction_results, summary_statistics)
        """
        logger.info(f"Processing {len(connections_df)} live connections")
        
        # Convert DataFrame rows to list for batch prediction
        connections = [row for _, row in connections_df.iterrows()]
        
        # Perform batch prediction
        results = self.batch_predict(connections)
        
        # Analyze prediction quality
        quality_metrics = self.analyze_prediction_quality(results)
        
        # Store results in repository if requested
        if store_results and repository:
            try:
                self._store_results_in_repository(connections_df, results, repository)
            except Exception as e:
                logger.error(f"Failed to store results in repository: {e}")
        
        # Generate summary
        summary = {
            'processed_connections': len(connections_df),
            'processing_timestamp': datetime.now().isoformat(),
            'quality_metrics': quality_metrics,
            'anomalies_requiring_review': len([
                r for r in results 
                if r.get('final_prediction', {}).get('requires_manual_review', False)
            ])
        }
        
        return results, summary
    
    def _store_results_in_repository(
        self, 
        connections_df: pd.DataFrame, 
        results: List[Dict[str, Any]], 
        repository: TrainingRepository
    ) -> None:
        """Store prediction results in the training repository."""
        for i, (_, connection_row) in enumerate(connections_df.iterrows()):
            if i >= len(results):
                break
                
            result = results[i]
            
            # Skip if prediction failed
            if 'error' in result:
                continue
            
            try:
                # Create TrainingConnection object
                training_conn = TrainingConnection(
                    uid=str(connection_row.get('uid', f'live_{i}_{datetime.now().timestamp()}')),
                    timestamp=pd.to_datetime(connection_row.get('ts', datetime.now())),
                    source_ip=str(connection_row.get('id.orig_h', '0.0.0.0')),
                    dest_ip=str(connection_row.get('id.resp_h', '0.0.0.0')),
                    source_port=connection_row.get('id.orig_p'),
                    dest_port=connection_row.get('id.resp_p'),
                    proto=str(connection_row.get('proto', 'unknown')),
                    service=connection_row.get('service'),
                    duration=connection_row.get('duration'),
                    orig_bytes=connection_row.get('orig_bytes'),
                    resp_bytes=connection_row.get('resp_bytes'),
                    orig_pkts=connection_row.get('orig_pkts'),
                    resp_pkts=connection_row.get('resp_pkts'),
                    history=connection_row.get('history'),
                    feature_vector=np.array(result.get('feature_vector', [])),
                    anomaly_score=result.get('anomaly_detection', {}).get('score'),
                    is_anomaly=result.get('anomaly_detection', {}).get('is_anomaly', False),
                    label_category=result.get('final_prediction', {}).get('category'),
                    label_subcategory=result.get('final_prediction', {}).get('subcategory'),
                    confidence_level=None,  # Will be set based on manual review
                    labeled_by='hybrid_classifier',
                    labeled_at=datetime.now(),
                    training_source='hybrid_pipeline'
                )
                
                repository.add_connection(training_conn)
                
            except Exception as e:
                logger.warning(f"Failed to store connection {i} in repository: {e}")