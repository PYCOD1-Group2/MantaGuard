#!/usr/bin/env python3
"""
Multi-class classifier for network attack classification in MantaGuard.

This module provides functionality to classify network connections into specific
attack categories using supervised learning techniques.
"""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.utils.class_weight import compute_class_weight
import json

from mantaguard.utils.logger import get_logger
from mantaguard.utils.file_utils import safe_create_directory
from mantaguard.data.storage.training_repository import TrainingRepository, ConfidenceLevel

logger = get_logger(__name__)


class MultiClassNetworkClassifier:
    """Multi-class classifier for network attack categorization."""
    
    def __init__(self, model_dir: Optional[str] = None, classifier_type: str = 'random_forest'):
        """
        Initialize the multi-class classifier.
        
        Args:
            model_dir: Directory to save/load model files
            classifier_type: Type of classifier ('random_forest', 'gradient_boosting')
        """
        if model_dir is None:
            project_root = Path(__file__).parent.parent.parent.parent.parent
            self.model_dir = project_root / "data" / "output" / "multi_class_models"
        else:
            self.model_dir = Path(model_dir)
            
        safe_create_directory(self.model_dir)
        
        self.classifier_type = classifier_type
        self.model = None
        self.label_encoder = None
        self.feature_scaler = None
        self.class_names = None
        self.confidence_threshold = 0.7
        self.min_samples_per_class = 10
        
        # Model performance metrics
        self.last_training_metrics = {}
        
    def _create_classifier(self) -> Any:
        """Create the underlying classifier based on type."""
        if self.classifier_type == 'random_forest':
            return RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced',
                n_jobs=-1
            )
        elif self.classifier_type == 'gradient_boosting':
            return GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
            )
        else:
            raise ValueError(f"Unknown classifier type: {self.classifier_type}")
    
    def train_from_repository(
        self, 
        repository: TrainingRepository,
        min_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
        hyperparameter_tuning: bool = False
    ) -> Dict[str, Any]:
        """
        Train the classifier using data from the training repository.
        
        Args:
            repository: TrainingRepository instance
            min_confidence: Minimum confidence level for training data
            hyperparameter_tuning: Whether to perform hyperparameter optimization
            
        Returns:
            Dictionary containing training metrics and results
        """
        logger.info("Loading training data from repository...")
        
        # Get labeled connections with minimum confidence
        connections = repository.get_connections(limit=100000)  # Get all connections
        
        # Filter for labeled anomalies with sufficient confidence
        training_data = []
        for conn in connections:
            if (conn.label_category and 
                conn.label_subcategory and 
                conn.feature_vector is not None and
                conn.confidence_level and
                self._confidence_meets_minimum(conn.confidence_level, min_confidence)):
                training_data.append(conn)
        
        if len(training_data) < 20:
            raise ValueError(f"Insufficient training data: {len(training_data)} samples (minimum 20 required)")
        
        logger.info(f"Found {len(training_data)} labeled connections for training")
        
        # Prepare features and labels
        X = np.array([conn.feature_vector for conn in training_data])
        y_category = [conn.label_category for conn in training_data]
        y_subcategory = [f"{conn.label_category}.{conn.label_subcategory}" for conn in training_data]
        
        # Check class distribution
        class_counts = pd.Series(y_subcategory).value_counts()
        valid_classes = class_counts[class_counts >= self.min_samples_per_class].index
        
        if len(valid_classes) < 2:
            raise ValueError(f"Insufficient classes with minimum samples. Need at least 2 classes with {self.min_samples_per_class}+ samples each")
        
        # Filter to only include classes with sufficient samples
        valid_indices = [i for i, label in enumerate(y_subcategory) if label in valid_classes]
        X = X[valid_indices]
        y_subcategory = [y_subcategory[i] for i in valid_indices]
        
        logger.info(f"Training with {len(valid_classes)} classes: {list(valid_classes)}")
        
        # Encode labels
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y_subcategory)
        self.class_names = self.label_encoder.classes_
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )
        
        # Create and train classifier
        if hyperparameter_tuning:
            self.model = self._tune_hyperparameters(X_train, y_train)
        else:
            self.model = self._create_classifier()
            self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        classification_rep = classification_report(
            y_test, y_pred, 
            target_names=self.class_names,
            output_dict=True
        )
        confusion_mat = confusion_matrix(y_test, y_pred)
        
        # Calculate confidence-based metrics
        confident_predictions = np.max(y_pred_proba, axis=1) >= self.confidence_threshold
        confident_accuracy = accuracy_score(
            y_test[confident_predictions], 
            y_pred[confident_predictions]
        ) if np.any(confident_predictions) else 0.0
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X, y_encoded, cv=5, scoring='accuracy')
        
        # Feature importance (for tree-based models)
        feature_importance = None
        if hasattr(self.model, 'feature_importances_'):
            feature_importance = self.model.feature_importances_.tolist()
        
        # Store training metrics
        self.last_training_metrics = {
            'accuracy': accuracy,
            'confident_accuracy': confident_accuracy,
            'confidence_threshold': self.confidence_threshold,
            'confident_ratio': np.mean(confident_predictions),
            'cv_mean': np.mean(cv_scores),
            'cv_std': np.std(cv_scores),
            'classification_report': classification_rep,
            'confusion_matrix': confusion_mat.tolist(),
            'feature_importance': feature_importance,
            'class_names': self.class_names.tolist(),
            'training_samples': len(training_data),
            'test_samples': len(X_test),
            'classes_count': len(self.class_names),
            'trained_at': datetime.now().isoformat()
        }
        
        logger.info(f"Training completed. Accuracy: {accuracy:.3f}, Confident accuracy: {confident_accuracy:.3f}")
        logger.info(f"Cross-validation: {np.mean(cv_scores):.3f} ± {np.std(cv_scores):.3f}")
        
        return self.last_training_metrics
    
    def _confidence_meets_minimum(self, level: ConfidenceLevel, minimum: ConfidenceLevel) -> bool:
        """Check if confidence level meets minimum requirement."""
        confidence_order = [ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM, ConfidenceLevel.HIGH]
        return confidence_order.index(level) >= confidence_order.index(minimum)
    
    def _tune_hyperparameters(self, X_train: np.ndarray, y_train: np.ndarray) -> Any:
        """Perform hyperparameter tuning using grid search."""
        logger.info("Performing hyperparameter tuning...")
        
        if self.classifier_type == 'random_forest':
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [10, 15, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            }
            base_model = RandomForestClassifier(random_state=42, class_weight='balanced', n_jobs=-1)
        else:
            param_grid = {
                'n_estimators': [50, 100, 200],
                'learning_rate': [0.05, 0.1, 0.2],
                'max_depth': [5, 10, 15],
                'min_samples_split': [2, 5, 10]
            }
            base_model = GradientBoostingClassifier(random_state=42)
        
        grid_search = GridSearchCV(
            base_model, param_grid, 
            cv=3, scoring='accuracy', 
            n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best cross-validation score: {grid_search.best_score_:.3f}")
        
        return grid_search.best_estimator_
    
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Predict attack category for given features.
        
        Args:
            features: Feature vector(s) for prediction
            
        Returns:
            Dictionary containing prediction results
        """
        if self.model is None:
            raise RuntimeError("Model not trained. Call train_from_repository() first.")
        
        # Handle single sample
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Make predictions
        predictions = self.model.predict(features)
        probabilities = self.model.predict_proba(features)
        
        results = []
        for i in range(len(features)):
            pred_class = self.class_names[predictions[i]]
            max_prob = np.max(probabilities[i])
            
            # Parse category and subcategory
            if '.' in pred_class:
                category, subcategory = pred_class.split('.', 1)
            else:
                category = pred_class
                subcategory = pred_class
            
            # Determine if prediction is confident
            is_confident = max_prob >= self.confidence_threshold
            
            # If not confident, mark as unknown
            if not is_confident:
                category = "unknown"
                subcategory = "unknown"
            
            result = {
                'category': category,
                'subcategory': subcategory,
                'confidence': float(max_prob),
                'is_confident': is_confident,
                'probabilities': {
                    self.class_names[j]: float(probabilities[i][j]) 
                    for j in range(len(self.class_names))
                },
                'requires_review': not is_confident
            }
            results.append(result)
        
        return results[0] if len(results) == 1 else results
    
    def save_model(self, version: str = "v1") -> str:
        """
        Save the trained model to disk.
        
        Args:
            version: Model version string
            
        Returns:
            Path to saved model file
        """
        if self.model is None:
            raise RuntimeError("No model to save. Train a model first.")
        
        model_path = self.model_dir / f"multi_class_model_{version}.pkl"
        encoder_path = self.model_dir / f"label_encoder_{version}.pkl"
        metadata_path = self.model_dir / f"model_metadata_{version}.json"
        
        # Save model components
        joblib.dump(self.model, model_path)
        joblib.dump(self.label_encoder, encoder_path)
        
        # Save metadata
        metadata = {
            'classifier_type': self.classifier_type,
            'confidence_threshold': self.confidence_threshold,
            'class_names': self.class_names.tolist() if self.class_names is not None else None,
            'training_metrics': self.last_training_metrics,
            'version': version,
            'created_at': datetime.now().isoformat()
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model saved to {model_path}")
        return str(model_path)
    
    def load_model(self, version: str = "v1") -> bool:
        """
        Load a trained model from disk.
        
        Args:
            version: Model version string
            
        Returns:
            True if successful, False otherwise
        """
        try:
            model_path = self.model_dir / f"multi_class_model_{version}.pkl"
            encoder_path = self.model_dir / f"label_encoder_{version}.pkl"
            metadata_path = self.model_dir / f"model_metadata_{version}.json"
            
            # Check if files exist
            if not all(path.exists() for path in [model_path, encoder_path, metadata_path]):
                logger.error(f"Model files not found for version {version}")
                return False
            
            # Load model components
            self.model = joblib.load(model_path)
            self.label_encoder = joblib.load(encoder_path)
            
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            self.classifier_type = metadata.get('classifier_type', 'random_forest')
            self.confidence_threshold = metadata.get('confidence_threshold', 0.7)
            self.class_names = np.array(metadata.get('class_names', []))
            self.last_training_metrics = metadata.get('training_metrics', {})
            
            logger.info(f"Model {version} loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model {version}: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the current model.
        
        Returns:
            Dictionary containing model information
        """
        if self.model is None:
            return {'error': 'No model loaded'}
        
        info = {
            'classifier_type': self.classifier_type,
            'confidence_threshold': self.confidence_threshold,
            'num_classes': len(self.class_names) if self.class_names is not None else 0,
            'class_names': self.class_names.tolist() if self.class_names is not None else [],
            'is_trained': self.model is not None,
            'last_training_metrics': self.last_training_metrics
        }
        
        return info
    
    def update_confidence_threshold(self, threshold: float) -> None:
        """
        Update the confidence threshold for predictions.
        
        Args:
            threshold: New confidence threshold (0.0 to 1.0)
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")
        
        self.confidence_threshold = threshold
        logger.info(f"Confidence threshold updated to {threshold}")
    
    def evaluate_on_test_data(self, repository: TrainingRepository) -> Dict[str, Any]:
        """
        Evaluate model performance on recent test data.
        
        Args:
            repository: TrainingRepository instance
            
        Returns:
            Dictionary containing evaluation metrics
        """
        if self.model is None:
            raise RuntimeError("No model loaded")
        
        # Get recent labeled connections for testing
        connections = repository.get_connections(
            limit=1000,
            filter_params={'review_status': 'verified'}
        )
        
        if len(connections) < 10:
            return {'error': 'Insufficient test data', 'sample_count': len(connections)}
        
        # Prepare test data
        test_data = []
        for conn in connections:
            if (conn.label_category and 
                conn.label_subcategory and 
                conn.feature_vector is not None):
                test_data.append(conn)
        
        if len(test_data) < 10:
            return {'error': 'Insufficient valid test data', 'sample_count': len(test_data)}
        
        X_test = np.array([conn.feature_vector for conn in test_data])
        y_true = [f"{conn.label_category}.{conn.label_subcategory}" for conn in test_data]
        
        # Make predictions
        predictions = []
        for features in X_test:
            pred = self.predict(features)
            full_label = f"{pred['category']}.{pred['subcategory']}"
            predictions.append(full_label)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, predictions)
        
        # Calculate per-class metrics
        unique_labels = list(set(y_true + predictions))
        per_class_metrics = {}
        
        for label in unique_labels:
            true_positive = sum(1 for t, p in zip(y_true, predictions) if t == label and p == label)
            false_positive = sum(1 for t, p in zip(y_true, predictions) if t != label and p == label)
            false_negative = sum(1 for t, p in zip(y_true, predictions) if t == label and p != label)
            
            precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) > 0 else 0
            recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            per_class_metrics[label] = {
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'support': sum(1 for t in y_true if t == label)
            }
        
        return {
            'accuracy': accuracy,
            'test_samples': len(test_data),
            'per_class_metrics': per_class_metrics,
            'evaluated_at': datetime.now().isoformat()
        }