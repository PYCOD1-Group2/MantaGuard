#!/usr/bin/env python3
"""
Training validation utilities for MantaGuard.

This module provides functionality to validate training data and parameters
before starting model retraining operations.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import Counter

from mantaguard.utils.logger import get_logger

logger = get_logger(__name__)


class TrainingValidator:
    """Validates training data and parameters before model retraining."""
    
    def __init__(self, model_dir: str = None):
        """
        Initialize training validator.
        
        Args:
            model_dir: Directory containing model files
        """
        if model_dir is None:
            project_root = Path(__file__).parent.parent.parent
            self.model_dir = project_root / "data" / "output" / "ocsvm_model"
        else:
            self.model_dir = Path(model_dir)
    
    def validate_labeled_data(self, min_samples: int = 50, min_categories: int = 2) -> Dict:
        """
        Validate labeled anomalies data for training.
        
        Args:
            min_samples: Minimum number of labeled samples required
            min_categories: Minimum number of attack categories required
            
        Returns:
            Dictionary with validation results
        """
        try:
            labeled_path = self.model_dir / "labeled_anomalies.csv"
            
            if not labeled_path.exists():
                return {
                    'is_valid': False,
                    'error': 'No labeled anomalies file found',
                    'recommendations': ['Label some anomalies before starting training']
                }
            
            # Load labeled data
            df = pd.read_csv(labeled_path)
            
            if len(df) == 0:
                return {
                    'is_valid': False,
                    'error': 'Labeled anomalies file is empty',
                    'recommendations': ['Label some anomalies before starting training']
                }
            
            # Validation checks
            validation_results = {
                'total_samples': len(df),
                'has_min_samples': len(df) >= min_samples,
                'attack_categories': {},
                'has_min_categories': False,
                'feature_vector_quality': {},
                'data_quality_issues': [],
                'recommendations': []
            }
            
            # Check attack categories
            if 'attack_category' in df.columns:
                category_counts = df['attack_category'].value_counts()
                validation_results['attack_categories'] = category_counts.to_dict()
                validation_results['has_min_categories'] = len(category_counts) >= min_categories
                
                # Check category balance
                min_category_count = category_counts.min()
                max_category_count = category_counts.max()
                balance_ratio = min_category_count / max_category_count if max_category_count > 0 else 0
                
                validation_results['category_balance_ratio'] = balance_ratio
                validation_results['is_balanced'] = balance_ratio > 0.2  # At least 20% balance
                
                if not validation_results['is_balanced']:
                    validation_results['recommendations'].append(
                        f"Consider balancing attack categories. Smallest category has {min_category_count} samples, "
                        f"largest has {max_category_count} samples."
                    )
            else:
                validation_results['data_quality_issues'].append('Missing attack_category column')
                validation_results['recommendations'].append('Ensure all anomalies have attack categories assigned')
            
            # Check feature vector quality
            if 'feature_vector' in df.columns:
                try:
                    # Test parsing a few feature vectors
                    sample_features = []
                    parse_errors = 0
                    
                    for i, row in df.head(10).iterrows():
                        try:
                            feature_str = row['feature_vector'].strip('[]')
                            features = np.array([float(x.strip()) for x in feature_str.split(',')])
                            sample_features.append(len(features))
                        except Exception:
                            parse_errors += 1
                    
                    if sample_features:
                        validation_results['feature_vector_quality'] = {
                            'parseable': True,
                            'consistent_dimensions': len(set(sample_features)) == 1,
                            'feature_dimensions': sample_features[0] if sample_features else 0,
                            'parse_error_rate': parse_errors / 10
                        }
                        
                        if parse_errors > 0:
                            validation_results['data_quality_issues'].append(
                                f'{parse_errors}/10 feature vectors failed to parse'
                            )
                        
                        if not validation_results['feature_vector_quality']['consistent_dimensions']:
                            validation_results['data_quality_issues'].append(
                                'Inconsistent feature vector dimensions detected'
                            )
                    else:
                        validation_results['feature_vector_quality'] = {
                            'parseable': False,
                            'consistent_dimensions': False,
                            'feature_dimensions': 0,
                            'parse_error_rate': 1.0
                        }
                        validation_results['data_quality_issues'].append('No parseable feature vectors found')
                        
                except Exception as e:
                    validation_results['feature_vector_quality'] = {
                        'parseable': False,
                        'error': str(e)
                    }
                    validation_results['data_quality_issues'].append(f'Feature vector parsing error: {e}')
            else:
                validation_results['data_quality_issues'].append('Missing feature_vector column')
            
            # Check confidence levels
            if 'confidence' in df.columns:
                confidence_dist = df['confidence'].value_counts()
                validation_results['confidence_distribution'] = confidence_dist.to_dict()
                
                high_confidence_ratio = len(df[df['confidence'] == 'high']) / len(df)
                if high_confidence_ratio > 0.8:
                    validation_results['recommendations'].append(
                        'Very high percentage of high-confidence labels. Consider reviewing labeling criteria.'
                    )
                elif high_confidence_ratio < 0.3:
                    validation_results['recommendations'].append(
                        'Low percentage of high-confidence labels. Consider improving label quality.'
                    )
            
            # Generate sample size recommendations
            if not validation_results['has_min_samples']:
                needed = min_samples - validation_results['total_samples']
                validation_results['recommendations'].append(
                    f'Need {needed} more labeled samples (current: {validation_results["total_samples"]}, '
                    f'minimum: {min_samples})'
                )
            
            if not validation_results['has_min_categories']:
                current_categories = len(validation_results['attack_categories'])
                validation_results['recommendations'].append(
                    f'Need more attack category diversity (current: {current_categories}, '
                    f'minimum: {min_categories})'
                )
            
            # Overall validation
            validation_results['is_valid'] = (
                validation_results['has_min_samples'] and
                validation_results['has_min_categories'] and
                len(validation_results['data_quality_issues']) == 0
            )
            
            # Risk assessment
            if validation_results['is_valid']:
                validation_results['risk_level'] = 'low'
                validation_results['training_recommended'] = True
            elif validation_results['has_min_samples'] and len(validation_results['data_quality_issues']) <= 1:
                validation_results['risk_level'] = 'medium'
                validation_results['training_recommended'] = True
                validation_results['recommendations'].append(
                    'Training can proceed but consider addressing data quality issues'
                )
            else:
                validation_results['risk_level'] = 'high'
                validation_results['training_recommended'] = False
                validation_results['recommendations'].append(
                    'Training not recommended until data quality issues are resolved'
                )
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Error validating labeled data: {e}")
            return {
                'is_valid': False,
                'error': str(e),
                'recommendations': ['Fix data loading issues before training']
            }
    
    def estimate_training_time(self, sample_count: int) -> Dict:
        """
        Estimate training time based on sample count and system resources.
        
        Args:
            sample_count: Number of training samples
            
        Returns:
            Dictionary with time estimates
        """
        try:
            # Basic time estimation (these are rough estimates)
            base_time_per_sample = 0.01  # seconds per sample for OCSVM
            
            # Adjust for sample count (non-linear scaling)
            if sample_count < 1000:
                time_factor = 1.0
            elif sample_count < 10000:
                time_factor = 1.5
            else:
                time_factor = 2.0
            
            estimated_seconds = sample_count * base_time_per_sample * time_factor
            
            # Add overhead for data processing
            overhead_seconds = min(30, sample_count * 0.001)
            total_seconds = estimated_seconds + overhead_seconds
            
            # Convert to human-readable format
            if total_seconds < 60:
                time_str = f"{int(total_seconds)} seconds"
            elif total_seconds < 3600:
                minutes = int(total_seconds / 60)
                seconds = int(total_seconds % 60)
                time_str = f"{minutes}m {seconds}s"
            else:
                hours = int(total_seconds / 3600)
                minutes = int((total_seconds % 3600) / 60)
                time_str = f"{hours}h {minutes}m"
            
            return {
                'estimated_seconds': int(total_seconds),
                'estimated_time_str': time_str,
                'sample_count': sample_count,
                'complexity_factor': time_factor,
                'overhead_seconds': int(overhead_seconds)
            }
            
        except Exception as e:
            logger.error(f"Error estimating training time: {e}")
            return {
                'estimated_seconds': 0,
                'estimated_time_str': 'Unknown',
                'error': str(e)
            }
    
    def validate_training_parameters(self, params: Dict) -> Dict:
        """
        Validate training parameters.
        
        Args:
            params: Dictionary of training parameters
            
        Returns:
            Dictionary with validation results
        """
        try:
            validation_results = {
                'is_valid': True,
                'parameter_issues': [],
                'recommendations': []
            }
            
            # Validate nu parameter (for OCSVM)
            nu = params.get('nu', 0.01)
            if not isinstance(nu, (int, float)) or nu <= 0 or nu > 1:
                validation_results['parameter_issues'].append(
                    f'Invalid nu parameter: {nu}. Must be between 0 and 1.'
                )
                validation_results['recommendations'].append('Use nu between 0.01 and 0.1 for most cases')
            elif nu > 0.5:
                validation_results['recommendations'].append(
                    f'Nu parameter ({nu}) is quite high. Consider using a lower value (0.01-0.1) for better anomaly detection.'
                )
            
            # Validate gamma parameter
            gamma = params.get('gamma', 'scale')
            valid_gamma_values = ['scale', 'auto']
            if isinstance(gamma, str) and gamma not in valid_gamma_values:
                if gamma != 'scale' and gamma != 'auto':
                    try:
                        float(gamma)
                    except ValueError:
                        validation_results['parameter_issues'].append(
                            f'Invalid gamma parameter: {gamma}. Must be "scale", "auto", or a positive number.'
                        )
            elif isinstance(gamma, (int, float)) and gamma <= 0:
                validation_results['parameter_issues'].append(
                    f'Invalid gamma parameter: {gamma}. Must be positive.'
                )
            
            # Validate kernel parameter
            kernel = params.get('kernel', 'rbf')
            valid_kernels = ['linear', 'poly', 'rbf', 'sigmoid']
            if kernel not in valid_kernels:
                validation_results['parameter_issues'].append(
                    f'Invalid kernel: {kernel}. Must be one of {valid_kernels}.'
                )
            
            # Validate training type
            training_type = params.get('training_type', 'batch')
            valid_types = ['batch', 'reinforcement', 'incremental']
            if training_type not in valid_types:
                validation_results['parameter_issues'].append(
                    f'Invalid training type: {training_type}. Must be one of {valid_types}.'
                )
            
            validation_results['is_valid'] = len(validation_results['parameter_issues']) == 0
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Error validating training parameters: {e}")
            return {
                'is_valid': False,
                'error': str(e),
                'parameter_issues': ['Parameter validation failed']
            }
    
    def get_training_recommendations(self, validation_results: Dict) -> List[str]:
        """
        Generate comprehensive training recommendations based on validation results.
        
        Args:
            validation_results: Results from validate_labeled_data()
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        try:
            # Sample size recommendations
            if validation_results.get('total_samples', 0) < 100:
                recommendations.append(
                    "🔴 Critical: Very few labeled samples. Label at least 100 anomalies for reliable training."
                )
            elif validation_results.get('total_samples', 0) < 200:
                recommendations.append(
                    "🟡 Warning: Consider labeling more samples for better model performance."
                )
            else:
                recommendations.append(
                    "✅ Good: Sufficient labeled samples for training."
                )
            
            # Category diversity recommendations
            categories = validation_results.get('attack_categories', {})
            if len(categories) < 3:
                recommendations.append(
                    "🔴 Critical: Label more diverse attack types for comprehensive detection."
                )
            elif len(categories) < 5:
                recommendations.append(
                    "🟡 Warning: Consider adding more attack categories for better coverage."
                )
            else:
                recommendations.append(
                    "✅ Good: Good diversity in attack categories."
                )
            
            # Data quality recommendations
            quality_issues = validation_results.get('data_quality_issues', [])
            if quality_issues:
                recommendations.append(
                    f"🔴 Data Quality: {len(quality_issues)} issues found. Review before training."
                )
            else:
                recommendations.append(
                    "✅ Good: No data quality issues detected."
                )
            
            # Balance recommendations
            balance_ratio = validation_results.get('category_balance_ratio', 1.0)
            if balance_ratio < 0.1:
                recommendations.append(
                    "🔴 Critical: Severe category imbalance. Balance your training data."
                )
            elif balance_ratio < 0.3:
                recommendations.append(
                    "🟡 Warning: Category imbalance detected. Consider balancing training data."
                )
            
            # Risk level recommendations
            risk_level = validation_results.get('risk_level', 'unknown')
            if risk_level == 'high':
                recommendations.append(
                    "⚠️ HIGH RISK: Training not recommended until issues are resolved."
                )
            elif risk_level == 'medium':
                recommendations.append(
                    "⚠️ MEDIUM RISK: Training can proceed but monitor results carefully."
                )
            else:
                recommendations.append(
                    "✅ LOW RISK: Training conditions are good."
                )
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            recommendations.append("Error generating recommendations. Review data manually.")
        
        return recommendations