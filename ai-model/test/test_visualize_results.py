#!/usr/bin/env python3
# test_visualize_results.py - Test the visualize_results.py script with sample data

import os
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import subprocess

def create_sample_data(num_samples=100, anomaly_ratio=0.1, with_true_labels=True):
    """Create sample data for testing the visualization script."""
    # Create random UIDs
    uids = [f"C{i:08d}" for i in range(num_samples)]
    
    # Create timestamps over the last hour
    now = datetime.now()
    timestamps = [(now - timedelta(minutes=i)).isoformat() for i in range(num_samples)]
    
    # Create random scores (negative values for normal, positive for anomalies)
    np.random.seed(42)  # For reproducibility
    scores = np.random.normal(-1, 0.5, num_samples)
    
    # Make some scores positive (anomalies)
    anomaly_indices = np.random.choice(num_samples, int(num_samples * anomaly_ratio), replace=False)
    scores[anomaly_indices] = np.random.normal(1, 0.5, len(anomaly_indices))
    
    # Create predictions based on scores
    predictions = ['normal' if score < 0 else 'anomaly' for score in scores]
    
    # Create data dictionary
    data = {
        'uid': uids,
        'timestamp': timestamps,
        'score': scores,
        'prediction': predictions
    }
    
    # Add true labels if requested
    if with_true_labels:
        # Create some mislabeled samples for interesting metrics
        true_labels = predictions.copy()
        mislabeled_indices = np.random.choice(num_samples, int(num_samples * 0.05), replace=False)
        for idx in mislabeled_indices:
            true_labels[idx] = 'anomaly' if true_labels[idx] == 'normal' else 'normal'
        
        data['true_label'] = true_labels
    
    return pd.DataFrame(data)

def main():
    # Create output directory
    output_dir = 'output/test_visualizations'
    os.makedirs(output_dir, exist_ok=True)
    
    # Create sample data with true labels
    print("Creating sample data with true labels...")
    df_with_labels = create_sample_data(with_true_labels=True)
    csv_path_with_labels = os.path.join(output_dir, 'sample_with_labels.csv')
    df_with_labels.to_csv(csv_path_with_labels, index=False)
    print(f"Sample data with true labels saved to: {csv_path_with_labels}")
    
    # Create sample data without true labels
    print("Creating sample data without true labels...")
    df_without_labels = create_sample_data(with_true_labels=False)
    csv_path_without_labels = os.path.join(output_dir, 'sample_without_labels.csv')
    df_without_labels.to_csv(csv_path_without_labels, index=False)
    print(f"Sample data without true labels saved to: {csv_path_without_labels}")
    
    # Test visualize_results.py with true labels
    print("\nTesting visualize_results.py with true labels...")
    vis_dir_with_labels = os.path.join(output_dir, 'with_labels')
    os.makedirs(vis_dir_with_labels, exist_ok=True)
    
    try:
        cmd = f"python visualize_results.py {csv_path_with_labels} {vis_dir_with_labels} --title-prefix='With Labels: '"
        print(f"Running command: {cmd}")
        subprocess.run(cmd, shell=True, check=True)
        print(f"Visualizations with true labels saved to: {vis_dir_with_labels}")
    except subprocess.CalledProcessError as e:
        print(f"Error running visualize_results.py with true labels: {e}")
    
    # Test visualize_results.py without true labels
    print("\nTesting visualize_results.py without true labels...")
    vis_dir_without_labels = os.path.join(output_dir, 'without_labels')
    os.makedirs(vis_dir_without_labels, exist_ok=True)
    
    try:
        cmd = f"python visualize_results.py {csv_path_without_labels} {vis_dir_without_labels} --title-prefix='Without Labels: '"
        print(f"Running command: {cmd}")
        subprocess.run(cmd, shell=True, check=True)
        print(f"Visualizations without true labels saved to: {vis_dir_without_labels}")
    except subprocess.CalledProcessError as e:
        print(f"Error running visualize_results.py without true labels: {e}")
    
    print("\nTest completed. Please check the output directories for the generated visualizations.")

if __name__ == "__main__":
    main()