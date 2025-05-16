#!/usr/bin/env python3
# test_pipeline.py - Test the ML pipeline with synthetic Zeek records

import os
import sys
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import argparse
from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve, average_precision_score

# Add parent directory to path to import custom modules if needed
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from parsers.zeek_loader import load_conn_log, zeek_to_features

def generate_normal_records(n_samples=100):
    """
    Generate synthetic normal Zeek records similar to those in sample_conn.log.

    Args:
        n_samples (int): Number of samples to generate

    Returns:
        pandas.DataFrame: DataFrame containing synthetic normal records
    """
    # Define ranges for normal traffic based on sample_conn.log
    normal_data = []

    # Sample values from sample_conn.log to use as templates
    proto_options = ['tcp', 'udp']
    service_options = ['http', 'ssl', 'dns']
    history_options = ['ShADadFf', 'Dd']

    # Approximate ranges from sample_conn.log
    duration_range = (0.005, 1.5)
    orig_bytes_range = (60, 4096)
    resp_bytes_range = (120, 32768)
    orig_pkts_range = (1, 48)
    resp_pkts_range = (1, 40)

    for _ in range(n_samples):
        # Generate a random timestamp (similar to sample_conn.log)
        base_ts = 1672531200.0  # 2023-01-01 00:00:00 UTC
        ts = pd.Timestamp.fromtimestamp(base_ts + np.random.randint(0, 5), tz='UTC')

        # Generate random values for other fields based on sample_conn.log patterns
        record = {
            'ts': ts,
            'uid': f'CXWfMc4eWKNl5EqQ{np.random.randint(0, 100)}',
            'proto': np.random.choice(proto_options, p=[0.8, 0.2]),
            'service': np.random.choice(service_options, p=[0.4, 0.4, 0.2]),
            'duration': np.random.uniform(*duration_range),
            'orig_bytes': np.random.randint(*orig_bytes_range),
            'resp_bytes': np.random.randint(*resp_bytes_range),
            'orig_pkts': np.random.randint(*orig_pkts_range),
            'resp_pkts': np.random.randint(*resp_pkts_range),
            'history': np.random.choice(history_options, p=[0.7, 0.3])
        }
        normal_data.append(record)

    return pd.DataFrame(normal_data)

def generate_anomalous_records(n_samples=20):
    """
    Generate synthetic anomalous Zeek records with unusual patterns.

    Args:
        n_samples (int): Number of samples to generate

    Returns:
        pandas.DataFrame: DataFrame containing synthetic anomalous records
    """
    anomaly_data = []

    for _ in range(n_samples):
        # Generate a random timestamp
        ts = pd.Timestamp.now(tz='UTC') - pd.Timedelta(seconds=np.random.randint(0, 86400))

        # Generate anomalous values (unusual patterns)
        record = {
            'ts': ts,
            'uid': f'C{np.random.randint(1000000, 9999999)}',
            'proto': np.random.choice(['tcp', 'udp', 'icmp']),  # Added unusual protocol
            'service': np.random.choice(['http', 'ssl', 'dns', 'ftp', 'ssh', 'unknown']),  # Added unusual services
            'duration': np.random.choice([
                np.random.exponential(10),  # Very long duration
                np.random.uniform(0, 0.001)  # Very short duration
            ]),
            'orig_bytes': np.random.choice([
                np.random.lognormal(12, 2),  # Very large
                0  # Zero bytes
            ]),
            'resp_bytes': np.random.choice([
                np.random.lognormal(12, 2),  # Very large
                0  # Zero bytes
            ]),
            'orig_pkts': np.random.choice([
                np.random.randint(100, 1000),  # Many packets
                1  # Single packet
            ]),
            'resp_pkts': np.random.choice([
                np.random.randint(100, 1000),  # Many packets
                0  # No response
            ]),
            'history': np.random.choice(['ShADadFf', 'Dd', 'S', 'SR', ''])  # Various histories
        }
        anomaly_data.append(record)

    return pd.DataFrame(anomaly_data)

def process_data(df, encoders, scaler, model, threshold=None):
    """
    Process data through the ML pipeline.

    Args:
        df (pandas.DataFrame): DataFrame containing Zeek records
        encoders (dict): Dictionary of encoders for categorical features
        scaler (sklearn.preprocessing.StandardScaler): Scaler for numerical features
        model (sklearn.svm.OneClassSVM): Trained OneClassSVM model
        threshold (float, optional): Custom decision threshold (default: None)

    Returns:
        tuple: (X_scaled, predictions, scores)
    """
    # Convert to features
    X, _ = zeek_to_features(df)

    # Scale features
    X_scaled = scaler.transform(X)

    # Get decision scores
    scores = model.decision_function(X_scaled)

    # Get predictions (using custom threshold if provided)
    if threshold is not None:
        predictions = np.where(scores > threshold, 1, -1)
    else:
        predictions = model.predict(X_scaled)

    return X_scaled, predictions, scores

def evaluate_model(y_true, y_pred, scores, show_plots=True):
    """
    Evaluate model performance and print metrics.

    Args:
        y_true (numpy.ndarray): True labels (1 for normal, -1 for anomaly)
        y_pred (numpy.ndarray): Predicted labels (1 for normal, -1 for anomaly)
        scores (numpy.ndarray): Decision function scores
        show_plots (bool): Whether to display ROC and PR curves
    """
    # Compute confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    print("\nConfusion Matrix:")
    print(cm)

    # Calculate accuracy, precision, recall, F1 score
    tn, fp, fn, tp = cm.ravel()
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\nAccuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")

    # Compute ROC curve and ROC area
    fpr, tpr, _ = roc_curve(y_true, scores)
    roc_auc = auc(fpr, tpr)
    print(f"ROC AUC: {roc_auc:.4f}")

    # Compute Precision-Recall curve
    precision_curve, recall_curve, _ = precision_recall_curve(y_true, scores)
    average_precision = average_precision_score(y_true, scores)
    print(f"Average Precision: {average_precision:.4f}")

    # Plot ROC and PR curves if requested
    if show_plots:
        plt.figure(figsize=(12, 5))

        plt.subplot(1, 2, 1)
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")

        plt.subplot(1, 2, 2)
        plt.plot(recall_curve, precision_curve, color='blue', lw=2, 
                 label=f'Precision-Recall curve (AP = {average_precision:.2f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend(loc="lower left")

        plt.tight_layout()
        plt.show()

def load_sample_conn_log(path='data/sample_conn.log'):
    """
    Load the sample_conn.log file for normal records.

    Args:
        path (str): Path to the sample_conn.log file

    Returns:
        pandas.DataFrame: DataFrame containing the sample_conn.log data
    """
    try:
        return load_conn_log(path)
    except FileNotFoundError:
        print(f"Warning: Sample conn.log file not found at {path}")
        print("Falling back to synthetic normal data generation")
        return None

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Test the ML pipeline with synthetic Zeek records.'
    )
    parser.add_argument('--use-training-data', action='store_true',
                        help='Use the actual training data (sample_conn.log) for normal records')
    parser.add_argument('--normal-samples', type=int, default=100,
                        help='Number of normal samples to generate (default: 100)')
    parser.add_argument('--anomaly-samples', type=int, default=20,
                        help='Number of anomalous samples to generate (default: 20)')
    parser.add_argument('--threshold', type=float, default=None,
                        help='Custom decision threshold for the OneClassSVM model (default: 0)')
    parser.add_argument('--no-plots', action='store_true',
                        help='Disable plotting of ROC and PR curves')
    return parser.parse_args()

def main():
    """
    Main function to test the ML pipeline with synthetic data.
    """
    # Parse command line arguments
    args = parse_args()

    print("Testing ML Pipeline with Zeek Records")
    print("=" * 50)

    # Load trained models
    try:
        model_dir = 'output/ocsvm_model'
        model_path = os.path.join(model_dir, 'ocsvm_model.pkl')
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        encoders_path = os.path.join(model_dir, 'encoders.pkl')

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        encoders = joblib.load(encoders_path)
        print("Loaded trained models successfully")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Make sure to run training/train_ocsvm.py first to generate the model files.")
        sys.exit(1)

    # Generate or load data
    print("\nPreparing data...")

    # Normal data - either load from sample_conn.log or generate synthetic
    if args.use_training_data:
        normal_df = load_sample_conn_log()
        if normal_df is None:
            normal_df = generate_normal_records(n_samples=args.normal_samples)
            print(f"Generated {len(normal_df)} synthetic normal records")
        else:
            print(f"Loaded {len(normal_df)} normal records from sample_conn.log")
    else:
        normal_df = generate_normal_records(n_samples=args.normal_samples)
        print(f"Generated {len(normal_df)} synthetic normal records")

    # Anomalous data - always generate synthetic
    anomaly_df = generate_anomalous_records(n_samples=args.anomaly_samples)
    print(f"Generated {len(anomaly_df)} synthetic anomalous records")

    # Process normal data with threshold if provided
    print("\nProcessing normal data...")
    if args.threshold is not None:
        print(f"Using custom decision threshold: {args.threshold}")
    _, normal_pred, normal_scores = process_data(normal_df, encoders, scaler, model, args.threshold)

    # Process anomalous data with threshold if provided
    print("Processing anomalous data...")
    _, anomaly_pred, anomaly_scores = process_data(anomaly_df, encoders, scaler, model, args.threshold)

    # Combine results
    all_predictions = np.concatenate([normal_pred, anomaly_pred])
    all_scores = np.concatenate([normal_scores, anomaly_scores])

    # True labels: 1 for normal, -1 for anomaly
    true_labels = np.concatenate([np.ones(len(normal_df)), -np.ones(len(anomaly_df))])

    # Print detection results
    normal_detected = np.sum(normal_pred == 1)
    anomaly_detected = np.sum(anomaly_pred == -1)

    print("\nDetection Results:")
    print(f"Normal records correctly identified as normal: {normal_detected}/{len(normal_df)} ({normal_detected/len(normal_df)*100:.1f}%)")
    print(f"Anomalous records correctly identified as anomalies: {anomaly_detected}/{len(anomaly_df)} ({anomaly_detected/len(anomaly_df)*100:.1f}%)")

    # Evaluate model performance
    evaluate_model(true_labels, all_predictions, all_scores, not args.no_plots)

if __name__ == "__main__":
    main()
