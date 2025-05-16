#!/usr/bin/env python3
# train_ocsvm.py - Train a OneClassSVM model on Zeek conn.log data

import os
import sys
import argparse
import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# Add parent directory to path to import custom modules if needed
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from parsers.zeek_loader import load_conn_log, zeek_to_features

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Train a OneClassSVM model on Zeek conn.log data containing normal traffic.'
    )
    parser.add_argument('--log', required=True, help='Path to Zeek conn.log file containing normal traffic')
    parser.add_argument('--output-dir', default='output/ocsvm_model', help='Directory to save model files')
    return parser.parse_args()

def main():
    """Main function to train and save the OneClassSVM model."""
    # Parse command line arguments
    args = parse_args()

    # Check if the log file exists
    if not os.path.isfile(args.log):
        print(f"Error: Log file not found: {args.log}")
        sys.exit(1)

    print(f"Loading Zeek conn.log from: {args.log}")
    try:
        # Load the Zeek conn.log file
        df = load_conn_log(args.log)
        print(f"Loaded DataFrame with shape: {df.shape}")

        # Convert to features
        X, encoders = zeek_to_features(df)
        print(f"Created feature matrix with shape: {X.shape}")

        # Apply standard scaling
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        print(f"Applied standard scaling to features")

        # Train OneClassSVM model
        print("Training OneClassSVM model...")
        model = OneClassSVM(kernel='rbf', nu=0.01, gamma='scale')
        model.fit(X_scaled)
        print("Model training completed")

        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)

        # Save model, scaler, and encoders
        print(f"Saving model, scaler, and encoders to {args.output_dir}...")
        model_path = os.path.join(args.output_dir, 'ocsvm_model.pkl')
        scaler_path = os.path.join(args.output_dir, 'scaler.pkl')
        encoders_path = os.path.join(args.output_dir, 'encoders.pkl')

        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)
        joblib.dump(encoders, encoders_path)

        print("Files saved successfully:")
        print(f"  - {model_path}")
        print(f"  - {scaler_path}")
        print(f"  - {encoders_path}")

        # Print training stats
        print("\nTraining Statistics:")
        print(f"Number of samples: {X.shape[0]}")
        print(f"Feature shape: {X.shape[1]}")

    except Exception as e:
        print(f"Error during training: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
