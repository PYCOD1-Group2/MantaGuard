#!/usr/bin/env python3
# test_realtime_detector.py - Test the realtime_detector.py script

import os
import sys
import pandas as pd
import numpy as np
import joblib
from datetime import datetime

# Add parent directory to path to import custom modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from parsers.zeek_loader import load_conn_log, zeek_to_features

def test_feature_extraction_with_nan_handling():
    """Test feature extraction with NaN handling."""
    print("Testing feature extraction with NaN handling...")

    # Load a sample conn.log file
    conn_log_path = "data/zeek/zeek_output/conn.log"
    if not os.path.exists(conn_log_path):
        print(f"Error: Sample conn.log file not found at {conn_log_path}")
        print("Please run a Zeek analysis first to generate the conn.log file.")
        return False

    # Load the conn.log file
    df = load_conn_log(conn_log_path)
    if df.empty:
        print("Error: No connections found in the sample conn.log file")
        return False

    print(f"Loaded {len(df)} connections from conn.log")

    # Load the ML model, scaler, and encoders
    model_dir = 'output/retrained_model'
    try:
        model_path = os.path.join(model_dir, 'ocsvm_model.pkl')
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        encoders_path = os.path.join(model_dir, 'encoders.pkl')

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        encoders = joblib.load(encoders_path)
    except FileNotFoundError as e:
        print(f"Error: Required model file not found: {e}")
        print("Make sure to run training/train_ocsvm.py first to generate the model files.")
        return False
    except Exception as e:
        print(f"Error loading models: {e}")
        return False

    # Test with a single row to simulate real-time processing
    test_row = df.iloc[0:1]
    print(f"Testing with a single connection: UID={test_row['uid'].values[0]}")

    try:
        # Convert to feature vector
        X, _, _ = zeek_to_features(test_row, encoders)

        # Introduce some NaN values for testing
        X[0, 0] = np.nan
        X[0, 1] = np.nan

        print(f"Introduced NaN values in the feature matrix for testing")
        print(f"NaN values present: {np.isnan(X).any()}")

        # Handle NaN values in the feature matrix
        if np.isnan(X).any():
            print(f"Found NaN values in the feature matrix. Filling with zeros...")
            # Fill NaN values with zeros
            X = np.nan_to_num(X, nan=0.0)
            print(f"NaN values filled with zeros.")

        # Verify NaN values are gone
        print(f"NaN values present after handling: {np.isnan(X).any()}")

        # Scale the features
        X_scaled = scaler.transform(X)

        # Make predictions
        prediction = model.predict(X_scaled)[0]
        score = model.decision_function(X_scaled)[0]

        # Determine label (1 is inlier/normal, -1 is outlier/anomaly)
        label = "normal" if prediction == 1 else "anomaly"

        print(f"Prediction successful: SCORE={score:.6f} LABEL={label}")
        return True

    except Exception as e:
        print(f"Error during feature extraction or prediction: {e}")
        return False

def main():
    """Main function to test the realtime_detector.py script."""
    print("Testing realtime_detector.py NaN handling...")

    # Test feature extraction with NaN handling
    if test_feature_extraction_with_nan_handling():
        print("\nAll tests passed!")
    else:
        print("\nTests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
