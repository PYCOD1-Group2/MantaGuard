#!/usr/bin/env python3
# test_offline_pipeline.py - Test script for the full pipeline on Arch Linux

import os
import sys
import argparse
import joblib
import json
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from parsers.zeek_loader import load_conn_log, zeek_to_features

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Validate the full pipeline using a Zeek-generated conn.log.'
    )
    parser.add_argument('--log-path', required=True, help='Path to Zeek conn.log file')
    return parser.parse_args()

def main():
    """Main function to test the full pipeline."""
    # Parse command line arguments
    args = parse_args()

    # Check if the log file exists
    if not os.path.isfile(args.log_path):
        print(f"Error: Log file not found: {args.log_path}")
        sys.exit(1)

    try:
        # Step 1: Load conn.log using zeek_loader.load_conn_log()
        print(f"Loading Zeek conn.log from: {args.log_path}")
        df = load_conn_log(args.log_path)
        print(f"Loaded DataFrame with shape: {df.shape}")

        # Step 2: Load the trained OneClassSVM model, scaler, and encoders using joblib
        print("Loading model, scaler, and encoders...")
        model_dir = 'output/retrained_model'
        model_path = os.path.join(model_dir, 'ocsvm_model.pkl')
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        encoders_path = os.path.join(model_dir, 'encoders.pkl')

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        encoders = joblib.load(encoders_path)
        print("Model, scaler, and encoders loaded successfully")

        # Step 3: Convert the DataFrame into a feature matrix using zeek_to_features() with pre-trained encoders
        print("Converting DataFrame to feature matrix using pre-trained encoders...")
        X, _, unknown_values = zeek_to_features(df, pre_trained_encoders=encoders)
        print(f"Created feature matrix with shape: {X.shape}")

        # Check if any unknown values were found
        has_unknown_values = any(len(values) > 0 for values in unknown_values.values())
        if has_unknown_values:
            print("Unknown categorical values were found and encoded as -1.")

            # Function to merge unknown values with existing file
            def update_unknown_categories(unknown_values, filename="unknown_categories.json"):
                # Initialize with current unknown values
                merged_unknown_values = unknown_values

                # If file exists, load and merge with current unknown values
                if os.path.exists(filename):
                    try:
                        with open(filename, 'r') as f:
                            existing_unknown_values = json.load(f)

                        # Merge with current unknown values
                        for col, values in existing_unknown_values.items():
                            if col in merged_unknown_values:
                                # Combine lists and remove duplicates
                                merged_unknown_values[col] = list(set(merged_unknown_values[col] + values))
                            else:
                                merged_unknown_values[col] = values
                    except Exception as e:
                        print(f"Warning: Could not read existing unknown categories file: {e}")

                # Write merged unknown values to file
                try:
                    with open(filename, 'w') as f:
                        json.dump(merged_unknown_values, f, indent=2)
                    print(f"Unknown categorical values written to {filename}")
                except Exception as e:
                    print(f"Warning: Could not write unknown categories to file: {e}")

                return merged_unknown_values

            # Update unknown categories file
            merged_unknown_values = update_unknown_categories(unknown_values)

            # Print unknown values
            print("Unknown categorical values found:")
            for col, values in merged_unknown_values.items():
                if values:
                    print(f"  {col}: {values}")

        # Step 4: Scale the feature matrix
        print("Scaling feature matrix...")
        X_scaled = scaler.transform(X)

        # Check for NaN values and handle them
        if np.isnan(X_scaled).any():
            print("Warning: NaN values detected in scaled features. Imputing with mean strategy...")
            imputer = SimpleImputer(strategy='mean')
            X_scaled = imputer.fit_transform(X_scaled)
            print("Imputation completed.")

        # Step 5: Run predictions
        print("Running predictions...")
        # Get decision function scores (distance from the hyperplane)
        scores = model.decision_function(X_scaled)
        # Get predictions (-1 for anomaly, 1 for normal)
        predictions = model.predict(X_scaled)

        # Step 6: Print results for each prediction
        print("\nPrediction Results:")
        print("UID, Timestamp, Score, Prediction (-1=anomaly, 1=normal)")
        print("-" * 70)

        for i in range(len(df)):
            uid = df.iloc[i]['uid'] if 'uid' in df.columns else 'N/A'
            timestamp = df.iloc[i]['ts'] if 'ts' in df.columns else 'N/A'
            score = scores[i]
            prediction = predictions[i]
            print(f"{uid}, {timestamp}, {score:.6f}, {prediction}")

        # Step 7: Print counts of normal vs anomaly predictions
        normal_count = np.sum(predictions == 1)
        anomaly_count = np.sum(predictions == -1)
        total_count = len(predictions)

        print("\nSummary:")
        print(f"Total connections: {total_count}")
        print(f"Normal connections: {normal_count} ({normal_count/total_count*100:.2f}%)")
        print(f"Anomaly connections: {anomaly_count} ({anomaly_count/total_count*100:.2f}%)")

    except Exception as e:
        print(f"Error during pipeline execution: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
