#!/usr/bin/env python3
# retrain_ocsvm.py - Retrain OneClassSVM model with normal data and optionally labeled feedback and new categories

import os
import sys
import argparse
import joblib
import json
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# Add parent directory to path to import custom modules if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsers.zeek_loader import load_conn_log, zeek_to_features

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Retrain OneClassSVM model with normal data and optionally labeled feedback and new categories.'
    )
    parser.add_argument('--base-normal', help='Path to Zeek conn.log file containing original normal traffic')
    parser.add_argument('--labeled-anomalies', required=False, help='Path to CSV file with labeled anomalies (optional)')
    parser.add_argument('--unknown-categories', required=True, help='Path to JSON file with unknown categories')
    parser.add_argument('--encoders', required=True, help='Path to original encoders.pkl file')
    parser.add_argument('--scaler', required=True, help='Path to original scaler.pkl file')
    parser.add_argument('--output-dir', default='.', help='Directory to save updated model and files')
    return parser.parse_args()

def load_labeled_anomalies(path):
    """
    Load labeled anomalies from CSV file.

    Args:
        path (str): Path to the CSV file with labeled anomalies

    Returns:
        pandas.DataFrame: DataFrame containing the labeled anomalies
    """
    df = pd.read_csv(path)

    # Convert ts column to datetime if it exists
    if 'ts' in df.columns:
        df['ts'] = pd.to_datetime(df['ts'])

    # Convert timestamp column to datetime if it exists
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Parse feature_vector column if it exists
    if 'feature_vector' in df.columns:
        # Convert string representation of list to actual numpy array
        df['feature_vector'] = df['feature_vector'].apply(
            lambda x: np.array(eval(x)) if isinstance(x, str) else x
        )

    return df

def expand_encoders(encoders, unknown_categories):
    """
    Expand encoders with new unknown categories.

    Args:
        encoders (dict): Original encoders dictionary
        unknown_categories (dict): Dictionary of unknown categories to add

    Returns:
        dict: Updated encoders dictionary
        int: Number of categories added
    """
    categories_added = 0

    # For each categorical column
    for col, values in unknown_categories.items():
        if col in encoders:
            # Get the current mapping
            mapping = encoders[col]

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

    return encoders, categories_added

def main():
    """Main function to retrain and save the OneClassSVM model."""
    # Parse command line arguments
    args = parse_args()

    # Check if required files exist
    required_files = [args.unknown_categories, args.encoders, args.scaler]
    if args.labeled_anomalies:
        required_files.append(args.labeled_anomalies)

    for file_path in required_files:
        if not os.path.isfile(file_path):
            print(f"Error: File not found: {file_path}")
            sys.exit(1)

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    try:
        # Load original encoders and scaler
        print(f"Loading original encoders from: {args.encoders}")
        encoders = joblib.load(args.encoders)

        print(f"Loading original scaler from: {args.scaler}")
        scaler = joblib.load(args.scaler)

        # Load unknown categories
        print(f"Loading unknown categories from: {args.unknown_categories}")
        with open(args.unknown_categories, 'r') as f:
            unknown_categories = json.load(f)

        # Expand encoders with new categories
        print("Expanding encoders with new categories...")
        updated_encoders, categories_added = expand_encoders(encoders, unknown_categories)
        print(f"Added {categories_added} new categories to encoders")

        # Save updated encoders
        encoders_v2_path = os.path.join(args.output_dir, 'encoders_v2.pkl')
        joblib.dump(updated_encoders, encoders_v2_path)
        print(f"Saved updated encoders to: {encoders_v2_path}")

        # Initialize variables for labeled anomalies
        X_labeled = None
        unknown_values = {}
        rows_from_labeled = 0

        # Load labeled anomalies if provided
        if args.labeled_anomalies:
            print(f"Loading labeled anomalies from: {args.labeled_anomalies}")
            labeled_df = load_labeled_anomalies(args.labeled_anomalies)
            print(f"Loaded labeled anomalies with shape: {labeled_df.shape}")

            # Apply updated encoders to labeled anomalies
            print("Processing labeled anomalies with updated encoders...")

            # Check if feature_vector column exists and use it directly
            if 'feature_vector' in labeled_df.columns:
                print("Using pre-computed feature vectors from labeled anomalies")
                # Convert list of numpy arrays to a 2D numpy array
                X_labeled = np.vstack(labeled_df['feature_vector'].values)
                unknown_values = {}  # No unknown values when using pre-computed features

                # Load and process a sample of normal data to get feature dimensions
                if args.base_normal and os.path.isfile(args.base_normal):
                    print(f"Loading sample of normal data to determine feature dimensions...")
                    # Load just a small sample to determine feature dimensions
                    normal_sample_df = load_conn_log(args.base_normal).head(1)
                    X_normal_sample, _, _ = zeek_to_features(normal_sample_df, updated_encoders)
                    normal_feature_dim = X_normal_sample.shape[1]
                    labeled_feature_dim = X_labeled.shape[1]

                    print(f"Normal data feature dimension: {normal_feature_dim}")
                    print(f"Labeled anomalies feature dimension: {labeled_feature_dim}")

                    # If dimensions don't match, pad the labeled anomalies with zeros
                    if normal_feature_dim != labeled_feature_dim:
                        print(f"Padding labeled anomalies features to match normal data dimension")
                        if normal_feature_dim > labeled_feature_dim:
                            # Pad with zeros
                            padding = np.zeros((X_labeled.shape[0], normal_feature_dim - labeled_feature_dim))
                            X_labeled = np.hstack((X_labeled, padding))
                        else:
                            # Truncate to match normal data dimension
                            X_labeled = X_labeled[:, :normal_feature_dim]

                        print(f"Adjusted labeled anomalies feature dimension: {X_labeled.shape[1]}")
            else:
                # Fall back to zeek_to_features if feature_vector column doesn't exist
                X_labeled, _, unknown_values = zeek_to_features(labeled_df, updated_encoders)

            # Check if there are still unknown values
            has_unknown = False
            for col, values in unknown_values.items():
                if values:
                    has_unknown = True
                    print(f"Warning: New unknown values found in column '{col}': {values}")

            rows_from_labeled = X_labeled.shape[0]

        # Initialize variables for combined dataset
        X_combined = None
        rows_from_normal = 0

        # Load and process original normal data if provided
        if args.base_normal and os.path.isfile(args.base_normal):
            print(f"Loading original normal data from: {args.base_normal}")
            normal_df = load_conn_log(args.base_normal)
            print(f"Loaded normal data with shape: {normal_df.shape}")

            # Process normal data with updated encoders
            print("Processing normal data with updated encoders...")
            X_normal, _, _ = zeek_to_features(normal_df, updated_encoders)
            rows_from_normal = X_normal.shape[0]

            # Combine with labeled data if available
            if X_labeled is not None:
                print("Combining normal data with labeled anomalies...")
                X_combined = np.vstack((X_normal, X_labeled))
            else:
                print("Using only normal data for training (no labeled anomalies provided)...")
                X_combined = X_normal
        elif X_labeled is not None:
            # Use only labeled data if no normal data is provided
            print("Using only labeled anomalies for training (no normal data provided)...")
            X_combined = X_labeled
        else:
            print("Error: Either --base-normal or --labeled-anomalies must be provided")
            sys.exit(1)

        # Check for and handle NaN values in the combined dataset
        print("Checking for NaN values in the combined dataset...")
        nan_count = np.isnan(X_combined).sum()
        if nan_count > 0:
            print(f"Found {nan_count} NaN values in the combined dataset. Replacing with zeros.")
            # Replace NaN values with zeros
            X_combined = np.nan_to_num(X_combined, nan=0.0)

        # Fit a new scaler on the combined data
        print("Fitting new scaler on combined dataset...")
        scaler_v2 = StandardScaler()
        X_combined_scaled = scaler_v2.fit_transform(X_combined)

        # Check for NaN values after scaling
        nan_count_after_scaling = np.isnan(X_combined_scaled).sum()
        if nan_count_after_scaling > 0:
            print(f"Found {nan_count_after_scaling} NaN values after scaling. Replacing with zeros.")
            # Replace NaN values with zeros
            X_combined_scaled = np.nan_to_num(X_combined_scaled, nan=0.0)

        # Train new OneClassSVM model
        print("Training new OneClassSVM model...")
        model_v2 = OneClassSVM(kernel='rbf', nu=0.01, gamma='scale')
        model_v2.fit(X_combined_scaled)
        print("Model training completed")

        # Save new model and scaler
        model_v2_path = os.path.join(args.output_dir, 'ocsvm_model_v2.pkl')
        scaler_v2_path = os.path.join(args.output_dir, 'scaler_v2.pkl')

        joblib.dump(model_v2, model_v2_path)
        joblib.dump(scaler_v2, scaler_v2_path)

        print("Files saved successfully:")
        print(f"  - {encoders_v2_path}")
        print(f"  - {model_v2_path}")
        print(f"  - {scaler_v2_path}")

        # Print summary
        print("\nRetraining Summary:")
        print(f"Rows from normal data: {rows_from_normal}")
        print(f"Rows from labeled anomalies: {rows_from_labeled}")
        print(f"Total rows in combined dataset: {X_combined.shape[0]}")
        print(f"Encoder categories added: {categories_added}")
        print(f"Model training shape: {X_combined_scaled.shape}")

    except Exception as e:
        print(f"Error during retraining: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
