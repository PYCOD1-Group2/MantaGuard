#!/usr/bin/env python3
# realtime_detector.py - Monitor a live Zeek conn.log and classify each new line as normal or anomaly

import os
import sys
import time
import argparse
import joblib
import pandas as pd
import numpy as np
import csv
import sqlite3
import json
from datetime import datetime

# Add parent directory to path to import custom modules if needed
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ai-model'))
from parsers.zeek_loader import load_conn_log, zeek_to_features

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Monitor a live Zeek conn.log and classify each new line as normal or anomaly.'
    )
    parser.add_argument('--log', default='ai-model/current/conn.log', 
                        help='Path to live Zeek conn.log file (default: ai-model/current/conn.log)')
    parser.add_argument('--csv', default='ai-model/labeled_anomalies.csv',
                        help='Path to CSV file for storing labeled anomalies (default: ai-model/labeled_anomalies.csv)')
    parser.add_argument('--sqlite', default='ai-model/labeled_anomalies.db',
                        help='Path to SQLite database for storing labeled anomalies (default: ai-model/labeled_anomalies.db)')
    parser.add_argument('--no-csv', action='store_true',
                        help='Disable CSV storage of labeled anomalies')
    parser.add_argument('--no-sqlite', action='store_true',
                        help='Disable SQLite storage of labeled anomalies')
    return parser.parse_args()

def load_models():
    """Load the trained model, scaler, and encoders."""
    model_dir = 'ai-model/output/ocsvm_model'
    try:
        model_path = os.path.join(model_dir, 'ocsvm_model.pkl')
        scaler_path = os.path.join(model_dir, 'scaler.pkl')
        encoders_path = os.path.join(model_dir, 'encoders.pkl')

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        encoders = joblib.load(encoders_path)
        return model, scaler, encoders
    except FileNotFoundError as e:
        print(f"Error: Required model file not found: {e}")
        print("Make sure to run ai-model/training/train_ocsvm.py first to generate the model files.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading models: {e}")
        sys.exit(1)

def parse_zeek_line(line, field_names):
    """Parse a single line from a Zeek conn.log file into a dictionary."""
    values = line.strip().split('\t')
    if len(values) != len(field_names):
        return None

    # Create a dictionary of field names and values
    row_dict = dict(zip(field_names, values))

    # Convert ts to float for later datetime conversion
    if 'ts' in row_dict:
        try:
            row_dict['ts'] = float(row_dict['ts'])
        except ValueError:
            return None

    return row_dict

def extract_field_names(log_path):
    """Extract field names from the Zeek conn.log header."""
    try:
        with open(log_path, 'r') as f:
            for line in f:
                if line.startswith('#fields'):
                    return line.strip().split('\t')[1:]
    except Exception as e:
        print(f"Error reading log file header: {e}")
        return None

def initialize_storage(args):
    """Initialize storage for labeled anomalies."""
    # Initialize in-memory dataset
    labeled_anomalies = []

    # Initialize SQLite database if enabled
    conn = None
    if not args.no_sqlite:
        try:
            conn = sqlite3.connect(args.sqlite)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS labeled_anomalies (
                    timestamp TEXT,
                    uid TEXT,
                    score REAL,
                    original_label TEXT,
                    user_label TEXT,
                    feature_vector TEXT
                )
            ''')
            conn.commit()
            print(f"SQLite storage initialized: {args.sqlite}")
        except Exception as e:
            print(f"Error initializing SQLite database: {e}")
            conn = None

    # Initialize CSV file if enabled
    if not args.no_csv:
        try:
            # Check if file exists to determine if we need to write headers
            file_exists = os.path.isfile(args.csv)

            with open(args.csv, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['timestamp', 'uid', 'score', 'original_label', 'user_label', 'feature_vector'])
            print(f"CSV storage initialized: {args.csv}")
        except Exception as e:
            print(f"Error initializing CSV file: {e}")

    return labeled_anomalies, conn

def get_user_feedback(timestamp, uid, score, X_scaled):
    """
    Get user feedback when an anomaly is detected.

    Args:
        timestamp (str): UTC timestamp
        uid (str): Connection UID
        score (float): Anomaly score
        X_scaled (numpy.ndarray): Scaled feature vector

    Returns:
        str: User-provided label or None if user pressed Enter (keep as anomaly)
    """
    print(f"\n[{timestamp}] ANOMALY DETECTED: UID={uid} SCORE={score:.6f}")
    print("Enter a label for this anomaly or press ENTER to keep it as 'anomaly':")
    user_input = input("> ").strip()

    if user_input:
        return user_input
    return None

def store_labeled_anomaly(labeled_anomalies, conn, args, timestamp, uid, score, user_label, X_scaled):
    """
    Store a labeled anomaly in memory and optionally in CSV/SQLite.

    Args:
        labeled_anomalies (list): In-memory dataset of labeled anomalies
        conn (sqlite3.Connection): SQLite database connection
        args (argparse.Namespace): Command-line arguments
        timestamp (str): UTC timestamp
        uid (str): Connection UID
        score (float): Anomaly score
        user_label (str): User-provided label or "anomaly" if none provided
        X_scaled (numpy.ndarray): Scaled feature vector
    """
    # Convert feature vector to string for storage
    feature_vector_str = np.array2string(X_scaled[0], precision=6, separator=',')

    # Store in memory
    labeled_anomalies.append({
        'timestamp': timestamp,
        'uid': uid,
        'score': score,
        'original_label': 'anomaly',
        'user_label': user_label if user_label else 'anomaly',
        'feature_vector': feature_vector_str
    })

    # Store in CSV if enabled
    if not args.no_csv:
        try:
            with open(args.csv, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    uid,
                    score,
                    'anomaly',
                    user_label if user_label else 'anomaly',
                    feature_vector_str
                ])
        except Exception as e:
            print(f"Error writing to CSV file: {e}")

    # Store in SQLite if enabled
    if conn is not None:
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO labeled_anomalies 
                (timestamp, uid, score, original_label, user_label, feature_vector)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                uid,
                score,
                'anomaly',
                user_label if user_label else 'anomaly',
                feature_vector_str
            ))
            conn.commit()
        except Exception as e:
            print(f"Error writing to SQLite database: {e}")

    print(f"Labeled anomaly stored: UID={uid}, Label={'user-defined: ' + user_label if user_label else 'anomaly'}")

def update_unknown_categories(unknown_values, filename="ai-model/training/unknown_categories.json"):
    """
    Update the unknown categories file with new unknown values.

    Args:
        unknown_values (dict): Dictionary of unknown categorical values
        filename (str, optional): Path to the unknown categories file.
                                 Defaults to "ai-model/training/unknown_categories.json".

    Returns:
        dict: Merged unknown values
    """
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

    # Create directory if it doesn't exist
    directory = os.path.dirname(filename)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory)
            print(f"Created directory: {directory}")
        except Exception as e:
            print(f"Warning: Could not create directory {directory}: {e}")

    # Write merged unknown values to file
    try:
        with open(filename, 'w') as f:
            json.dump(merged_unknown_values, f, indent=2)
        print(f"Unknown categorical values written to {filename}")
    except Exception as e:
        print(f"Warning: Could not write unknown categories to file: {e}")

    return merged_unknown_values

def tail_file(file_path, field_names, model, scaler, encoders, labeled_anomalies, conn, args):
    """
    Non-blocking tail implementation to monitor a file for new lines.
    Processes each new line and classifies it as normal or anomaly.

    When an anomaly is detected, pauses and asks for user feedback.
    """
    try:
        # Open the file and seek to the end
        with open(file_path, 'r') as f:
            f.seek(0, os.SEEK_END)

            while True:
                # Get current position
                curr_position = f.tell()

                # Read new lines
                line = f.readline()

                if line:
                    # Skip comment lines
                    if line.startswith('#'):
                        continue

                    # Parse the line
                    row_dict = parse_zeek_line(line, field_names)
                    if row_dict is None:
                        continue

                    # Create a DataFrame with a single row
                    df = pd.DataFrame([row_dict])

                    # Convert ts to datetime
                    if 'ts' in df.columns:
                        df['ts'] = pd.to_datetime(df['ts'], unit='s', utc=True)

                    # Get the UID for reporting
                    uid = row_dict.get('uid', 'unknown')

                    # Process the row if it has the required columns
                    try:
                        # Convert to feature vector
                        X, _, unknown_values = zeek_to_features(df, encoders)

                        # Check if any unknown values were found
                        has_unknown_values = any(len(values) > 0 for values in unknown_values.values())
                        if has_unknown_values:
                            print("Unknown categorical values were found and encoded as -1.")

                            # Update unknown categories file
                            merged_unknown_values = update_unknown_categories(unknown_values)

                            # Print unknown values
                            print("Unknown categorical values found:")
                            for col, values in merged_unknown_values.items():
                                if values:
                                    print(f"  {col}: {values}")

                        # Handle NaN values in the feature matrix
                        if np.isnan(X).any():
                            print(f"Found NaN values in the feature matrix. Filling with zeros...")
                            # Fill NaN values with zeros
                            X = np.nan_to_num(X, nan=0.0)

                        # Scale the features
                        X_scaled = scaler.transform(X)

                        # Predict and get decision score
                        prediction = model.predict(X_scaled)[0]
                        score = model.decision_function(X_scaled)[0]

                        # Determine label (1 is inlier/normal, -1 is outlier/anomaly)
                        label = "normal" if prediction == 1 else "anomaly"

                        # Print result in the required format
                        timestamp = datetime.utcnow().isoformat() + 'Z'
                        print(f"[{timestamp}] UID={uid} SCORE={score:.6f} LABEL={label}")

                        # If anomaly is detected, get user feedback
                        if label == "anomaly":
                            user_label = get_user_feedback(timestamp, uid, score, X_scaled)

                            # Store the labeled anomaly
                            store_labeled_anomaly(
                                labeled_anomalies, conn, args, 
                                timestamp, uid, score, user_label, X_scaled
                            )

                    except Exception as e:
                        print(f"Error processing line: {e}")
                        continue
                else:
                    # Check if file has been rotated
                    try:
                        # If file size is smaller than our position, it was likely rotated
                        if os.path.getsize(file_path) < curr_position:
                            print(f"[{datetime.utcnow().isoformat()}Z] Log rotation detected, reopening file")
                            return  # Exit function to reopen the file

                        # No new lines, sleep briefly
                        time.sleep(0.1)
                    except FileNotFoundError:
                        print(f"[{datetime.utcnow().isoformat()}Z] Log file not found, waiting for it to appear")
                        time.sleep(1)
                        return  # Exit function to reopen the file

    except Exception as e:
        print(f"Error tailing file: {e}")
        time.sleep(1)  # Wait before retrying

def monitor_log_file(log_path, model, scaler, encoders, labeled_anomalies, conn, args):
    """
    Monitor the log file, handling file rotation and reopening.
    """
    print(f"Starting to monitor {log_path} for new connections...")
    print(f"Press Ctrl+C to stop")
    print(f"When an anomaly is detected, you will be prompted for feedback.")

    if not args.no_csv:
        print(f"Labeled anomalies will be stored in: {args.csv}")
    if conn is not None:
        print(f"Labeled anomalies will be stored in SQLite database: {args.sqlite}")

    while True:
        try:
            # Check if file exists
            if not os.path.exists(log_path):
                print(f"[{datetime.utcnow().isoformat()}Z] Waiting for log file to appear: {log_path}")
                time.sleep(1)
                continue

            # Extract field names from the header
            field_names = extract_field_names(log_path)
            if field_names is None:
                print(f"[{datetime.utcnow().isoformat()}Z] Could not extract field names from log file")
                time.sleep(1)
                continue

            # Start tailing the file
            tail_file(log_path, field_names, model, scaler, encoders, labeled_anomalies, conn, args)

        except KeyboardInterrupt:
            print("\nStopping monitoring")
            if conn is not None:
                conn.close()
                print("SQLite database connection closed")
            print(f"Total labeled anomalies collected: {len(labeled_anomalies)}")
            break
        except Exception as e:
            print(f"Error in monitor loop: {e}")
            time.sleep(1)

def main():
    """Main function to monitor a live Zeek conn.log and classify each new line."""
    # Parse command line arguments
    args = parse_args()

    # Load the trained model, scaler, and encoders
    model, scaler, encoders = load_models()

    # Initialize storage for labeled anomalies
    labeled_anomalies, conn = initialize_storage(args)

    # Start monitoring the log file
    monitor_log_file(args.log, model, scaler, encoders, labeled_anomalies, conn, args)

if __name__ == "__main__":
    main()
