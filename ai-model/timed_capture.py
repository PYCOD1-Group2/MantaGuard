#!/usr/bin/env python3
# timed_capture.py - Capture network packets and analyze them with Zeek and ML

import os
import sys
import time
import subprocess
import pyshark
import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime

# Add parent directory to path to import custom modules
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ai-model'))
from parsers.zeek_loader import load_conn_log, zeek_to_features

def run_capture(interface, duration, output_path):
    """
    Capture live packets on a given interface for a specified duration and save to a PCAP file.

    Args:
        interface (str): Network interface to capture packets on (e.g., 'eth0', 'Wi-Fi')
        duration (int): Duration in seconds to capture packets
        output_path (str): Path where the PCAP file will be saved

    Returns:
        str: Path to the saved PCAP file

    Raises:
        Exception: If packet capture fails
    """
    print(f"Starting packet capture on interface '{interface}' for {duration} seconds...")

    try:
        # Create directory for output file if it doesn't exist
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Use subprocess with tshark (part of Wireshark) which doesn't require root privileges
        # for many interfaces and has better timeout handling
        tshark_cmd = f"tshark -i {interface} -a duration:{duration} -w {output_path}"
        print(f"Running command: {tshark_cmd}")

        # Run tshark with timeout (add a small buffer to the duration)
        process = subprocess.run(tshark_cmd, shell=True, timeout=duration+5)

        if process.returncode != 0 and process.returncode != 124:  # 124 is timeout's exit code
            raise Exception(f"tshark exited with code {process.returncode}")

        print(f"Packet capture completed. PCAP file saved to: {output_path}")
        return output_path

    except subprocess.TimeoutExpired:
        print(f"Packet capture timed out after {duration+5} seconds. This is expected.")
        return output_path
    except Exception as e:
        print(f"Error during packet capture: {str(e)}")

        # If tshark fails, fall back to a simpler pyshark approach
        print("Falling back to pyshark for packet capture...")
        try:
            # Initialize the capture
            capture = pyshark.LiveCapture(interface=interface, output_file=output_path)

            # Use a simple approach with a single sniff call and a timeout
            print(f"Capturing packets for {duration} seconds...")
            capture.sniff(packet_count=1000, timeout=duration)

            # Close the capture
            capture.close()

            print(f"Packet capture completed. PCAP file saved to: {output_path}")
            return output_path
        except Exception as pyshark_error:
            print(f"Error during pyshark fallback: {str(pyshark_error)}")
            raise

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

def analyze_pcap_with_zeek(pcap_path, model_dir='ai-model/output/retrained_model', model_version='v2'):
    """
    Analyze a PCAP file with Zeek and pass the conn.log to the ML model for classification.

    Args:
        pcap_path (str): Path to the PCAP file to analyze
        model_dir (str, optional): Directory containing the ML model files.
                                  Defaults to 'ai-model/output/retrained_model'.
        model_version (str, optional): Version suffix for model files (e.g., 'v2' for 
                                      ocsvm_model_v2.pkl). If None, will try to detect
                                      the available model files.

    Returns:
        list: List of dictionaries containing predictions with fields:
              uid, timestamp, score, prediction

    Raises:
        FileNotFoundError: If the PCAP file doesn't exist
        Exception: If Zeek analysis fails
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    print(f"Analyzing PCAP file with Zeek: {pcap_path}")

    # Create a temporary directory for Zeek output
    temp_dir = os.path.join(os.path.dirname(pcap_path), "zeek_output")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    conn_log_path = os.path.join(temp_dir, "conn.log")

    try:
        # Run Zeek on the PCAP file
        print("Running Zeek analysis...")

        # Convert to absolute paths to avoid directory issues
        abs_pcap_path = os.path.abspath(pcap_path)

        # Use the most minimal command possible with absolute paths
        zeek_cmd = f"zeek -r {abs_pcap_path}"
        print(f"Running command: {zeek_cmd}")

        # Change to the output directory before running Zeek
        current_dir = os.getcwd()
        os.chdir(temp_dir)

        try:
            subprocess.run(zeek_cmd, shell=True, check=True)
        finally:
            # Change back to the original directory
            os.chdir(current_dir)

        # Check if conn.log was created
        if not os.path.exists(conn_log_path):
            raise FileNotFoundError(f"Zeek did not generate conn.log at {conn_log_path}")

        print(f"Zeek analysis completed. Loading conn.log from {conn_log_path}")

        # Load the conn.log file
        df = load_conn_log(conn_log_path)

        if df.empty:
            print("Warning: No connections found in the PCAP file")
            return []

        print(f"Loaded {len(df)} connections from conn.log")

        # Load the ML model, scaler, and encoders
        # Determine file names based on model_version
        if model_version is None or not os.path.exists(os.path.join(model_dir, f'ocsvm_model_{model_version}.pkl')):
            # Try to detect available model files
            base_model_path = os.path.join(model_dir, 'ocsvm_model.pkl')
            v2_model_path = os.path.join(model_dir, 'ocsvm_model_v2.pkl')

            # If model_version was provided but file doesn't exist, print a warning
            if model_version is not None:
                print(f"Warning: Model file with version '{model_version}' not found. Attempting to auto-detect available models.")

            if os.path.exists(v2_model_path):
                model_version = 'v2'
                print(f"Detected model version: v2")
            elif os.path.exists(base_model_path):
                model_version = ''
                print(f"Detected model version: base")
            else:
                raise FileNotFoundError(f"No model files found in directory: {model_dir}. Please ensure the model directory exists and contains model files (ocsvm_model.pkl or ocsvm_model_v2.pkl). You may need to train a model first or specify a different model directory.")

        # Construct file paths based on model_version
        version_suffix = f"_{model_version}" if model_version else ""
        model_path = os.path.join(model_dir, f'ocsvm_model{version_suffix}.pkl')
        scaler_path = os.path.join(model_dir, f'scaler{version_suffix}.pkl')
        encoders_path = os.path.join(model_dir, f'encoders{version_suffix}.pkl')

        print(f"Using AI model from directory: {model_dir}, version: {model_version if model_version else 'base'}")

        # Check if model files exist
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}. Please ensure you have trained a model and it exists at this location.")
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler file not found: {scaler_path}. This file should be created during model training.")
        if not os.path.exists(encoders_path):
            raise FileNotFoundError(f"Encoders file not found: {encoders_path}. This file should be created during model training.")

        try:
            model = joblib.load(model_path)
            scaler = joblib.load(scaler_path)
            encoders = joblib.load(encoders_path)
        except Exception as e:
            raise Exception(f"Error loading model files from {model_dir}: {str(e)}. The model files may be corrupted or incompatible with the current version of the software.")

        # Convert to feature vectors
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
        print(f"Checking for NaN values in the feature matrix...")
        if np.isnan(X).any():
            print(f"Found NaN values in the feature matrix. Filling with zeros...")
            # Fill NaN values with zeros
            X = np.nan_to_num(X, nan=0.0)
            print(f"NaN values filled with zeros.")

        # Scale the features
        X_scaled = scaler.transform(X)

        # Make predictions
        predictions = model.predict(X_scaled)
        scores = model.decision_function(X_scaled)

        # Create results list
        results = []
        for i in range(len(df)):
            # Get the timestamp and UID
            timestamp = df.iloc[i]['ts'].isoformat() if 'ts' in df.columns else datetime.now().isoformat()
            uid = df.iloc[i]['uid'] if 'uid' in df.columns else f"unknown-{i}"

            # Determine label (1 is inlier/normal, -1 is outlier/anomaly)
            label = "normal" if predictions[i] == 1 else "anomaly"

            # Add to results
            results.append({
                'uid': uid,
                'timestamp': timestamp,
                'score': float(scores[i]),
                'prediction': label
            })

        print(f"Analysis complete. Found {sum(1 for r in results if r['prediction'] == 'anomaly')} anomalies "
              f"out of {len(results)} connections.")

        return results

    except subprocess.CalledProcessError as e:
        print(f"Error running Zeek: {str(e)}")
        raise
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        raise
    finally:
        # You might want to clean up the temporary directory here
        # Commented out to keep logs for debugging
        # import shutil
        # shutil.rmtree(temp_dir)
        pass

if __name__ == "__main__":
    # Example usage
    if len(sys.argv) < 4 or sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("Usage: python timed_capture.py <interface> <duration> <output_path> [<model_dir> [<model_version>]]")
        print("  <interface>     : Network interface to capture packets on (e.g., 'eth0', 'Wi-Fi')")
        print("  <duration>      : Duration in seconds to capture packets")
        print("  <output_path>   : Path where the PCAP file will be saved")
        print("  <model_dir>     : (Optional) Directory containing the AI model files")
        print("                    Default: 'ai-model/output/retrained_model'")
        print("  <model_version> : (Optional) Version suffix for model files (e.g., 'v2' for ocsvm_model_v2.pkl)")
        print("                    Default: Auto-detect based on available files")
        print("")
        print("Options:")
        print("  -h, --help      : Show this help message and exit")
        print("")
        print("Examples:")
        print("  python timed_capture.py eth0 60 capture.pcap")
        print("  python timed_capture.py eth0 60 capture.pcap ai-model/output/retrained_model")
        print("  python timed_capture.py eth0 60 capture.pcap ai-model/output/retrained_model v2")
        sys.exit(1)

    interface = sys.argv[1]
    duration = int(sys.argv[2])
    output_path = sys.argv[3]

    # Use the specified model directory if provided, otherwise use the default
    model_dir = sys.argv[4] if len(sys.argv) > 4 else 'ai-model/output/retrained_model'

    # If model_dir doesn't start with 'ai-model/' and doesn't start with '/', add 'ai-model/' prefix
    if model_dir and not model_dir.startswith('ai-model/') and not model_dir.startswith('/'):
        model_dir = os.path.join('ai-model', model_dir)

    # Use the specified model version if provided, otherwise auto-detect
    model_version = sys.argv[5] if len(sys.argv) > 5 else 'v2'

    try:
        # Capture packets
        pcap_file = run_capture(interface, duration, output_path)

        # Analyze the PCAP file
        results = analyze_pcap_with_zeek(pcap_file, model_dir, model_version)

        # Print results
        print("\nAnalysis Results:")
        for result in results:
            print(f"UID: {result['uid']}, Score: {result['score']:.6f}, Prediction: {result['prediction']}")

        # Save results to CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join('ai-model', 'output', 'analysis_results', timestamp)
        os.makedirs(output_dir, exist_ok=True)

        csv_path = os.path.join(output_dir, 'prediction_results.csv')
        df = pd.DataFrame(results)
        df.to_csv(csv_path, index=False)
        print(f"\nResults saved to CSV: {csv_path}")

        # Generate visualizations
        try:
            import subprocess
            vis_cmd = f"python ai-model/visualize_results.py {csv_path} {output_dir}"
            print(f"\nGenerating visualizations with command: {vis_cmd}")
            subprocess.run(vis_cmd, shell=True, check=True)
            print(f"Visualizations saved to: {output_dir}")
        except Exception as vis_error:
            print(f"Warning: Failed to generate visualizations: {str(vis_error)}")

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
