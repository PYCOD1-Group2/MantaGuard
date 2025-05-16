#!/usr/bin/env python3
# run_retrain_ocsvm.py - Executable script with hard-coded parameters for retrain_ocsvm.py

import os
import subprocess
import sys

def main():
    """Run retrain_ocsvm.py with hard-coded parameters."""

    # Get the directory of the current script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Path to retrain_ocsvm.py
    retrain_script = os.path.join(script_dir, "training", "retrain_ocsvm.py")

    # Hard-coded parameters
    params = [
        sys.executable,  # Use the current Python interpreter
        retrain_script,
        "--base-normal", "data/zeek/conn.log",
        "--labeled-anomalies", "output/ocsvm_model/labeled_anomalies.csv",
        "--unknown-categories", "training/unknown_categories.json",
        "--encoders", "output/ocsvm_model/encoders.pkl",
        "--scaler", "output/ocsvm_model/scaler.pkl",
        "--output-dir", "output/retrained_model"
    ]

    # Print the command being executed
    print("Executing command:")
    print(" ".join(params))
    print("\n")

    # Run the command
    try:
        result = subprocess.run(params, check=True)
        print(f"\nCommand completed successfully with exit code {result.returncode}")
    except subprocess.CalledProcessError as e:
        print(f"\nCommand failed with exit code {e.returncode}")
        sys.exit(e.returncode)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
