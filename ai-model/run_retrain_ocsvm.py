#!/usr/bin/env python3
# run_retrain_ocsvm.py - Executable script with hard-coded parameters for retrain_ocsvm.py (using only normal data)

import os
import subprocess
import sys

def main():
    """Run retrain_ocsvm.py with hard-coded parameters.

    This script retrains the OCSVM model using only normal data without requiring labeled anomalies.
    It's useful when you have traffic data but don't yet have any attack data or labeled anomalies.
    """

    # Get the directory of the current script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Path to retrain_ocsvm.py
    retrain_script = os.path.join(script_dir, "training", "retrain_ocsvm.py")

    # Hard-coded parameters
    params = [
        sys.executable,  # Use the current Python interpreter
        retrain_script,
        "--base-normal", "ai-model/pcaps/zeek_output/conn.log",
        # "--labeled-anomalies" parameter is now optional and removed for training with only normal data
        "--unknown-categories", os.path.join(script_dir, "training", "unknown_categories.json"),
        "--encoders", os.path.join(script_dir, "output", "retrained_model", "encoders_v2.pkl"),
        "--scaler", os.path.join(script_dir, "output", "retrained_model", "scaler_v2.pkl"),
        "--output-dir", os.path.join(script_dir, "output", "retrained_model")
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
