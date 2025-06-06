#!/usr/bin/env python3
# analyze_capture.py - Analyze an existing PCAP file with Zeek and ML

import os
import sys
import pandas as pd
from datetime import datetime

# Add current directory to path to import custom modules
current_script_dir = os.path.dirname(os.path.abspath(__file__))
if current_script_dir not in sys.path:
    sys.path.insert(0, current_script_dir)

# Try importing with error handling
try:
    from timed_capture import analyze_pcap_with_zeek
except ImportError as e:
    print(f"Import error: {e}")
    # Try alternative import path
    import importlib.util
    timed_capture_path = os.path.join(current_script_dir, 'timed_capture.py')
    spec = importlib.util.spec_from_file_location("timed_capture", timed_capture_path)
    timed_capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(timed_capture)
    analyze_pcap_with_zeek = timed_capture.analyze_pcap_with_zeek

def main():
    # Parse command-line arguments
    if len(sys.argv) < 2 or sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("Usage: python analyze_capture.py <pcap_path> [<model_dir> [<model_version>]]")
        print("  <pcap_path>     : Path to the existing PCAP file to analyze")
        print("  <model_dir>     : (Optional) Directory containing the AI model files")
        print("                    Default: 'ai-model/output/retrained_model'")
        print("  <model_version> : (Optional) Version suffix for model files (e.g., 'v2' for ocsvm_model_v2.pkl)")
        print("                    Default: Auto-detect based on available files")
        print("")
        print("Options:")
        print("  -h, --help      : Show this help message and exit")
        print("")
        print("Examples:")
        print("  python analyze_capture.py capture.pcap")
        print("  python analyze_capture.py capture.pcap ai-model/output/retrained_model")
        print("  python analyze_capture.py capture.pcap ai-model/output/retrained_model v2")
        sys.exit(1)

    pcap_path = sys.argv[1]

    # Check if the PCAP file exists
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        sys.exit(1)

    # Use the specified model directory if provided, otherwise use the default
    if len(sys.argv) > 2:
        model_dir = sys.argv[2]
        # If not absolute path, make it relative to script directory
        if not os.path.isabs(model_dir):
            script_dir = os.path.dirname(os.path.abspath(__file__))
            model_dir = os.path.join(script_dir, model_dir)
    else:
        # Set default model directory using absolute path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        model_dir = os.path.join(script_dir, 'output', 'retrained_model')

    # Use the specified model version if provided, otherwise auto-detect
    model_version = sys.argv[3] if len(sys.argv) > 3 else None

    try:
        print(f"Analyzing PCAP file: {pcap_path}")
        print(f"Using model directory: {model_dir}")
        if model_version:
            print(f"Using model version: {model_version}")
        else:
            print("Model version: Auto-detect")

        # Analyze the PCAP file
        results, output_dir = analyze_pcap_with_zeek(pcap_path, model_dir, model_version)

        # Print results
        print("\nAnalysis Results:")
        print(f"Found {sum(1 for r in results if r['prediction'] == 'anomaly')} anomalies out of {len(results)} connections.")

        # Print detailed results
        for result in results:
            print(f"UID: {result['uid']}, Score: {result['score']:.6f}, Prediction: {result['prediction']}")

        # Save results to CSV
        csv_path = os.path.join(output_dir, 'prediction_results.csv')
        df = pd.DataFrame(results)
        df.to_csv(csv_path, index=False)
        print(f"\nResults saved to CSV: {csv_path}")

        # Generate visualizations
        try:
            import subprocess
            # Use absolute path for visualize_results.py
            script_dir = os.path.dirname(os.path.abspath(__file__))
            vis_script_path = os.path.join(script_dir, "visualize_results.py")
            vis_cmd = f"{sys.executable} {vis_script_path} {csv_path} {output_dir}"
            print(f"\nGenerating visualizations with command: {vis_cmd}")
            subprocess.run(vis_cmd, shell=True, check=True)
            print(f"Visualizations saved to: {output_dir}")
        except Exception as vis_error:
            print(f"Warning: Failed to generate visualizations: {str(vis_error)}")

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
