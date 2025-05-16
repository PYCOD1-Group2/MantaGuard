#!/usr/bin/env python3
# analyze_capture.py - Analyze an existing PCAP file with Zeek and ML

import os
import sys
import pandas as pd
from datetime import datetime
from timed_capture import analyze_pcap_with_zeek

def main():
    # Parse command-line arguments
    if len(sys.argv) < 2 or sys.argv[1] == "--help" or sys.argv[1] == "-h":
        print("Usage: python analyze_capture.py <pcap_path> [<model_dir> [<model_version>]]")
        print("  <pcap_path>     : Path to the existing PCAP file to analyze")
        print("  <model_dir>     : (Optional) Directory containing the AI model files")
        print("                    Default: 'output/ocsvm_model'")
        print("  <model_version> : (Optional) Version suffix for model files (e.g., 'v2' for ocsvm_model_v2.pkl)")
        print("                    Default: Auto-detect based on available files")
        print("")
        print("Options:")
        print("  -h, --help      : Show this help message and exit")
        print("")
        print("Examples:")
        print("  python analyze_capture.py capture.pcap")
        print("  python analyze_capture.py capture.pcap output/retrained_model")
        print("  python analyze_capture.py capture.pcap output/retrained_model v2")
        sys.exit(1)

    pcap_path = sys.argv[1]

    # Check if the PCAP file exists
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        sys.exit(1)

    # Use the specified model directory if provided, otherwise use the default
    model_dir = sys.argv[2] if len(sys.argv) > 2 else 'output/ocsvm_model'

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
        results = analyze_pcap_with_zeek(pcap_path, model_dir, model_version)

        # Print results
        print("\nAnalysis Results:")
        print(f"Found {sum(1 for r in results if r['prediction'] == 'anomaly')} anomalies out of {len(results)} connections.")

        # Print detailed results
        for result in results:
            print(f"UID: {result['uid']}, Score: {result['score']:.6f}, Prediction: {result['prediction']}")

        # Save results to CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join('output', 'analysis_results', timestamp)
        os.makedirs(output_dir, exist_ok=True)

        csv_path = os.path.join(output_dir, 'prediction_results.csv')
        df = pd.DataFrame(results)
        df.to_csv(csv_path, index=False)
        print(f"\nResults saved to CSV: {csv_path}")

        # Generate visualizations
        try:
            import subprocess
            vis_cmd = f"python visualize_results.py {csv_path} {output_dir}"
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
