#!/usr/bin/env python3
# test_analyze_capture.py - Test the analyze_capture.py script

import os
import sys
import subprocess

def main():
    # Test parameters
    pcap_path = "data/zeek/test_capture.pcap"
    model_dir = "output/retrained_model"
    
    # Check if the test PCAP file exists
    if not os.path.exists(pcap_path):
        print(f"Test PCAP file not found: {pcap_path}")
        print("Creating a test PCAP file using timed_capture.py...")
        
        try:
            # Use timed_capture.py to create a test PCAP file
            from timed_capture import run_capture
            interface = "lo"  # Use loopback interface for testing
            duration = 5  # Short duration for testing
            run_capture(interface, duration, pcap_path)
            print(f"Created test PCAP file: {pcap_path}")
        except Exception as e:
            print(f"Failed to create test PCAP file: {str(e)}")
            sys.exit(1)
    
    # Test analyze_capture.py
    print("\nTesting analyze_capture.py...")
    try:
        # Run the analyze_capture.py script as a subprocess
        cmd = f"python analyze_capture.py {pcap_path} {model_dir}"
        print(f"Running command: {cmd}")
        
        process = subprocess.run(cmd, shell=True, check=True, text=True, capture_output=True)
        
        # Print the output
        print("\nOutput from analyze_capture.py:")
        print(process.stdout)
        
        if "Error:" in process.stdout:
            print("Test failed: Error detected in output")
            sys.exit(1)
        
        print("Test passed!")
    except subprocess.CalledProcessError as e:
        print(f"Test failed: {str(e)}")
        if e.stdout:
            print("Standard output:")
            print(e.stdout)
        if e.stderr:
            print("Standard error:")
            print(e.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Test failed: {str(e)}")
        sys.exit(1)
    
    print("\nAll tests passed!")

if __name__ == "__main__":
    main()