#!/usr/bin/env python3
# test_timed_capture.py - Test the timed_capture.py script

import os
import sys
import time
from timed_capture import run_capture, analyze_pcap_with_zeek

def main():
    # Test parameters
    interface = "lo"  # Use loopback interface for testing
    duration = 5  # Short duration for testing
    pcap_path = "data/zeek/test_capture.pcap"
    model_dir = "output/retrained_model"
    
    # Test packet capture
    print("Testing packet capture...")
    try:
        pcap_file = run_capture(interface, duration, pcap_path)
        print(f"Packet capture test passed. PCAP file saved to: {pcap_file}")
    except Exception as e:
        print(f"Packet capture test failed: {str(e)}")
        sys.exit(1)
    
    # Test Zeek analysis
    print("\nTesting Zeek analysis...")
    try:
        results = analyze_pcap_with_zeek(pcap_file, model_dir)
        print(f"Zeek analysis test passed. Found {len(results)} connections.")
        
        # Print some results if available
        if results:
            print("\nSample results:")
            for i, result in enumerate(results[:5]):  # Show up to 5 results
                print(f"  {i+1}. UID: {result['uid']}, Prediction: {result['prediction']}, Score: {result['score']}")
    except Exception as e:
        print(f"Zeek analysis test failed: {str(e)}")
        sys.exit(1)
    
    print("\nAll tests passed!")

if __name__ == "__main__":
    main()