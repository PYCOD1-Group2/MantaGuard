#!/usr/bin/env python3
# test_zeek_loader.py - Test script for the zeek_loader module

import os
import sys
import argparse
import numpy as np
from mantaguard.core.ai.parsers.zeek_loader import load_conn_log, zeek_to_features

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Test the zeek_loader module with a sample conn.log file.'
    )
    parser.add_argument('log_path', help='Path to the conn.log file to test')
    parser.add_argument('--verbose', '-v', action='store_true', 
                        help='Show detailed output including feature mappings')
    return parser.parse_args()

def main():
    """
    Test the zeek_loader module with a sample conn.log file.

    Usage:
        python test_zeek_loader.py <path_to_conn_log> [--verbose]
    """
    try:
        args = parse_args()
        log_path = args.log_path
        verbose = args.verbose

        if not os.path.exists(log_path):
            print(f"Error: File not found: {log_path}")
            print("\nExample: python test_zeek_loader.py data/sample_conn.log")
            return 1

        print(f"Loading Zeek conn.log from: {log_path}")
        df = load_conn_log(log_path)

        print("\nDataFrame info:")
        print(f"Shape: {df.shape}")
        print(f"Rows: {df.shape[0]}, Columns: {df.shape[1]}")

        print("\nColumns:")
        for col in df.columns:
            print(f"  - {col}")

        print("\nFirst 5 rows:")
        print(df.head(5))

        if verbose:
            print("\nData types:")
            print(df.dtypes)

        # Test zeek_to_features function
        print("\n" + "="*50)
        print("Testing zeek_to_features function:")
        print("="*50)

        # Convert DataFrame to feature matrix
        X, encoders, unknown_values = zeek_to_features(df)

        print("\nFeature matrix info:")
        print(f"Shape: {X.shape}")
        print(f"Data type: {X.dtype}")

        print("\nSample of feature matrix (first 3 rows):")
        print(X[:3] if X.shape[0] >= 3 else X)

        if unknown_values:
            print("\nWarning: Unknown values detected:")
            for col, values in unknown_values.items():
                print(f"  - {col}: {values}")

        if verbose:
            print("\nEncoders for categorical columns:")
            for col, mapping in encoders.items():
                if isinstance(mapping, dict) and not mapping.get('column_missing', False):
                    print(f"\n{col} mapping:")
                    for value, idx in mapping.items():
                        print(f"  {value} -> {idx}")
                else:
                    print(f"\n{col}: {mapping}")

        print("\nTest completed successfully!")
        return 0

    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
