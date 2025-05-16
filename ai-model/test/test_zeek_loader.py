#!/usr/bin/env python3
# test_zeek_loader.py - Test script for the zeek_loader module

import os
import sys
import numpy as np
from parsers.zeek_loader import load_conn_log, zeek_to_features

def main():
    """
    Test the zeek_loader module with a sample conn.log file.

    Usage:
        python test_zeek_loader.py <path_to_conn_log>
    """
    if len(sys.argv) < 2:
        print("Usage: python test_zeek_loader.py <path_to_conn_log>")
        print("\nExample: python test_zeek_loader.py data/sample_conn.log")
        return

    log_path = sys.argv[1]

    try:
        print(f"Loading Zeek conn.log from: {log_path}")
        df = load_conn_log(log_path)

        print("\nDataFrame info:")
        print(f"Shape: {df.shape}")
        print("\nColumns:")
        for col in df.columns:
            print(f"  - {col}")

        print("\nFirst 5 rows:")
        print(df.head(5))

        print("\nData types:")
        print(df.dtypes)

        # Test zeek_to_features function
        print("\n" + "="*50)
        print("Testing zeek_to_features function:")
        print("="*50)

        # Convert DataFrame to feature matrix
        X, encoders = zeek_to_features(df)

        print("\nFeature matrix info:")
        print(f"Shape: {X.shape}")
        print(f"Data type: {X.dtype}")

        print("\nSample of feature matrix (first 3 rows):")
        print(X[:3])

        print("\nEncoders for categorical columns:")
        for col, mapping in encoders.items():
            if isinstance(mapping, dict) and not mapping.get('column_missing', False):
                print(f"\n{col} mapping:")
                for value, idx in mapping.items():
                    print(f"  {value} -> {idx}")
            else:
                print(f"\n{col}: {mapping}")

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
