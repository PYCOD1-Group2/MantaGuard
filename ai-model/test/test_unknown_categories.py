#!/usr/bin/env python3
# test_unknown_categories.py - Test script for unknown categories handling

import os
import sys
import json
import pandas as pd
import numpy as np
import joblib
import shutil

# Add parent directory to path to import custom modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from parsers.zeek_loader import zeek_to_features
from timed_capture import update_unknown_categories

def test_with_existing_file():
    """Test updating unknown categories when the file already exists."""
    print("\n=== Testing with existing file ===")

    # Create a backup of the unknown categories file
    unknown_categories_file = "training/unknown_categories.json"
    backup_file = "training/unknown_categories.json.bak"

    if os.path.exists(unknown_categories_file):
        print(f"Creating backup of {unknown_categories_file} to {backup_file}")
        with open(unknown_categories_file, 'r') as f:
            original_content = f.read()
        with open(backup_file, 'w') as f:
            f.write(original_content)

    # Load pre-trained encoders
    model_dir = 'output/retrained_model'
    encoders_path = os.path.join(model_dir, 'encoders.pkl')

    try:
        encoders = joblib.load(encoders_path)
        print("Loaded pre-trained encoders")
    except Exception as e:
        print(f"Error loading encoders: {e}")
        sys.exit(1)

    # Create a sample DataFrame with new categorical values
    print("Creating sample DataFrame with new categorical values...")
    df = pd.DataFrame({
        'ts': [pd.Timestamp.now()],
        'uid': ['TEST123'],
        'proto': ['new_proto'],  # New value for proto
        'service': ['new_service'],  # New value for service
        'history': ['new_history'],  # New value for history
        'duration': [1.0],
        'orig_bytes': [100],
        'resp_bytes': [200],
        'orig_pkts': [10],
        'resp_pkts': [20]
    })

    # Convert to feature vectors
    print("Converting to feature vectors...")
    X, _, unknown_values = zeek_to_features(df, encoders)

    # Check if any unknown values were found
    has_unknown_values = any(len(values) > 0 for values in unknown_values.values())
    if has_unknown_values:
        print("Unknown categorical values were found and encoded as -1.")

        # Print unknown values
        print("Unknown values detected:")
        for col, values in unknown_values.items():
            if values:
                print(f"  {col}: {values}")

        # Update unknown categories file
        print("Updating unknown categories file...")
        merged_unknown_values = update_unknown_categories(unknown_values)

        # Verify that the unknown categories file was updated correctly
        print("Verifying that the unknown categories file was updated correctly...")
        with open(unknown_categories_file, 'r') as f:
            updated_content = json.load(f)

        # Check if new values are in the updated file
        success = True
        for col, values in unknown_values.items():
            if values:
                for value in values:
                    if value not in updated_content.get(col, []):
                        print(f"Error: Value '{value}' for column '{col}' not found in updated file")
                        success = False

        if success:
            print("Success! Unknown categories file was updated correctly")
        else:
            print("Error: Unknown categories file was not updated correctly")
    else:
        print("No unknown values were found. This is unexpected.")
        sys.exit(1)

    # Restore the original unknown categories file
    if os.path.exists(backup_file):
        print(f"Restoring {unknown_categories_file} from {backup_file}")
        with open(backup_file, 'r') as f:
            original_content = f.read()
        with open(unknown_categories_file, 'w') as f:
            f.write(original_content)

        # Remove the backup file
        os.remove(backup_file)

    print("Test with existing file completed")

def test_with_nonexistent_file():
    """Test updating unknown categories when the file doesn't exist."""
    print("\n=== Testing with nonexistent file ===")

    # Define test file paths
    test_dir = "training/test_nonexistent"
    test_file = f"{test_dir}/unknown_categories.json"
    backup_dir = None

    # Backup the directory if it exists
    if os.path.exists(test_dir):
        backup_dir = f"{test_dir}_backup"
        print(f"Directory {test_dir} exists. Moving to {backup_dir}")
        shutil.move(test_dir, backup_dir)

    # Create sample unknown values
    unknown_values = {
        "proto": ["test_proto"],
        "service": ["test_service"],
        "history": ["test_history"]
    }

    try:
        # Update unknown categories file (should create the directory and file)
        print(f"Calling update_unknown_categories with nonexistent file: {test_file}")
        merged_unknown_values = update_unknown_categories(unknown_values, test_file)

        # Verify that the file was created
        if os.path.exists(test_file):
            print(f"Success! File {test_file} was created")

            # Verify content
            with open(test_file, 'r') as f:
                content = json.load(f)

            # Check if values are in the file
            success = True
            for col, values in unknown_values.items():
                if col not in content:
                    print(f"Error: Column '{col}' not found in created file")
                    success = False
                else:
                    for value in values:
                        if value not in content[col]:
                            print(f"Error: Value '{value}' for column '{col}' not found in created file")
                            success = False

            if success:
                print("Success! File content is correct")
            else:
                print("Error: File content is incorrect")
        else:
            print(f"Error: File {test_file} was not created")
    finally:
        # Clean up
        if os.path.exists(test_dir):
            print(f"Removing test directory: {test_dir}")
            shutil.rmtree(test_dir)

        # Restore backup if it exists
        if backup_dir and os.path.exists(backup_dir):
            print(f"Restoring directory from {backup_dir} to {test_dir}")
            shutil.move(backup_dir, test_dir)

    print("Test with nonexistent file completed")

def main():
    """Test unknown categories handling in timed_capture.py and realtime_detector.py."""
    print("Testing unknown categories handling...")

    # Test with existing file
    test_with_existing_file()

    # Test with nonexistent file
    test_with_nonexistent_file()

    print("\nAll tests completed")

if __name__ == "__main__":
    main()
