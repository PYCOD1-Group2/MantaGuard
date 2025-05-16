import sys
import os
from data_loader import check_dataset_labels, load_and_preprocess_data
import argparse

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Check the labels in NSL-KDD dataset')
    parser.add_argument('--train', default='data/KDDTrain.csv', help='Path to training data')
    parser.add_argument('--test', default='data/KDDTest.csv', help='Path to test data')
    return parser.parse_args()

def main():
    """Main function to check dataset labels and preprocessing."""
    args = parse_args()
    
    # Print the current working directory for debugging
    print(f"Current working directory: {os.getcwd()}")
    
    # Check if files exist
    if not os.path.exists(args.train):
        print(f"Error: Training file not found at {args.train}")
        print(f"Full path: {os.path.abspath(args.train)}")
        return
    
    if not os.path.exists(args.test):
        print(f"Error: Test file not found at {args.test}")
        print(f"Full path: {os.path.abspath(args.test)}")
        return
    
    print(f"Found files:")
    print(f"  - Training data: {args.train}")
    print(f"  - Test data: {args.test}")
    
    print("\nChecking dataset labels:")
    check_dataset_labels(args.train, args.test)
    
    # Now try to load and preprocess the data
    print("\nTrying to load and preprocess the data...")
    try:
        X_normal_scaled, X_test_scaled, y_test, scaler, categorical_encoders = load_and_preprocess_data(
            args.train, args.test, save_normal=True
        )
        print(f"\nSuccess! Loaded {X_normal_scaled.shape[0]} normal training samples and {X_test_scaled.shape[0]} test samples.")
        print(f"Feature dimensions: {X_normal_scaled.shape[1]}")
    except Exception as e:
        print(f"Error loading data: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print("\nEnd of script")

if __name__ == "__main__":
    main()