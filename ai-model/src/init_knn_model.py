import os
import argparse
import numpy as np
from incremental_knn import IncrementalKNN

def parse_args():
    """Parse command line arguments for KNN initialization."""
    parser = argparse.ArgumentParser(description='Initialize Incremental KNN with normal traffic')
    
    parser.add_argument('--train', default='data/KDDTrain_normal.csv', 
                        help='Path to normal traffic training data')
    parser.add_argument('--output', default='output/knn_model', 
                        help='Output directory for the KNN model')
    parser.add_argument('--base-model', default='output/base_model',
                        help='Path to base model directory to reuse scaler')
    parser.add_argument('--k', type=int, default=5, 
                        help='Number of neighbors for KNN')
    parser.add_argument('--threshold', type=float, default=2.5, 
                        help='Distance threshold for anomaly detection')
    parser.add_argument('--create-new-scaler', action='store_true',
                        help='Create a new scaler instead of using the base model scaler')
    
    return parser.parse_args()

def main():
    """Initialize the Incremental KNN system with normal traffic."""
    args = parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Initialize KNN model
    print(f"Initializing Incremental KNN (k={args.k}, threshold={args.threshold})...")
    knn_model = IncrementalKNN(k=args.k, distance_threshold=args.threshold)
    
    # Try to load existing scaler from base model if not creating a new one
    if not args.create_new_scaler and os.path.exists(args.base_model):
        print(f"Attempting to use scaler from base model: {args.base_model}")
        knn_model.load_existing_model(args.base_model)
    else:
        if args.create_new_scaler:
            print("Will create a new scaler instead of using base model")
    
    # Load normal traffic data
    if not os.path.exists(args.train):
        print(f"Error: Training file not found at {args.train}")
        return
    
    knn_model.load_normal_data(args.train)
    
    # Save the initialized model
    knn_model.save_model(args.output)
    
    print(f"\nModel initialization complete!")
    print(f"Normal samples in memory: {knn_model.stats['normal_samples']}")
    print(f"Model saved to: {args.output}")
    
    print("\nYou can now use this model to classify traffic and learn from user feedback")
    print("Example command to test the model:")
    print(f"python src/test_knn.py --model {args.output} --test data/KDDTest.csv")

if __name__ == "__main__":
    main()