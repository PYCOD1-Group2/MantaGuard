import os
import argparse
import numpy as np
from data_loader import load_and_preprocess_data, create_binary_labels
from model import AnomalyDetector
from evaluation import evaluate_model, print_evaluation, plot_evaluation, analyze_attack_types, plot_attack_type_analysis
import joblib

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Train and evaluate One-Class SVM on NSL-KDD dataset')
    
    parser.add_argument('--train', default='data/KDDTrain.csv', help='Path to NSL-KDD training data')
    parser.add_argument('--test', default='data/KDDTest.csv', help='Path to NSL-KDD test data')
    parser.add_argument('--output', default='output/nslkdd_model', help='Output directory for results')
    parser.add_argument('--nu', type=float, default=0.01, help='Nu parameter for One-Class SVM')
    parser.add_argument('--gamma', default='scale', help='Gamma parameter for One-Class SVM')
    parser.add_argument('--kernel', default='rbf', help='Kernel for One-Class SVM')
    parser.add_argument('--analyze-attacks', action='store_true', help='Analyze detection rate by attack type')
    
    return parser.parse_args()

def main():
    """Main function to train on NSL-KDD dataset."""
    args = parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Load and preprocess data
    print(f"Loading and preprocessing NSL-KDD data from {args.train} and {args.test}...")
    X_normal_scaled, X_test_scaled, y_test, scaler, categorical_encoders = load_and_preprocess_data(
        args.train, args.test, save_normal=True
    )
    
    # Save scaler and encoders
    joblib.dump(scaler, os.path.join(args.output, "scaler.pkl"))
    joblib.dump(categorical_encoders, os.path.join(args.output, "encoders.pkl"))
    
    # Initialize and train the model
    print(f"Training One-Class SVM with nu={args.nu}, gamma={args.gamma}, kernel={args.kernel}...")
    detector = AnomalyDetector(kernel=args.kernel, nu=args.nu, gamma=args.gamma)
    detector.train(X_normal_scaled)
    
    # Save the trained model
    detector.save_model(args.output)
    print(f"Model saved to {args.output}")
    
    # Predict on test data
    print("Running predictions on test data...")
    y_pred_raw = detector.predict(X_test_scaled)
    decision_scores = detector.decision_function(X_test_scaled)
    
    # Convert predictions to "normal"/"anomaly" labels
    y_pred = np.where(y_pred_raw == 1, "normal", "anomaly")
    
    # Convert true labels to binary (normal/anomaly)
    y_true = create_binary_labels(y_test)
    
    # Evaluate the model
    print("Evaluating model performance...")
    results = evaluate_model(y_true, y_pred, decision_scores)
    
    # Print and plot evaluation results
    print_evaluation(results)
    plot_evaluation(results, args.output)
    
    # Analyze attack types if requested
    if args.analyze_attacks:
        print("Analyzing detection performance by attack type...")
        attack_analysis = analyze_attack_types(y_true, y_pred, y_test)
        print("\nDetection Rate by Attack Type:")
        print(attack_analysis)
        
        # Plot attack type analysis
        plot_attack_type_analysis(attack_analysis, args.output)
    
    print(f"All results saved to {args.output}")

if __name__ == "__main__":
    main()