import os
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('TkAgg')  # or try 'Qt5Agg' if TkAgg doesn't work
import matplotlib.pyplot as plt
from incremental_knn import IncrementalKNN
from data_loader import create_binary_labels
from evaluation import evaluate_model, print_evaluation, plot_evaluation
from datetime import datetime

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Test Incremental KNN model')
    
    parser.add_argument('--model', required=True, 
                        help='Path to trained KNN model directory')
    parser.add_argument('--test', default='data/KDDTest.csv', 
                        help='Path to test data')
    parser.add_argument('--interactive', action='store_true',
                        help='Enable interactive mode for user feedback')
    parser.add_argument('--output-dir', default=None,
                        help='Directory to save evaluation plots (default: model directory)')
    parser.add_argument('--show-plots', action='store_true',
                        help='Show plots interactively (will pause execution)')
    
    return parser.parse_args()

def save_evaluation_to_txt(results, output_dir, model_type="KNN", timestamp=None):
    """
    Save evaluation results to a text file.
    
    Parameters:
    -----------
    results : dict
        Dictionary with evaluation results
    output_dir : str
        Directory to save the evaluation file
    model_type : str
        Type of model being evaluated
    timestamp : str, optional
        Timestamp to use in the filename, if None a new timestamp will be generated
    """
    # Create directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Create file path with timestamp
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    file_path = os.path.join(output_dir, f"{model_type}_evaluation_{timestamp}.txt")
    
    # Format evaluation results
    with open(file_path, 'w') as f:
        # Write header
        f.write(f"=== {model_type} MODEL EVALUATION REPORT ===\n")
        f.write(f"Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Write confusion matrix
        cm = results['confusion_matrix']
        f.write("Confusion Matrix:\n")
        f.write(f"                 Predicted Normal    Predicted Anomaly\n")
        f.write(f"Actual Normal    {cm[0, 0]:<16} {cm[0, 1]:<16}\n")
        f.write(f"Actual Anomaly   {cm[1, 0]:<16} {cm[1, 1]:<16}\n\n")
        
        # Write classification report
        cr = results['classification_report']
        f.write("Classification Report:\n")
        f.write(f"              Precision    Recall  F1-Score   Support\n")
        
        for label in cr:
            if label in ['normal', 'anomaly']:
                f.write(f"{label.capitalize():<15} {cr[label]['precision']:.2f}        {cr[label]['recall']:.2f}    {cr[label]['f1-score']:.2f}       {cr[label]['support']}\n")
        
        f.write(f"Accuracy                                   {results['accuracy']:.2f}\n\n")
        
        # Write ROC AUC
        f.write(f"ROC AUC Score: {results['roc_auc']:.4f}\n\n")
        
        # Write additional info
        f.write(f"True positives: {cm[1, 1]}\n")
        f.write(f"False positives: {cm[0, 1]}\n")
        f.write(f"True negatives: {cm[0, 0]}\n")
        f.write(f"False negatives: {cm[1, 0]}\n\n")
        
        # Calculate additional metrics
        detection_rate = cm[1, 1] / (cm[1, 0] + cm[1, 1])
        false_alarm_rate = cm[0, 1] / (cm[0, 0] + cm[0, 1])
        f.write(f"Detection rate: {detection_rate:.4f}\n")
        f.write(f"False alarm rate: {false_alarm_rate:.4f}\n")
    
    return file_path

def main():
    """Test the incremental KNN model."""
    args = parse_args()
    
    # Generate timestamp for this evaluation
    full_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # Full timestamp for files
    date_only = datetime.now().strftime("%Y%m%d")  # Date-only for folder
    
    # Create date-only output directory
    if args.output_dir:
        base_output_dir = args.output_dir
    else:
        base_output_dir = "output/knn_model"  # Changed default to fixed directory
    
    # Create a date-only subdirectory within the output directory
    output_dir = os.path.join(base_output_dir, f"eval_{date_only}")
    
    # Make sure this is in your main function before using output_dir
    os.makedirs(output_dir, exist_ok=True)
    
    # Check if model exists
    if not os.path.exists(args.model):
        print(f"Error: Model directory not found at {args.model}")
        return
    
    # Check if test file exists
    if not os.path.exists(args.test):
        print(f"Error: Test file not found at {args.test}")
        return
    
    # Load the model
    print(f"Loading KNN model from {args.model}...")
    knn_model = IncrementalKNN.load_model(args.model)
    
    # Load test data
    print(f"Loading test data from {args.test}...")
    df_test = pd.read_csv(args.test)
    
    # Extract features and labels
    label_column = None
    for col in ['label', 'class', 'attack_type']:
        if col in df_test.columns:
            label_column = col
            break
    
    if not label_column:
        print("Error: Could not find label column in test data")
        return
    
    y_test = df_test[label_column].values
    X_df_test = df_test.drop(label_column, axis=1)
    
    # Apply same preprocessing as in training
    # 1. Check for "difficulty" column and remove it if present
    if 'difficulty' in X_df_test.columns:
        print("Removing 'difficulty' column from test data")
        X_df_test = X_df_test.drop('difficulty', axis=1)
    
    # 2. Encode categorical columns
    categorical_cols = ["protocol_type", "service", "flag"]
    for cat_col in categorical_cols:
        if cat_col in X_df_test.columns and X_df_test[cat_col].dtype == 'object':
            print(f"Encoding categorical column: {cat_col}")
            from sklearn.preprocessing import LabelEncoder
            encoder = LabelEncoder()
            X_df_test[cat_col] = encoder.fit_transform(X_df_test[cat_col])
    
    # 3. Convert remaining non-numeric columns
    for col in X_df_test.columns:
        if X_df_test[col].dtype == 'object':
            print(f"Converting non-numeric column {col} to numeric")
            X_df_test[col] = pd.to_numeric(X_df_test[col], errors='coerce')
    
    # 4. Fill NaN values with 0
    X_df_test.fillna(0, inplace=True)
    
    # Now convert to numpy array
    X_test = X_df_test.values
    
    if args.interactive:
        # Interactive mode: process samples one by one with user feedback
        print("\n=== Interactive Testing Mode ===")
        print("Processing test samples one by one with user feedback.")
        
        n_samples = min(50, len(X_test))  # Process up to 50 samples
        for i in range(n_samples):
            print(f"\nSample {i+1}/{n_samples} (true label: {y_test[i]})")
            knn_model.handle_new_packet(X_test[i])
            
            # Ask to continue every 5 samples
            if i % 5 == 4:
                cont = input("\nContinue with more samples? (y/n): ")
                if cont.lower() != 'y':
                    break
        
        # Save updated model
        knn_model.save_model(args.model)
        print(f"\nUpdated model saved to {args.model}")
    else:
        # Batch mode: evaluate performance
        print("\n=== Batch Testing Mode ===")
        print("Evaluating model performance on test data...")
        
        # Scale the test data using the model's scaler
        X_test_scaled = knn_model.scaler.transform(X_test)
        
        # Get predictions
        y_pred = []
        for sample in X_test_scaled:
            label, _ = knn_model.classify_packet_knn(sample)
            y_pred.append(label.lower())
        
        # Convert true labels to binary
        y_true = create_binary_labels(y_test)
        
        # Convert predictions to binary format for evaluation
        y_pred_binary = ['normal' if p == 'normal' else 'anomaly' for p in y_pred]
        
        # Get decision scores
        decision_scores = []
        for sample in X_test_scaled:
            _, distance = knn_model.classify_packet_knn(sample)
            decision_scores.append(-distance)  # Negative distance as score
        
        # Evaluate
        results = evaluate_model(y_true, y_pred_binary, np.array(decision_scores))
        print_evaluation(results)
        
        # Save evaluation to text file - pass the full timestamp as an extra parameter
        report_path = save_evaluation_to_txt(results, output_dir, model_type="KNN", timestamp=full_timestamp)
        print(f"Evaluation report saved to: {report_path}")
        
        # Generate and save plots
        print("\nGenerating evaluation plots...")
        plot_evaluation(results, output_dir=output_dir)
        if args.show_plots:
            plt.show()  # Only show plots if flag is provided
        print(f"Plots saved to {output_dir}")

if __name__ == "__main__":
    main()