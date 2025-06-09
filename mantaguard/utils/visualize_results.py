#!/usr/bin/env python3
# visualize_results.py - Generate visualizations from prediction results

import os
import sys
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from sklearn.metrics import roc_curve, auc, precision_recall_curve, confusion_matrix

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Generate visualizations from prediction results.')
    parser.add_argument('input_csv', help='Path to the CSV file with prediction results')
    parser.add_argument('output_dir', help='Directory to save visualization images')
    parser.add_argument('--title-prefix', help='Prefix for chart titles', default='')
    return parser.parse_args()

def load_data(csv_path):
    """Load and validate the CSV data."""
    try:
        # Load the CSV file
        df = pd.read_csv(csv_path)
        
        # Check for required columns
        required_columns = ['uid', 'timestamp', 'score', 'prediction']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            print(f"Error: Missing required columns in CSV: {', '.join(missing_columns)}")
            sys.exit(1)
        
        # Convert timestamp to datetime if it's not already
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Check if true label column exists
        has_true_label = 'true_label' in df.columns
        
        return df, has_true_label
    
    except Exception as e:
        print(f"Error loading CSV file: {str(e)}")
        sys.exit(1)

def create_score_histogram(df, output_dir, title_prefix=''):
    """Create histogram of decision function scores."""
    plt.figure(figsize=(10, 6))
    
    # Create histogram with KDE
    sns.histplot(df['score'], kde=True)
    
    # Add a vertical line at score=0 (typical decision boundary)
    plt.axvline(x=0, color='r', linestyle='--', label='Decision Boundary')
    
    # Set labels and title
    plt.xlabel('Decision Function Score')
    plt.ylabel('Frequency')
    plt.title(f'{title_prefix}Distribution of Anomaly Scores')
    plt.legend()
    
    # Save the figure
    output_path = os.path.join(output_dir, 'score_histogram.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved score histogram to {output_path}")

def create_roc_curve(df, has_true_label, output_dir, title_prefix=''):
    """Create ROC curve if ground truth labels are present."""
    if not has_true_label:
        print("Skipping ROC curve: No ground truth labels found")
        return
    
    plt.figure(figsize=(10, 6))
    
    # Convert labels to binary (1 for anomaly, 0 for normal)
    y_true = (df['true_label'] == 'anomaly').astype(int)
    
    # Use negative of score since higher scores typically indicate anomalies
    y_score = -df['score']
    
    # Calculate ROC curve and ROC area
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    
    # Plot ROC curve
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random')
    
    # Set labels and title
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title(f'{title_prefix}Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    
    # Save the figure
    output_path = os.path.join(output_dir, 'roc_curve.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved ROC curve to {output_path}")

def create_precision_recall_curve(df, has_true_label, output_dir, title_prefix=''):
    """Create Precision-Recall curve if ground truth labels are present."""
    if not has_true_label:
        print("Skipping Precision-Recall curve: No ground truth labels found")
        return
    
    plt.figure(figsize=(10, 6))
    
    # Convert labels to binary (1 for anomaly, 0 for normal)
    y_true = (df['true_label'] == 'anomaly').astype(int)
    
    # Use negative of score since higher scores typically indicate anomalies
    y_score = -df['score']
    
    # Calculate precision-recall curve
    precision, recall, _ = precision_recall_curve(y_true, y_score)
    
    # Plot precision-recall curve
    plt.plot(recall, precision, color='blue', lw=2)
    
    # Set labels and title
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title(f'{title_prefix}Precision-Recall Curve')
    
    # Add baseline for random classifier
    baseline = sum(y_true) / len(y_true)
    plt.axhline(y=baseline, color='r', linestyle='--', label=f'Baseline (No Skill): {baseline:.3f}')
    plt.legend()
    
    # Save the figure
    output_path = os.path.join(output_dir, 'precision_recall_curve.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved Precision-Recall curve to {output_path}")

def create_confusion_matrix(df, has_true_label, output_dir, title_prefix=''):
    """Create confusion matrix if ground truth labels are present."""
    if not has_true_label:
        print("Skipping confusion matrix: No ground truth labels found")
        return
    
    plt.figure(figsize=(8, 6))
    
    # Get true and predicted labels
    y_true = df['true_label'].map({'normal': 0, 'anomaly': 1})
    y_pred = df['prediction'].map({'normal': 0, 'anomaly': 1})
    
    # Calculate confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    
    # Plot confusion matrix
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Anomaly'],
                yticklabels=['Normal', 'Anomaly'])
    
    # Set labels and title
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title(f'{title_prefix}Confusion Matrix')
    
    # Save the figure
    output_path = os.path.join(output_dir, 'confusion_matrix.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved confusion matrix to {output_path}")

def create_time_series(df, output_dir, title_prefix=''):
    """Create time series of anomalies vs. time."""
    plt.figure(figsize=(12, 6))
    
    # Sort by timestamp
    df_sorted = df.sort_values('timestamp')
    
    # Create a color map for normal vs anomaly
    colors = df_sorted['prediction'].map({'normal': 'blue', 'anomaly': 'red'})
    
    # Plot scores over time
    plt.scatter(df_sorted['timestamp'], df_sorted['score'], c=colors, alpha=0.6)
    
    # Add a horizontal line at score=0 (typical decision boundary)
    plt.axhline(y=0, color='green', linestyle='--', label='Decision Boundary')
    
    # Set labels and title
    plt.xlabel('Time')
    plt.ylabel('Anomaly Score')
    plt.title(f'{title_prefix}Anomaly Scores Over Time')
    
    # Add legend
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Normal'),
        Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Anomaly'),
        Line2D([0], [0], color='green', linestyle='--', label='Decision Boundary')
    ]
    plt.legend(handles=legend_elements)
    
    # Format x-axis for better readability
    plt.gcf().autofmt_xdate()
    
    # Save the figure
    output_path = os.path.join(output_dir, 'time_series.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved time series plot to {output_path}")

def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # Check if input CSV exists
    if not os.path.exists(args.input_csv):
        print(f"Error: Input CSV file not found: {args.input_csv}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        print(f"Created output directory: {args.output_dir}")
    
    # Load and validate data
    df, has_true_label = load_data(args.input_csv)
    print(f"Loaded {len(df)} records from {args.input_csv}")
    print(f"Ground truth labels {'found' if has_true_label else 'not found'}")
    
    # Create visualizations
    create_score_histogram(df, args.output_dir, args.title_prefix)
    create_roc_curve(df, has_true_label, args.output_dir, args.title_prefix)
    create_precision_recall_curve(df, has_true_label, args.output_dir, args.title_prefix)
    create_confusion_matrix(df, has_true_label, args.output_dir, args.title_prefix)
    create_time_series(df, args.output_dir, args.title_prefix)
    
    print(f"All visualizations saved to {args.output_dir}")

if __name__ == "__main__":
    main()