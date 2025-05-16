import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc, precision_recall_curve

def evaluate_model(y_true, y_pred, y_score=None):
    """
    Evaluate the model performance with various metrics.
    
    Args:
        y_true: True binary labels (normal/anomaly)
        y_pred: Predicted binary labels (normal/anomaly)
        y_score: Decision function scores for ROC curve (optional)
        
    Returns:
        results: Dictionary containing evaluation metrics
    """
    # Calculate confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=["normal", "anomaly"])
    
    # Classification report
    report = classification_report(y_true, y_pred, output_dict=True)
    
    results = {
        "confusion_matrix": cm,
        "classification_report": report
    }
    
    # Calculate ROC curve and AUC if scores are provided
    if y_score is not None:
        # Convert labels to numeric for ROC calculation
        y_true_numeric = np.where(y_true == "normal", 0, 1)
        
        # For decision scores, lower values are more normal in OneClassSVM
        # We need to invert the scores for ROC calculation
        y_score_inverted = -y_score
        
        fpr, tpr, _ = roc_curve(y_true_numeric, y_score_inverted)
        roc_auc = auc(fpr, tpr)
        
        results["roc"] = {
            "fpr": fpr,
            "tpr": tpr,
            "auc": roc_auc
        }
        
        # Precision-Recall curve
        precision, recall, _ = precision_recall_curve(y_true_numeric, y_score_inverted)
        results["pr_curve"] = {
            "precision": precision,
            "recall": recall
        }
    
    return results

def print_evaluation(results):
    """
    Print the evaluation results in a readable format.
    
    Args:
        results: Results dictionary from evaluate_model()
    """
    cm = results["confusion_matrix"]
    report = results["classification_report"]
    
    print("Confusion Matrix:")
    print(f"                 Predicted Normal    Predicted Anomaly")
    print(f"Actual Normal    {cm[0,0]}              {cm[0,1]}")
    print(f"Actual Anomaly   {cm[1,0]}              {cm[1,1]}")
    
    print("\nClassification Report:")
    print(f"              Precision    Recall  F1-Score   Support")
    print(f"Normal         {report['normal']['precision']:.2f}        {report['normal']['recall']:.2f}    {report['normal']['f1-score']:.2f}       {report['normal']['support']}")
    print(f"Anomaly        {report['anomaly']['precision']:.2f}        {report['anomaly']['recall']:.2f}    {report['anomaly']['f1-score']:.2f}       {report['anomaly']['support']}")
    print(f"Accuracy                                   {report['accuracy']:.2f}")
    
    if "roc" in results:
        print(f"\nROC AUC Score: {results['roc']['auc']:.4f}")

def plot_evaluation(results, output_dir=None):
    """
    Plot the evaluation results and save to file if output_dir is provided.
    
    Args:
        results: Results dictionary from evaluate_model()
        output_dir: Directory to save the plots (optional)
    """
    # Create figure with multiple subplots
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    
    # Plot confusion matrix
    cm = results["confusion_matrix"]
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", 
                xticklabels=["Normal", "Anomaly"], 
                yticklabels=["Normal", "Anomaly"],
                ax=axes[0])
    axes[0].set_title("Confusion Matrix")
    axes[0].set_xlabel("Predicted")
    axes[0].set_ylabel("Actual")
    
    # Plot ROC curve if available
    if "roc" in results:
        fpr = results["roc"]["fpr"]
        tpr = results["roc"]["tpr"]
        roc_auc = results["roc"]["auc"]
        
        axes[1].plot(fpr, tpr, color='darkorange', lw=2, 
                  label=f'ROC curve (area = {roc_auc:.2f})')
        axes[1].plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        axes[1].set_xlim([0.0, 1.0])
        axes[1].set_ylim([0.0, 1.05])
        axes[1].set_xlabel('False Positive Rate')
        axes[1].set_ylabel('True Positive Rate')
        axes[1].set_title('Receiver Operating Characteristic')
        axes[1].legend(loc="lower right")
    else:
        axes[1].text(0.5, 0.5, "ROC curve not available", 
                  horizontalalignment='center', verticalalignment='center')
    
    # Plot Precision-Recall curve if available
    if "pr_curve" in results:
        precision = results["pr_curve"]["precision"]
        recall = results["pr_curve"]["recall"]
        
        axes[2].plot(recall, precision, color='green', lw=2)
        axes[2].set_xlim([0.0, 1.0])
        axes[2].set_ylim([0.0, 1.05])
        axes[2].set_xlabel('Recall')
        axes[2].set_ylabel('Precision')
        axes[2].set_title('Precision-Recall Curve')
    else:
        axes[2].text(0.5, 0.5, "PR curve not available", 
                  horizontalalignment='center', verticalalignment='center')
    
    plt.tight_layout()
    
    # Save to file if output_dir is provided
    if output_dir:
        import os
        os.makedirs(output_dir, exist_ok=True)
        plt.savefig(os.path.join(output_dir, "evaluation_plots.png"), dpi=300, bbox_inches="tight")
        print(f"Saved evaluation plots to {os.path.join(output_dir, 'evaluation_plots.png')}")
    
    plt.show()

def analyze_attack_types(y_true, y_pred, original_labels):
    """
    Analyze detection performance across different attack types.
    
    Args:
        y_true: Binary true labels (normal/anomaly)
        y_pred: Binary predicted labels (normal/anomaly)
        original_labels: Original multi-class labels
        
    Returns:
        attack_type_analysis: DataFrame with detection rates by attack type
    """
    results = []
    
    # Create a DataFrame with all relevant information
    df = pd.DataFrame({
        'true_binary': y_true,
        'pred_binary': y_pred,
        'original_label': original_labels
    })
    
    # Get unique attack types
    attack_types = np.unique(original_labels)
    
    # Analyze each attack type
    for attack_type in attack_types:
        attack_subset = df[df['original_label'] == attack_type]
        
        total = len(attack_subset)
        correct = sum(attack_subset['true_binary'] == attack_subset['pred_binary'])
        detection_rate = correct / total if total > 0 else 0
        
        results.append({
            'attack_type': attack_type,
            'total_samples': total,
            'correctly_classified': correct,
            'detection_rate': detection_rate
        })
    
    # Convert to DataFrame and sort by detection rate
    attack_type_analysis = pd.DataFrame(results)
    attack_type_analysis = attack_type_analysis.sort_values('detection_rate', ascending=False)
    
    return attack_type_analysis

def plot_attack_type_analysis(attack_type_analysis, output_dir=None):
    """
    Plot the detection rates across different attack types.
    
    Args:
        attack_type_analysis: DataFrame from analyze_attack_types()
        output_dir: Directory to save the plot (optional)
    """
    plt.figure(figsize=(12, 8))
    
    # Filter to include only attack types with a minimum number of samples
    min_samples = 10
    filtered_analysis = attack_type_analysis[attack_type_analysis['total_samples'] >= min_samples]
    
    # Sort by detection rate
    filtered_analysis = filtered_analysis.sort_values('detection_rate')
    
    # Plot horizontal bar chart
    bars = plt.barh(filtered_analysis['attack_type'], filtered_analysis['detection_rate'], color='skyblue')
    
    # Add the detection rate values at the end of each bar
    for i, bar in enumerate(bars):
        width = bar.get_width()
        label_position = width + 0.02
        plt.text(label_position, bar.get_y() + bar.get_height()/2, 
                f'{width:.2f} ({filtered_analysis.iloc[i]["total_samples"]} samples)',
                va='center')
    
    plt.xlabel('Detection Rate')
    plt.ylabel('Attack Type')
    plt.title('Detection Rate by Attack Type (with sample counts)')
    plt.grid(axis='x', linestyle='--', alpha=0.7)
    plt.xlim(0, 1.1)  # Set x-axis limit from 0 to 1.1 to accommodate text
    
    plt.tight_layout()
    
    # Save to file if output_dir is provided
    if output_dir:
        import os
        os.makedirs(output_dir, exist_ok=True)
        plt.savefig(os.path.join(output_dir, "attack_type_analysis.png"), dpi=300, bbox_inches="tight")
        print(f"Saved attack type analysis plot to {os.path.join(output_dir, 'attack_type_analysis.png')}")
    
    plt.show()