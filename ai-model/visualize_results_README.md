# Visualization Tool for Anomaly Detection Results

This tool generates visualizations from anomaly detection prediction results on Zeek conn.log data.

## Overview

The `visualize_results.py` script takes a CSV file containing prediction results and generates the following visualizations:

1. **Histogram of decision function scores** - Shows the distribution of anomaly scores
2. **ROC curve** - Receiver Operating Characteristic curve (if ground truth labels are present)
3. **Precision-Recall curve** - Shows precision vs. recall tradeoff (if ground truth labels are present)
4. **Confusion matrix** - Shows true positives, false positives, etc. (if ground truth labels are present)
5. **Time series of anomalies** - Shows anomaly scores over time with color-coded points

## Requirements

- Python 3.6+
- pandas
- numpy
- matplotlib
- seaborn
- scikit-learn

## Usage

```bash
python visualize_results.py <input_csv> <output_dir> [--title-prefix PREFIX]
```

### Arguments

- `input_csv`: Path to the CSV file with prediction results
- `output_dir`: Directory to save visualization images
- `--title-prefix`: (Optional) Prefix for chart titles

### Input CSV Format

The input CSV file must contain the following columns:
- `uid`: Unique identifier for each connection
- `timestamp`: Timestamp of the connection
- `score`: Decision function score from the model
- `prediction`: Prediction label ("normal" or "anomaly")

Optional column:
- `true_label`: Ground truth label ("normal" or "anomaly") - enables additional visualizations

## Integration with Analysis Workflow

The visualization tool is automatically called at the end of an analysis when using:
- `analyze_capture.py` - For analyzing existing PCAP files
- `timed_capture.py` - For capturing and analyzing live network traffic

The results and visualizations are saved to a timestamped directory under `output/analysis_results/`.

## Testing

You can test the visualization tool with sample data using:

```bash
python test_visualize_results.py
```

This will generate sample data with and without ground truth labels, run the visualization script on both datasets, and save the results to `output/test_visualizations/`.

## Example Visualizations

### Histogram of Decision Function Scores
Shows the distribution of anomaly scores with a vertical line indicating the decision boundary.

### ROC Curve
Shows the tradeoff between true positive rate and false positive rate at different threshold settings.

### Precision-Recall Curve
Shows the tradeoff between precision and recall at different threshold settings.

### Confusion Matrix
Shows the number of true positives, false positives, true negatives, and false negatives.

### Time Series of Anomalies
Shows anomaly scores over time with points color-coded by prediction (blue for normal, red for anomaly).