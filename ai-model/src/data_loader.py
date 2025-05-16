import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os

def download_nslkdd():
    """
    Function to guide downloading the NSL-KDD dataset.
    """
    print("Please download NSL-KDD dataset from the official website:")
    print("https://www.unb.ca/cic/datasets/nsl.html")
    print("Place KDDTrain+.txt and KDDTest+.txt in the data/ directory")

def get_column_names():
    """
    Return the column names for the NSL-KDD dataset.
    """
    # The original NSL-KDD column names
    col_names = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
        "num_compromised", "root_shell", "su_attempted", "num_root", 
        "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
        "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
    ]
    return col_names

def detect_file_format(file_path):
    """
    Detect if the file is in the original NSL-KDD format or a CSV with headers.
    Returns whether the file has headers and the column name for the label.
    """
    with open(file_path, 'r') as f:
        first_line = f.readline().strip()
    
    # Check if the first line looks like headers
    if ',' in first_line and 'duration' in first_line.lower():
        # This is a CSV with headers
        has_headers = True
        # Check if 'class' or 'label' is in the headers
        if 'class' in first_line.lower():
            label_column = 'class'
        else:
            label_column = 'label'
    else:
        # This is the original NSL-KDD format without headers
        has_headers = False
        label_column = 'label'
    
    return has_headers, label_column

def load_and_preprocess_data(train_path, test_path, save_normal=True):
    """
    Load and preprocess NSL-KDD dataset.
    
    Args:
        train_path: Path to KDDTrain+.txt or KDDTrain.csv
        test_path: Path to KDDTest+.txt or KDDTest.csv
        save_normal: Whether to save the normal subset to CSV
        
    Returns:
        X_normal_scaled: Scaled normal training data
        X_test_scaled: Scaled test data
        y_test: Test labels
        scaler: Fitted StandardScaler
        categorical_encoders: Dictionary of fitted LabelEncoders
    """
    # Check if files exist
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        download_nslkdd()
        raise FileNotFoundError(f"NSL-KDD dataset files not found at {train_path} or {test_path}")
    
    # Detect file format
    train_has_headers, train_label_column = detect_file_format(train_path)
    test_has_headers, test_label_column = detect_file_format(test_path)
    
    # Get the column names
    col_names = get_column_names()
    
    # Load training data
    print(f"Loading training data from {train_path}...")
    if train_has_headers:
        df_train = pd.read_csv(train_path)
        # Rename the label column if needed
        if train_label_column != 'label':
            df_train.rename(columns={train_label_column: 'label'}, inplace=True)
    else:
        df_train = pd.read_csv(train_path, header=None, names=col_names)
    
    print(f"Loaded {len(df_train)} training samples")
    
    # Check for label column and print unique labels
    if 'label' not in df_train.columns:
        raise ValueError(f"Label column not found in training data. Available columns: {df_train.columns.tolist()}")
    
    print(f"Training data labels: {df_train['label'].unique()}")
    
    # Filter only normal traffic for training
    df_normal = df_train[df_train["label"] == "normal"]
    print(f"Extracted {len(df_normal)} normal samples from {len(df_train)} total training samples")
    
    if len(df_normal) == 0:
        # If no 'normal' samples found, try other potential forms
        alternative_labels = ['normal.', 'Normal', 'NORMAL']
        for alt_label in alternative_labels:
            if df_train["label"].str.contains(alt_label).any():
                print(f"Found alternative label: {alt_label}")
                df_normal = df_train[df_train["label"].str.contains(alt_label)]
                print(f"Extracted {len(df_normal)} normal samples using alternative label")
                break
    
    # Save normal subset if requested
    if save_normal and len(df_normal) > 0:
        normal_csv_path = os.path.join(os.path.dirname(train_path), 
                                      os.path.basename(train_path).split('.')[0] + '_normal.csv')
        df_normal.to_csv(normal_csv_path, index=False)
        print(f"Saved normal subset to {normal_csv_path}")
    
    # Load test data
    print(f"Loading test data from {test_path}...")
    if test_has_headers:
        df_test = pd.read_csv(test_path)
        # Rename the label column if needed
        if test_label_column != 'label':
            df_test.rename(columns={test_label_column: 'label'}, inplace=True)
    else:
        df_test = pd.read_csv(test_path, header=None, names=col_names)
    
    print(f"Loaded {len(df_test)} test samples")
    print(f"Test data labels: {df_test['label'].unique()}")
    
    # Define feature columns (exclude 'label' and 'difficulty' if present)
    feature_cols = [col for col in df_train.columns if col not in ['label', 'difficulty', 'classnum']]
    
    # Prepare training and test data
    X_normal = df_normal[feature_cols].copy()
    X_test = df_test[feature_cols].copy()
    y_test = df_test["label"].values
    
    # Handle categorical features
    categorical_cols = ["protocol_type", "service", "flag"]
    categorical_encoders = {}
    
    for cat_col in categorical_cols:
        if cat_col in X_normal.columns:
            encoder = LabelEncoder()
            X_normal[cat_col] = encoder.fit_transform(X_normal[cat_col])
            categorical_encoders[cat_col] = encoder
            
            # Transform test data using the same encoder
            # Handle potential unknown categories in test data
            X_test[cat_col] = X_test[cat_col].map(
                lambda x: -1 if x not in encoder.classes_ else encoder.transform([x])[0]
            )
            # Replace any -1 values with most frequent value
            if (X_test[cat_col] == -1).any():
                most_freq = X_normal[cat_col].value_counts().index[0]
                X_test.loc[X_test[cat_col] == -1, cat_col] = most_freq
                print(f"Replaced unknown categories in {cat_col} with most frequent value")
    
    # Convert any remaining non-numeric columns
    for col in X_normal.columns:
        if X_normal[col].dtype == 'object':
            print(f"Converting non-numeric column {col} to numeric")
            X_normal[col] = pd.to_numeric(X_normal[col], errors='coerce')
            X_test[col] = pd.to_numeric(X_test[col], errors='coerce')
    
    # Fill NaN values with 0
    X_normal.fillna(0, inplace=True)
    X_test.fillna(0, inplace=True)
    
    # Scale the features
    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)
    X_test_scaled = scaler.transform(X_test)
    
    return X_normal_scaled, X_test_scaled, y_test, scaler, categorical_encoders

def create_binary_labels(y_test):
    """
    Convert multi-class labels to binary (normal vs anomaly)
    """
    return np.where(np.char.lower(y_test.astype(str)) == "normal", "normal", "anomaly")

def check_dataset_labels(train_path, test_path):
    """
    Check the labels in the dataset to help debugging.
    
    Args:
        train_path: Path to training data
        test_path: Path to test data
    """
    # Detect file format
    train_has_headers, train_label_column = detect_file_format(train_path)
    test_has_headers, test_label_column = detect_file_format(test_path)
    
    # Load training data
    print(f"Checking training data labels in {train_path}...")
    if train_has_headers:
        df_train = pd.read_csv(train_path)
    else:
        df_train = pd.read_csv(train_path, header=None, names=get_column_names())
    
    # Determine label column
    label_col = train_label_column if train_label_column in df_train.columns else 'label'
    if label_col not in df_train.columns and 'class' in df_train.columns:
        label_col = 'class'
    
    # Count labels in training data
    if label_col in df_train.columns:
        train_label_counts = df_train[label_col].value_counts()
        print(f"Labels in training data (column '{label_col}'):")
        print(train_label_counts)
        
        # Check if 'normal' is in labels (case insensitive)
        train_labels_lowercase = df_train[label_col].astype(str).str.lower()
        if 'normal' in train_labels_lowercase.values:
            print("'normal' label found (case-insensitive)")
            normal_variants = df_train.loc[train_labels_lowercase == 'normal', label_col].unique()
            print(f"Actual variants of 'normal' in the data: {normal_variants}")
        else:
            print("'normal' label NOT found (even case-insensitive)")
    else:
        print(f"Label column not found in training data. Available columns: {df_train.columns.tolist()}")
    
    # Load test data
    print(f"\nChecking test data labels in {test_path}...")
    if test_has_headers:
        df_test = pd.read_csv(test_path)
    else:
        df_test = pd.read_csv(test_path, header=None, names=get_column_names())
    
    # Determine label column for test data
    test_label_col = test_label_column if test_label_column in df_test.columns else 'label'
    if test_label_col not in df_test.columns and 'class' in df_test.columns:
        test_label_col = 'class'
    
    # Count labels in test data
    if test_label_col in df_test.columns:
        test_label_counts = df_test[test_label_col].value_counts()
        print(f"Labels in test data (column '{test_label_col}'):")
        print(test_label_counts)
    else:
        print(f"Label column not found in test data. Available columns: {df_test.columns.tolist()}")
    
    # Sample of the data
    print("\nSample of training data (first 5 rows):")
    print(df_train.head())

def check_dataset_labels(train_path, test_path):
    """
    Check the labels in the dataset to help debugging.
    
    Args:
        train_path: Path to training data
        test_path: Path to test data
    """
    # Check if files exist
    if not os.path.exists(train_path):
        print(f"Error: Training file not found at {train_path}")
        return
    if not os.path.exists(test_path):
        print(f"Error: Test file not found at {test_path}")
        return
    
    # Load training data
    print(f"Checking training data labels in {train_path}...")
    try:
        df_train = pd.read_csv(train_path)
        print(f"Training data shape: {df_train.shape}")
        print(f"Training data columns: {df_train.columns.tolist()}")
        
        # Find the label column (could be 'label', 'class', or similar)
        label_col = None
        for col_name in ['class', 'label', 'attack_type', 'attack']:
            if col_name in df_train.columns:
                label_col = col_name
                break
        
        if label_col:
            print(f"Found label column: '{label_col}'")
            train_label_counts = df_train[label_col].value_counts()
            print("Labels in training data:")
            print(train_label_counts)
            
            # Check for normal traffic
            normal_count = 0
            for label in train_label_counts.index:
                if 'normal' in str(label).lower():
                    normal_count += train_label_counts[label]
                    print(f"Found normal traffic with label: '{label}', count: {train_label_counts[label]}")
            
            print(f"Total normal traffic in training data: {normal_count} samples")
        else:
            print("Could not find a label column in the training data.")
    except Exception as e:
        print(f"Error loading training data: {str(e)}")
    
    # Load test data
    print(f"\nChecking test data labels in {test_path}...")
    try:
        df_test = pd.read_csv(test_path)
        print(f"Test data shape: {df_test.shape}")
        print(f"Test data columns: {df_test.columns.tolist()}")
        
        # Find the label column (could be 'label', 'class', or similar)
        label_col = None
        for col_name in ['class', 'label', 'attack_type', 'attack']:
            if col_name in df_test.columns:
                label_col = col_name
                break
        
        if label_col:
            print(f"Found label column: '{label_col}'")
            test_label_counts = df_test[label_col].value_counts()
            print("Labels in test data:")
            print(test_label_counts)
        else:
            print("Could not find a label column in the test data.")
    except Exception as e:
        print(f"Error loading test data: {str(e)}")
    
    # Sample of the data
    print("\nSample of training data (first 5 rows):")
    try:
        print(df_train.head())
    except:
        print("Could not print training data sample.")
