#!/usr/bin/env python3
"""
Zeek log file parser for MantaGuard.

Module for loading Zeek log files into pandas DataFrames and converting
them to ML-ready feature matrices.
"""

import os
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Tuple, Dict, Optional, List, Set, Union

from mantaguard.utils.logger import get_logger

logger = get_logger(__name__)


def load_conn_log(path: str) -> pd.DataFrame:
    """
    Load a Zeek conn.log file into a pandas DataFrame.

    Args:
        path: Path to the Zeek conn.log file

    Returns:
        DataFrame containing the conn.log data with selected columns

    Raises:
        FileNotFoundError: If the specified path does not exist
        ValueError: If column names cannot be found in the file
    """
    # Check if file exists
    if not os.path.isfile(path):
        logger.error(f"Zeek conn.log file not found: {path}")
        raise FileNotFoundError(f"File not found: {path}")

    # Read the file to extract column names from the header
    column_names = None
    try:
        with open(path, 'r') as f:
            for line in f:
                if line.startswith('#fields'):
                    # Extract column names from the #fields line
                    column_names = line.strip().split('\t')[1:]
                    break
    except Exception as e:
        logger.error(f"Error reading Zeek file header {path}: {e}")
        raise

    if column_names is None:
        logger.error(f"Could not find column names in Zeek file: {path}")
        raise ValueError(f"Could not find column names in file: {path}")

    # Read the data, skipping comment lines
    try:
        df = pd.read_csv(
            path, 
            sep='\t',
            comment='#',
            names=column_names,
            na_values='-',  # Zeek often uses '-' for missing values
            low_memory=False
        )
        logger.debug(f"Loaded Zeek conn.log with {len(df)} rows and {len(df.columns)} columns")
    except Exception as e:
        logger.error(f"Error reading Zeek data from {path}: {e}")
        raise

    # Convert ts column to datetime in UTC
    if 'ts' in df.columns:
        try:
            df['ts'] = pd.to_datetime(df['ts'], unit='s', utc=True)
        except Exception as e:
            logger.warning(f"Could not convert timestamp column: {e}")

    # Select only the required columns if they exist
    required_columns = [
        "ts", "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "orig_pkts", "resp_pkts", "history", "uid"
    ]

    # Check which required columns are present in the dataframe
    available_columns = [col for col in required_columns if col in df.columns]

    # If any required columns are missing, warn but continue
    missing_columns = set(required_columns) - set(available_columns)
    if missing_columns:
        logger.warning(f"Missing required columns in {path}: {missing_columns}")

    # Return dataframe with available required columns
    return df[available_columns]


def zeek_to_features(
    df: pd.DataFrame, 
    pre_trained_encoders: Optional[Dict] = None
) -> Tuple[np.ndarray, Dict, Dict[str, List]]:
    """
    Convert a Zeek DataFrame into an ML-ready numeric numpy array.

    Args:
        df: DataFrame containing Zeek log data
        pre_trained_encoders: Pre-trained encoders from training phase.
                             If provided, these will be used instead of
                             creating new encoders.

    Returns:
        Tuple containing:
            - X: Feature matrix as float64 numpy array
            - encoders: Dictionary mapping column names to their encoding dictionaries
                       for categorical columns
            - unknown_values: Dictionary mapping column names to lists of unknown 
                            categorical values not found in pre_trained_encoders
    """
    # Make a copy of the dataframe to avoid modifying the original
    df_copy = df.copy()
    logger.debug(f"Converting Zeek DataFrame to features: {len(df_copy)} rows")

    # Define categorical columns
    categorical_columns = ["proto", "service", "history"]

    # Initialize encoders dictionary
    encoders = pre_trained_encoders.copy() if pre_trained_encoders else {}

    # Initialize dictionary to track unknown values
    unknown_values = {col: set() for col in categorical_columns}

    # Process categorical columns
    for col in categorical_columns:
        if col in df_copy.columns:
            # Fill NaN values with a placeholder
            df_copy[col] = df_copy[col].fillna('unknown')

            if (pre_trained_encoders and col in pre_trained_encoders and 
                not pre_trained_encoders[col].get('column_missing', False)):
                # Use pre-trained encoder
                mapping = pre_trained_encoders[col]

                # Check for new/unseen categorical values
                unique_values = set(df_copy[col].unique())
                known_values = set(mapping.keys())
                unknown_values_col = unique_values - known_values

                # If unknown values are found, add them to the unknown_values dictionary
                if unknown_values_col:
                    unknown_values[col].update(unknown_values_col)
                    logger.warning(f"New categorical values found in column '{col}': {unknown_values_col}. "
                                 f"These values will be encoded as -1.")

                # Apply the mapping to the column, with -1 for unknown values
                df_copy[col] = df_copy[col].apply(lambda x: mapping.get(x, -1))
            else:
                # Create new mapping if no pre-trained encoder or column was missing during training
                unique_values = df_copy[col].unique()
                mapping = {value: idx for idx, value in enumerate(unique_values)}

                # Store the mapping in encoders
                encoders[col] = mapping
                logger.debug(f"Created new encoder for column '{col}' with {len(mapping)} categories")

                # Apply the mapping to the column
                df_copy[col] = df_copy[col].map(mapping)
        else:
            # If column doesn't exist, note it in encoders
            encoders[col] = {'column_missing': True}
            logger.warning(f"Column '{col}' missing from DataFrame")

    # Process numeric columns (all non-categorical columns except timestamp columns, 'uid', label columns, and feature_vector)
    non_numeric_columns = categorical_columns + ['ts', 'timestamp', 'uid', 'original_label', 'user_label', 'feature_vector']
    numeric_columns = [col for col in df_copy.columns if col not in non_numeric_columns]

    # Ensure numeric columns are float64
    for col in numeric_columns:
        try:
            df_copy[col] = df_copy[col].astype(np.float64)
        except Exception as e:
            logger.warning(f"Could not convert column '{col}' to float64: {e}")

    # Combine categorical and numeric columns
    feature_columns = [col for col in categorical_columns if col in df_copy.columns] + numeric_columns

    # Convert to numpy array
    try:
        X = df_copy[feature_columns].to_numpy(dtype=np.float64)
        logger.debug(f"Created feature matrix: shape {X.shape}")
    except Exception as e:
        logger.error(f"Error creating feature matrix: {e}")
        raise

    # Convert sets to lists for easier serialization
    unknown_values_list = {col: list(values) for col, values in unknown_values.items()}

    return X, encoders, unknown_values_list