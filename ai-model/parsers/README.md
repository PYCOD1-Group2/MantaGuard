# Zeek Log Parser

This directory contains parsers for various log formats used in network security monitoring.

## zeek_loader.py

A module for loading Zeek log files into pandas DataFrames for analysis.

### Functions

#### `load_conn_log(path)`

Loads a Zeek conn.log file into a pandas DataFrame.

**Arguments:**
- `path` (str): Path to the Zeek conn.log file

**Returns:**
- `pandas.DataFrame`: DataFrame containing the conn.log data with selected columns

**Raises:**
- `FileNotFoundError`: If the specified path does not exist
- `ValueError`: If column names cannot be found in the file

**Features:**
- Automatically extracts column names from the `#fields` header line
- Skips comment lines (lines starting with `#`)
- Converts the `ts` column to pandas datetime in UTC
- Returns only the following columns:
  - `ts`: Timestamp of the connection
  - `proto`: Transport protocol
  - `service`: Application protocol
  - `duration`: Connection duration
  - `orig_bytes`: Bytes sent by the originator
  - `resp_bytes`: Bytes sent by the responder
  - `orig_pkts`: Packets sent by the originator
  - `resp_pkts`: Packets sent by the responder
  - `history`: Connection state history
  - `uid`: Unique identifier for the connection

#### `zeek_to_features(df)`

Converts a Zeek DataFrame into an ML-ready numeric numpy array.

**Arguments:**
- `df` (pandas.DataFrame): DataFrame containing Zeek log data

**Returns:**
- `tuple`: (X, encoders) where:
  - `X` (numpy.ndarray): Feature matrix as float64
  - `encoders` (dict): Dictionary mapping column names to their encoding dictionaries for categorical columns

**Features:**
- Handles categorical columns ("proto", "service", "history") with LabelEncoder-style mapping
- Keeps numeric columns as float64
- Fills missing values in categorical columns with "unknown"
- Creates a mapping dictionary for each categorical column
- Returns both the feature matrix and the encoders for later use

### Example Usage

```python
from parsers.zeek_loader import load_conn_log, zeek_to_features
import numpy as np

# Load a Zeek conn.log file
df = load_conn_log('path/to/conn.log')

# Display the first few rows
print(df.head())

# Get basic statistics
print(df.describe())

# Filter connections by protocol
tcp_conns = df[df['proto'] == 'tcp']

# Convert to ML-ready features
X, encoders = zeek_to_features(df)

# Now X can be used for machine learning
print(f"Feature matrix shape: {X.shape}")

# Save encoders for later use (e.g., for encoding new data)
import pickle
with open('zeek_encoders.pkl', 'wb') as f:
    pickle.dump(encoders, f)

# Example: Apply the same encoding to new data
def encode_new_data(new_df, encoders):
    # Make a copy of the dataframe
    df_copy = new_df.copy()

    # Apply encodings to categorical columns
    for col, mapping in encoders.items():
        if col in df_copy.columns and isinstance(mapping, dict) and not mapping.get('column_missing', False):
            # Fill NaN values
            df_copy[col] = df_copy[col].fillna('unknown')

            # Apply mapping (with default for unseen values)
            df_copy[col] = df_copy[col].map(lambda x: mapping.get(x, -1))

    # Return the encoded dataframe
    return df_copy
```

### Sample Zeek conn.log Format

Zeek conn.log files typically have the following format:

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	...
#types	time	string	addr	port	addr	port	enum	string	...
1672531200.000000	CXWfMc4eWKNl5EqQ7h	192.168.1.100	49152	93.184.216.34	80	tcp	http	...
...
```

A sample conn.log file is provided in `data/sample_conn.log` for testing purposes.
