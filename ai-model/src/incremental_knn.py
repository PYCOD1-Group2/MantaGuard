import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import os
import joblib
import pickle
from datetime import datetime

class IncrementalKNN:
    """
    Incremental K-Nearest Neighbors classifier for network traffic anomaly detection.

    This model trains only on normal traffic initially, then learns from user feedback
    for continuous improvement without retraining.
    """

    def __init__(self, k=5, distance_threshold=2.5):
        """Initialize the Incremental KNN classifier."""
        # Core data structures
        self.global_features = np.array([])  # Scaled feature vectors
        self.global_labels = np.array([])    # Corresponding labels

        # Model parameters
        self.k = k
        self.distance_threshold = distance_threshold

        # Feature scaling
        self.scaler = None
        self.scaler_initialized = False

        # Stats tracking
        self.stats = {
            "normal_samples": 0,
            "labeled_threats": {},
            "last_update": None
        }

    def load_existing_model(self, model_dir):
        """
        Load existing scaler and preprocessors from a previously trained model.
        This allows the KNN model to use the same scaling as the base model.
        """
        scaler_path = os.path.join(model_dir, "scaler.pkl")
        if os.path.exists(scaler_path):
            print(f"Loading scaler from {scaler_path}")
            self.scaler = joblib.load(scaler_path)
            self.scaler_initialized = True
            return True
        else:
            print(f"Scaler not found at {scaler_path}")
            return False

    def load_normal_data(self, data_path):
        """Load normal traffic data from a file and initialize the model memory."""
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Data file not found: {data_path}")

        print(f"Loading normal data from {data_path}...")

        # Load the data
        df = pd.read_csv(data_path)

        # Ensure we have only normal traffic
        if 'label' in df.columns:
            if not all(df['label'].str.lower() == 'normal'):
                print("Filtering to include only normal traffic...")
                df = df[df['label'].str.lower() == 'normal']

        # Extract features and labels
        label_column = None
        for col in ['label', 'class', 'attack_type']:
            if col in df.columns:
                label_column = col
                break

        if label_column:
            y = df[label_column].values
            X_df = df.drop(label_column, axis=1)
        else:
            # If no label column found, assume all samples are normal
            y = np.array(['normal'] * len(df))
            X_df = df

        # Check for "difficulty" column and remove it if present (often in NSL-KDD)
        if 'difficulty' in X_df.columns:
            print("Removing 'difficulty' column")
            X_df = X_df.drop('difficulty', axis=1)

        # Use the same categorical encoding as in data_loader.py
        categorical_cols = ["protocol_type", "service", "flag"]
        for cat_col in categorical_cols:
            if cat_col in X_df.columns and X_df[cat_col].dtype == 'object':
                print(f"Encoding categorical column: {cat_col}")
                from sklearn.preprocessing import LabelEncoder
                encoder = LabelEncoder()
                X_df[cat_col] = encoder.fit_transform(X_df[cat_col])

        # Convert remaining non-numeric columns
        for col in X_df.columns:
            if X_df[col].dtype == 'object':
                print(f"Converting non-numeric column {col} to numeric")
                X_df[col] = pd.to_numeric(X_df[col], errors='coerce')

        # Fill NaN values with 0
        X_df.fillna(0, inplace=True)

        # Print feature count for debugging
        print(f"Feature count after preprocessing: {X_df.shape[1]}")

        # If using existing scaler, check for feature count mismatch and handle it
        if self.scaler_initialized:
            # Get expected feature count from scaler
            expected_features = self.scaler.n_features_in_
            current_features = X_df.shape[1]

            print(f"Scaler expects {expected_features} features, data has {current_features} features")

            if expected_features != current_features:
                print("WARNING: Feature count mismatch. Attempting to fix...")

                if current_features > expected_features:
                    # We have too many features, need to drop one
                    print(f"Too many features. Dropping feature(s) to match expected count.")
                    # Calculate how many extra features we have
                    extra_features = current_features - expected_features
                    # Sort columns by name for deterministic behavior
                    columns = sorted(X_df.columns)
                    # Drop the last N columns to match expected feature count
                    for i in range(extra_features):
                        col_to_drop = columns[-(i+1)]
                        print(f"Dropping column: {col_to_drop}")
                        X_df = X_df.drop(col_to_drop, axis=1)
                else:
                    # We have too few features, can't fix this automatically
                    print("ERROR: Not enough features in data. Cannot fix automatically.")
                    print("Consider creating a new scaler with --create-new-scaler")
                    raise ValueError(f"Feature count mismatch: Scaler expects {expected_features} features, but data has {current_features}")

        # Convert to numpy array
        X = X_df.values

        # Initialize scaler if needed
        if not self.scaler_initialized:
            print("Initializing new scaler...")
            self.scaler = StandardScaler()
            self.scaler.fit(X)
            self.scaler_initialized = True

        # Scale the features
        X_scaled = self.scaler.transform(X)

        # Store in memory
        if len(self.global_features) == 0:
            self.global_features = X_scaled
            self.global_labels = y
        else:
            self.global_features = np.vstack((self.global_features, X_scaled))
            self.global_labels = np.concatenate((self.global_labels, y))

        # Update stats
        self.stats["normal_samples"] += len(X)
        self.stats["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"Loaded {len(X)} normal samples into memory")
        return len(X)

    def classify_packet_knn(self, packet_features, k=None, distance_threshold=None):
        """
        Classify a single packet using lazy KNN with stored data.

        Returns:
            tuple: (predicted_label, average_distance_to_neighbors)
        """
        if k is None:
            k = self.k
        if distance_threshold is None:
            distance_threshold = self.distance_threshold

        if len(self.global_features) == 0:
            return "Unknown", None

        # Calculate distances to all stored points
        distances = np.linalg.norm(self.global_features - packet_features, axis=1)

        # Pair distances with labels
        dist_label_pairs = list(zip(distances, self.global_labels))

        # Sort by distance (ascending)
        dist_label_pairs.sort(key=lambda x: x[0])

        # Get k nearest neighbors
        nearest_neighbors = dist_label_pairs[:k]

        # Calculate average distance to k nearest neighbors
        avg_distance = np.mean([pair[0] for pair in nearest_neighbors])

        # Check if it's an anomaly based on distance threshold
        if avg_distance > distance_threshold:
            return "Anomaly", avg_distance
        else:
            # Majority vote for classification
            label_counts = {}
            for _, label in nearest_neighbors:
                label_counts[label] = label_counts.get(label, 0) + 1

            predicted_label = max(label_counts, key=label_counts.get)
            return predicted_label, avg_distance

    def handle_new_packet(self, packet_features_raw):
        """
        Process a new packet:
        1. Scale the features
        2. Classify using KNN
        3. If anomaly, get user feedback and update memory
        """
        if not self.scaler_initialized:
            return "Unknown"

        # Scale the input features
        packet_features_scaled = self.scaler.transform([packet_features_raw])[0]

        # Classify
        predicted_label, avg_dist = self.classify_packet_knn(packet_features_scaled)

        if predicted_label == "Anomaly":
            print(f"[!] Detected Anomaly (avg dist = {avg_dist:.2f}). Please label this threat.")
            user_label = input("Enter label (e.g., 'DDoS', 'PortScan', 'Normal'): ")

            # Update memory with the new labeled sample
            if len(self.global_features) == 0:
                self.global_features = np.array([packet_features_scaled])
                self.global_labels = np.array([user_label])
            else:
                self.global_features = np.vstack((self.global_features, packet_features_scaled))
                self.global_labels = np.append(self.global_labels, user_label)

            # Update stats
            if user_label.lower() == 'normal':
                self.stats["normal_samples"] += 1
            else:
                self.stats["labeled_threats"][user_label] = self.stats["labeled_threats"].get(user_label, 0) + 1

            self.stats["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            print(f"-> Added new {user_label} sample to memory. Future similar packets will be auto-labeled.")
            return user_label
        else:
            print(f"[+] Predicted: {predicted_label} (avg dist = {avg_dist:.2f})")
            return predicted_label

    def predict(self, X):
        """
        Predict labels for multiple samples (compatible with scikit-learn interface).
        Returns 1 for normal, -1 for anomaly (matching One-Class SVM convention).
        """
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        predictions = []
        for sample in X:
            label, _ = self.classify_packet_knn(sample)
            # Convert string labels to numeric (-1 for anomaly, 1 for normal)
            pred = 1 if label.lower() == 'normal' else -1
            predictions.append(pred)

        return np.array(predictions)

    def decision_function(self, X):
        """
        Calculate decision scores (negative distance) for compatibility with evaluation.
        """
        if len(X.shape) == 1:
            X = X.reshape(1, -1)

        scores = []
        for sample in X:
            _, distance = self.classify_packet_knn(sample)
            # Negative distance as decision score (higher = more normal)
            scores.append(-distance)

        return np.array(scores)

    def store_sample(self, feature_vector, label='normal'):
        """
        Store a new sample in the model's memory.

        Parameters:
        -----------
        feature_vector : numpy.ndarray
            The feature vector to store
        label : str, default='normal'
            The label for this sample
        """
        # Ensure feature_vector is a numpy array
        if not isinstance(feature_vector, np.ndarray):
            feature_vector = np.array(feature_vector)

        # Reshape if needed
        if len(feature_vector.shape) == 1:
            feature_vector = feature_vector.reshape(1, -1)

        # Add to memory
        if len(self.global_features) == 0:
            self.global_features = feature_vector
            self.global_labels = np.array([label])
        else:
            self.global_features = np.vstack((self.global_features, feature_vector))
            self.global_labels = np.append(self.global_labels, label)

        # Update stats
        if label.lower() == 'normal':
            self.stats["normal_samples"] += 1
        else:
            self.stats["labeled_threats"][label] = self.stats["labeled_threats"].get(label, 0) + 1

        self.stats["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def save_model(self, output_dir):
        """Save the current model state to disk."""
        os.makedirs(output_dir, exist_ok=True)

        # Save model parameters
        model_data = {
            "k": self.k,
            "distance_threshold": self.distance_threshold,
            "stats": self.stats,
            "scaler_initialized": self.scaler_initialized  # Add this line
        }

        joblib.dump(model_data, os.path.join(output_dir, "knn_params.pkl"))

        # Save scaler
        if self.scaler_initialized:
            joblib.dump(self.scaler, os.path.join(output_dir, "knn_scaler.pkl"))

        # Save memory (features and labels)
        if len(self.global_features) > 0:
            np.save(os.path.join(output_dir, "knn_features.npy"), self.global_features)
            # No special settings needed for saving
            np.save(os.path.join(output_dir, "knn_labels.npy"), self.global_labels)

        print(f"Model saved to {output_dir}")

    @classmethod
    def load_model(cls, model_dir):
        """
        Load a saved model from disk.

        Parameters:
        -----------
        model_dir : str
            Directory containing saved model files

        Returns:
        --------
        IncrementalKNN
            Loaded model instance
        """
        # Load parameters
        with open(os.path.join(model_dir, "knn_params.pkl"), "rb") as f:
            params = pickle.load(f)

        # Create new instance
        model = cls(k=params["k"], distance_threshold=params["distance_threshold"])
        model.stats = params["stats"]

        # Handle missing 'scaler_initialized' parameter in older saved models
        if "scaler_initialized" in params:
            model.scaler_initialized = params["scaler_initialized"]
        else:
            # Assume scaler is initialized if scaler file exists
            scaler_path = os.path.join(model_dir, "knn_scaler.pkl")
            model.scaler_initialized = os.path.exists(scaler_path)

        # Load scaler if available
        if model.scaler_initialized:
            model.scaler = joblib.load(os.path.join(model_dir, "knn_scaler.pkl"))

        # Load features and labels if available
        features_path = os.path.join(model_dir, "knn_features.npy")
        labels_path = os.path.join(model_dir, "knn_labels.npy")

        if os.path.exists(features_path) and os.path.exists(labels_path):
            model.global_features = np.load(features_path)
            # Add allow_pickle=True to load string labels
            model.global_labels = np.load(labels_path, allow_pickle=True)

        print(f"Model loaded from {model_dir}")
        print(f"Memory contains {len(model.global_labels)} samples")

        return model
