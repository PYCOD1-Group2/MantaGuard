from sklearn.svm import OneClassSVM
import joblib
import os

class AnomalyDetector:
    """
    One-Class SVM based anomaly detector for network traffic
    """
    
    def __init__(self, kernel='rbf', nu=0.01, gamma='scale'):
        """
        Initialize the One-Class SVM model.
        
        Args:
            kernel: Kernel type ('rbf', 'linear', 'poly', 'sigmoid')
            nu: An upper bound on the fraction of training errors and a lower bound 
                on the fraction of support vectors. Should be in the range (0, 1]
            gamma: Kernel coefficient for 'rbf', 'poly' and 'sigmoid'
        """
        self.model = OneClassSVM(kernel=kernel, nu=nu, gamma=gamma)
        self.kernel = kernel
        self.nu = nu
        self.gamma = gamma
        
    def train(self, X_normal_scaled):
        """
        Train the model on the scaled normal data.
        
        Args:
            X_normal_scaled: Scaled normal training data
        """
        print(f"Training One-Class SVM with nu={self.nu}, gamma={self.gamma}, kernel={self.kernel}")
        self.model.fit(X_normal_scaled)
        print("Training completed!")
        
    def predict(self, X_test_scaled):
        """
        Predict on test data.
        
        Args:
            X_test_scaled: Scaled test data
            
        Returns:
            predictions: 1 for normal, -1 for anomaly
        """
        return self.model.predict(X_test_scaled)
    
    def decision_function(self, X_test_scaled):
        """
        Get decision scores for custom thresholding.
        
        Args:
            X_test_scaled: Scaled test data
            
        Returns:
            decision_scores: The distance of each sample from the decision boundary
        """
        return self.model.decision_function(X_test_scaled)
    
    def save_model(self, model_dir):
        """
        Save the trained model and its parameters.
        
        Args:
            model_dir: Directory to save the model
        """
        os.makedirs(model_dir, exist_ok=True)
        
        # Save the model
        model_path = os.path.join(model_dir, "ocsvm_model.pkl")
        joblib.dump(self.model, model_path)
        
        # Save model parameters
        params = {
            "kernel": self.kernel,
            "nu": self.nu,
            "gamma": self.gamma
        }
        
        params_path = os.path.join(model_dir, "model_params.pkl")
        joblib.dump(params, params_path)
        
        print(f"Model saved to {model_path}")
        print(f"Parameters saved to {params_path}")
        
    @classmethod
    def load_model(cls, model_dir):
        """
        Load a saved model.
        
        Args:
            model_dir: Directory containing the saved model
            
        Returns:
            detector: Loaded AnomalyDetector object
        """
        model_path = os.path.join(model_dir, "ocsvm_model.pkl")
        params_path = os.path.join(model_dir, "model_params.pkl")
        
        if not os.path.exists(model_path) or not os.path.exists(params_path):
            raise FileNotFoundError(f"Model files not found in {model_dir}")
        
        # Load model parameters
        params = joblib.load(params_path)
        
        # Create a new instance with the saved parameters
        detector = cls(kernel=params["kernel"], nu=params["nu"], gamma=params["gamma"])
        
        # Load the model
        detector.model = joblib.load(model_path)
        
        print(f"Model loaded from {model_path}")
        return detector