import base64
import os

def get_base64_of_bin_file(bin_file):
    """Convert binary file to base64 string."""
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()

def ensure_directories():
    """Ensure required directories exist."""
    analysis_results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                      "ai-model", "output", "analysis_results")
    os.makedirs(analysis_results_dir, exist_ok=True)
    return analysis_results_dir