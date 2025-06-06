import base64
import os
import streamlit as st

def get_base64_of_bin_file(bin_file):
    """Convert binary file to base64 string."""
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()

def setup_page_config():
    """Configure Streamlit page settings."""
    st.set_page_config(
        page_title='MANTAGUARD',
        page_icon='https://raw.githubusercontent.com/aaron789746/MANTAGUARD/main/MANTAGUAD.png',
    )

def ensure_directories():
    """Ensure required directories exist."""
    analysis_results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                      "ai-model", "output", "analysis_results")
    os.makedirs(analysis_results_dir, exist_ok=True)
    return analysis_results_dir