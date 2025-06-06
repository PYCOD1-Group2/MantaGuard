import sys
import os

# Add the current directory to the Python path so we can import from src
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.utils.config import setup_page_config, ensure_directories
from src.utils.session_state import initialize_session_state, process_state_updates, process_error_messages
from src.utils.navigation import setup_sidebar_navigation, handle_navigation_change
from src.pages.home_page import render_home_page
from src.pages.scanning_page import render_scanning_page
from src.pages.reports_page import render_reports_page
from src.pages.fix_patches_page import render_fix_patches_page

import streamlit as st

def main():
    """Main application entry point."""
    # Setup page configuration
    setup_page_config()
    
    # Ensure required directories exist
    ensure_directories()
    
    # Initialize session state variables
    initialize_session_state()
    
    # Process any pending state updates from threads
    needs_rerun = process_state_updates()
    
    # Process any pending error messages from threads
    process_error_messages()
    
    # Rerun the app if needed
    if needs_rerun:
        st.rerun()
    
    # Setup sidebar navigation
    selected_option = setup_sidebar_navigation()
    
    # Handle navigation changes
    handle_navigation_change(selected_option, needs_rerun)
    
    # Render the selected page
    if selected_option == "Home":
        render_home_page()
    elif selected_option == "Scanning":
        render_scanning_page()
    elif selected_option == "Reports":
        render_reports_page()
    elif selected_option == "Fix & Patches":
        render_fix_patches_page()

if __name__ == "__main__":
    main()