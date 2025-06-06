import streamlit as st

def setup_sidebar_navigation():
    """Setup sidebar navigation and return selected option."""
    st.sidebar.title("🔧 MantaGuard Features")
    
    # Use the stored selection as the default value for the radio button
    options = ["Home", "Scanning", "Reports", "Fix & Patches"]
    index = options.index(st.session_state.current_selection) if st.session_state.current_selection in options else 0
    selected_option = st.sidebar.radio(
        "Navigate to:",
        options,
        index=index
    )
    
    return selected_option

def handle_navigation_change(selected_option, needs_rerun):
    """Handle navigation changes and determine if rerun is needed."""
    # Always force a rerun for Reports, Vulnerabilities, and Fix & Patches to ensure proper page switching
    if selected_option in ["Reports", "Vulnerabilities", "Fix & Patches"]:
        st.session_state.current_selection = selected_option
        # Only rerun if we haven't already scheduled a rerun and if the selection has changed
        if not needs_rerun and st.session_state.previous_selection != selected_option:
            st.session_state.previous_selection = selected_option
            st.rerun()

    # Check if the selection has changed for other options
    if st.session_state.previous_selection != selected_option:
        st.session_state.previous_selection = selected_option
        st.session_state.current_selection = selected_option
        # Force a rerun to refresh the page when selection changes
        st.rerun()