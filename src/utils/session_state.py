import queue
import streamlit as st

def initialize_session_state():
    """Initialize all session state variables used across different sections."""
    
    # Error and state update queues
    if "error_queue" not in st.session_state:
        st.session_state.error_queue = queue.Queue()
    if "state_updates" not in st.session_state:
        st.session_state.state_updates = queue.Queue()
    
    # Navigation state
    if "previous_selection" not in st.session_state:
        st.session_state.previous_selection = None
    if "current_selection" not in st.session_state:
        st.session_state.current_selection = "Home"
    
    # Scanning state
    if "scanning" not in st.session_state:
        st.session_state.scanning = False
    if "predictions" not in st.session_state:
        st.session_state.predictions = None
    if "processing" not in st.session_state:
        st.session_state.processing = False
    if "pcap_path" not in st.session_state:
        st.session_state.pcap_path = None
    if "scan_completed" not in st.session_state:
        st.session_state.scan_completed = False
    if "refreshed_after_scan" not in st.session_state:
        st.session_state.refreshed_after_scan = False
    if "refresh_count" not in st.session_state:
        st.session_state.refresh_count = 0
    if "success_message_displayed" not in st.session_state:
        st.session_state.success_message_displayed = False
    if "active_tab" not in st.session_state:
        st.session_state.active_tab = 0
    
    # File upload state
    if "uploaded_file_id" not in st.session_state:
        st.session_state.uploaded_file_id = None
    if "uploaded_file_path" not in st.session_state:
        st.session_state.uploaded_file_path = None
    if "upload_successful" not in st.session_state:
        st.session_state.upload_successful = False
    
    # Analysis state
    if "analysis_dir" not in st.session_state:
        st.session_state.analysis_dir = None
    if "graphs_generated" not in st.session_state:
        st.session_state.graphs_generated = False

def process_state_updates():
    """Process any pending state updates from threads."""
    needs_rerun = False
    while not st.session_state.state_updates.empty():
        try:
            key, value = st.session_state.state_updates.get(block=False)
            if key == "needs_rerun" and value:
                needs_rerun = True
            else:
                setattr(st.session_state, key, value)
        except queue.Empty:
            break
    return needs_rerun

def process_error_messages():
    """Process any pending error messages from threads."""
    while not st.session_state.error_queue.empty():
        try:
            error_msg = st.session_state.error_queue.get(block=False)
            st.error(error_msg)
        except queue.Empty:
            break