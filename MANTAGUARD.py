import streamlit as st
import time
import os
import sys
import pandas as pd
import threading
import subprocess
import glob
import importlib.util
from datetime import datetime
import csv
import queue

# Import backend modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import timed_capture module
timed_capture_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ai-model', 'timed_capture.py')
spec = importlib.util.spec_from_file_location("timed_capture", timed_capture_path)
timed_capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timed_capture)

# Import visualize_results module
visualize_results_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ai-model', 'visualize_results.py')
spec = importlib.util.spec_from_file_location("visualize_results", visualize_results_path)
visualize_results = importlib.util.module_from_spec(spec)
spec.loader.exec_module(visualize_results)

# Page config
st.set_page_config(
    page_title='MANTAGUARD',
    page_icon='https://raw.githubusercontent.com/aaron789746/MANTAGUARD/main/MANTAGUAD.png',)

# Convert hero banner image to base64 for CSS background
import base64
def get_base64_of_bin_file(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()

# Get the hero banner image as base64
hero_banner_base64 = get_base64_of_bin_file('content/hero-banner.png')

# Ensure required directories exist
analysis_results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "output", "analysis_results")
os.makedirs(analysis_results_dir, exist_ok=True)

# Initialize session state variables that are used across different sections
if "error_queue" not in st.session_state:
    st.session_state.error_queue = queue.Queue()
if "state_updates" not in st.session_state:
    st.session_state.state_updates = queue.Queue()

# Process any pending state updates from threads
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

# Process any pending error messages from threads
while not st.session_state.error_queue.empty():
    try:
        error_msg = st.session_state.error_queue.get(block=False)
        st.error(error_msg)
    except queue.Empty:
        break

# Rerun the app if needed
if needs_rerun:
    st.rerun()

# Sidebar navigation
st.sidebar.title("🔧 MantaGuard Features")
# Store the previous selection to detect changes
if "previous_selection" not in st.session_state:
    st.session_state.previous_selection = None

# Store the current selection to preserve it during reruns
if "current_selection" not in st.session_state:
    st.session_state.current_selection = "Home"

# Use the stored selection as the default value for the radio button
options = ["Home", "Scanning", "Reports", "Fix & Patches"]
index = options.index(st.session_state.current_selection) if st.session_state.current_selection in options else 0
selected_option = st.sidebar.radio(
    "Navigate to:",
    options,
    index=index
)

# Always force a rerun for Reports, Vulnerabilities, and Fix & Patches to ensure proper page switching
# This needs to be checked before the general selection change check
if selected_option in ["Reports", "Vulnerabilities", "Fix & Patches"]:
    # Make sure we preserve the current sidebar selection during rerun
    st.session_state.current_selection = selected_option
    # Only rerun if we haven't already scheduled a rerun and if the selection has changed
    if not needs_rerun and st.session_state.previous_selection != selected_option:
        st.session_state.previous_selection = selected_option
        st.rerun()

# Check if the selection has changed for other options
if st.session_state.previous_selection != selected_option:
    st.session_state.previous_selection = selected_option
    # Update the current selection to preserve it during reruns
    st.session_state.current_selection = selected_option
    # Force a rerun to refresh the page when selection changes
    st.rerun()

# Page content based on selection
if selected_option == "Home":
    # Custom CSS for the homepage
    st.markdown("""
    <style>
    /* Reset some default Streamlit styles */
    .block-container {
        max-width: 90% !important;
        padding-top: 0 !important;
        padding-left: 0 !important;
        padding-right: 0 !important;
    }

    /* Banner section */
    .hero-banner {
        width: 100%;
        min-height: 500px;
        background: linear-gradient(rgba(0, 0, 0, 0.4), rgba(0, 0, 0, 0.4)), 
                    url(data:image/png;base64,""" + f"{hero_banner_base64}" + """);
        background-size: cover;
        background-position: center;
        background-repeat: no-repeat;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        padding: 40px 20px;
        text-align: center;
        margin-bottom: 20px;
        border-radius: 15px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        position: relative;
    }

    /* Logo styling */
    .hero-logo {
        max-width: 200px;
        margin-bottom: 30px;
    }

    /* Headline styling */
    .hero-title {
        font-size: 3rem !important;
        font-weight: 700 !important;
        color: white !important;
        margin-bottom: 20px !important;
        line-height: 1.2 !important;
    }

    /* Subheadline styling */
    .hero-subtitle {
        font-size: 1.5rem !important;
        color: rgba(255, 255, 255, 0.8) !important;
        margin-bottom: 40px !important;
        max-width: 720px;
    }

    /* CTA button styling - enhanced for hero banner */
    .hero-cta {
        background-color: #00BFFF;
        color: white;
        font-weight: 600;
        padding: 12px 30px;
        border-radius: 30px;
        border: none;
        font-size: 1.1rem;
        cursor: pointer;
        transition: all 0.3s ease;
        text-decoration: none;
        display: inline-block;
        margin-top: 20px;
    }

    .hero-cta:hover {
        background-color: #00A0E0;
        box-shadow: 0 0 15px rgba(0, 191, 255, 0.5);
        transform: translateY(-2px);
    }
    
    /* Style Streamlit buttons within hero banner */
    .hero-banner .stButton > button {
        background-color: #00BFFF !important;
        color: white !important;
        border: none !important;
        border-radius: 30px !important;
        padding: 12px 30px !important;
        font-weight: 600 !important;
        font-size: 1.1rem !important;
        margin-top: 20px !important;
        transition: all 0.3s ease !important;
    }
    
    .hero-banner .stButton > button:hover {
        background-color: #00A0E0 !important;
        box-shadow: 0 0 15px rgba(0, 191, 255, 0.5) !important;
        transform: translateY(-2px) !important;
    }

    /* Features section styling */
    .features-section {
        padding: 80px 20px;
        max-width: 1080px;
        margin: 0 auto;
    }

    .features-title {
        font-size: 2.5rem !important;
        font-weight: 700 !important;
        text-align: center;
        margin-bottom: 10px !important;
    }

    .features-subtitle {
        font-size: 1.25rem !important;
        text-align: center;
        color: rgba(255, 255, 255, 0.8) !important;
        margin-bottom: 50px !important;
    }

    /* Feature card styling */
    .feature-card {
        background-color: #1E1E1E;
        border-radius: 8px;
        padding: 30px 20px;
        text-align: center;
        height: 100%;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        transition: all 0.3s ease;
    }

    .feature-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
    }

    .feature-icon {
        font-size: 2.5rem;
        margin-bottom: 20px;
        color: #00BFFF;
    }

    .feature-title {
        font-size: 1.5rem !important;
        font-weight: 700 !important;
        margin-bottom: 15px !important;
    }

    .feature-description {
        font-size: 1rem;
        color: rgba(255, 255, 255, 0.8);
    }

    /* Divider styling */
    .section-divider {
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        margin: 40px 0;
    }

    /* Tool descriptions (existing styles) */
    .tool-title {
        font-size: 1.5rem;
        font-weight: bold;
        margin-bottom: 10px;
        text-align: center;
    }
    .tool-description {
        border-radius: 5px;
        padding: 15px;
        height: 100%;
    }
    /* CSS for bottom alignment */
    .stVerticalBlock {
        display: flex;
        flex-direction: column;
    }
    .stImage {
        margin-top: auto;
        margin-bottom: 0;
        display: flex;
        align-items: flex-end;
    }
    /* CSS for tool images vertical centering */
    .streamlit-image{
        margin-top: 50px !important;
    }
    .vscode-image {
        margin-top: 50px !important;
    }
    .ocsvm-image {
        margin-top: 50px !important;
    }
    .zeek-image {
        margin-top: 90px !important;
    }

    /* Responsive styles */
    @media (max-width: 768px) {
        .hero-title {
            font-size: 2.5rem !important;
        }
        .hero-subtitle {
            font-size: 1.2rem !important;
        }
        .features-title {
            font-size: 2rem !important;
        }
    }
    </style>
    """, unsafe_allow_html=True)

    # Function to handle "Get Started" button click
    def navigate_to_scanning():
        # Update session state variables for navigation
        st.session_state.current_selection = "Scanning"
        st.session_state.previous_selection = "Home"
        # Force a rerun to navigate to the Scanning page
        st.rerun()

    # Hero Banner Section with background image and foreground content
    st.markdown("""
    <div class="hero-banner">
        <div style="display: flex; flex-direction: column; align-items: center; z-index: 10; position: relative;">
            <img src="data:image/png;base64,""" + get_base64_of_bin_file('content/Group3.png') + """" 
                 class="hero-logo" alt="MantaGuard Logo" style="max-width: 200px; margin-bottom: 20px;">
            <h1 class="hero-title">Welcome to MantaGuard</h1>
            <h2 class="hero-subtitle">Real-time Monitoring and Intrusion Detection using AI</h2>
    """, unsafe_allow_html=True)
    
    # Add the "Get Started" button within the hero banner
    col1, col2, col3 = st.columns([2, 1, 2])
    with col2:
        st.button("Get Started", on_click=navigate_to_scanning, key="get_started_button", type="primary", use_container_width=True)
    
    # Close the hero banner div
    st.markdown("""
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Features Section
    # Define features data
    features = [
        {
            "icon": "🧠",
            "title": "AI-Driven Anomaly Detection",
            "description": "Catches suspicious patterns in real time—24/7 monitoring."
        },
        {
            "icon": "🔔",
            "title": "Customizable Alerting",
            "description": "Get notified instantly when potential threats are detected."
        },
        {
            "icon": "📊",
            "title": "Easy Dashboard & Reporting",
            "description": "Visualize network activity and security insights at a glance."
        },
        {
            "icon": "🔒",
            "title": "Scalable & Secure",
            "description": "Enterprise-grade protection that grows with your network needs."
        }
    ]

    # Create the features section header
    st.markdown("""
    <div id="features" class="features-section">
        <h2 class="features-title">Why MantaGuard?</h2>
        <p class="features-subtitle">Our key features at a glance</p>
    """, unsafe_allow_html=True)

    # Create a 2x2 grid for features
    col1, col2 = st.columns(2)

    # First row
    with col1:
        st.markdown(f"""
        <div class="feature-card">
            <div class="feature-icon">{features[0]['icon']}</div>
            <h3 class="feature-title">{features[0]['title']}</h3>
            <p class="feature-description">{features[0]['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="feature-card">
            <div class="feature-icon">{features[1]['icon']}</div>
            <h3 class="feature-title">{features[1]['title']}</h3>
            <p class="feature-description">{features[1]['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    # Second row
    col3, col4 = st.columns(2)

    with col3:
        st.markdown(f"""
        <div class="feature-card">
            <div class="feature-icon">{features[2]['icon']}</div>
            <h3 class="feature-title">{features[2]['title']}</h3>
            <p class="feature-description">{features[2]['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="feature-card">
            <div class="feature-icon">{features[3]['icon']}</div>
            <h3 class="feature-title">{features[3]['title']}</h3>
            <p class="feature-description">{features[3]['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    # Close the features section
    st.markdown("""
    </div>
    <div class="section-divider"></div>
    """, unsafe_allow_html=True)

    # Brief project description
    st.write("""
    **MantaGuard** is an AI-powered monitoring and intrusion detection system. 
    It utilizes advanced algorithms and real-time data processing to ensure environmental security and safety.
    """)

    # Tools Showcase
    st.subheader("🧰 Tools Used")

    # Streamlit
    st.markdown('<div class="tool-title">Streamlit</div>', unsafe_allow_html=True)

    # Create a container for the tool content
    tool_container = st.container()

    # Create columns inside the container
    with tool_container:
        tool_row = st.columns([1, 2])

        with tool_row[0]:
            st.markdown('<div class="streamlit-image">', unsafe_allow_html=True)
            st.image("content/streamlit.png", width=300)
            st.markdown('</div>', unsafe_allow_html=True)

        with tool_row[1]:
            st.markdown('<div class="tool-description">Streamlit is an open-source Python library that makes it easy to create and share beautiful, custom web apps for machine learning and data science. In MantaGuard, Streamlit powers the entire user interface, providing interactive components like buttons, sliders, and visualizations that make network monitoring and intrusion detection accessible and user-friendly. Its ability to update in real-time makes it perfect for displaying live network data and analysis results.</div>', unsafe_allow_html=True)
    st.markdown("---")
    # VS Code
    st.markdown('<div class="tool-title">VS Code</div>', unsafe_allow_html=True)

    # Create a container for the tool content
    tool_container = st.container()

    # Create columns inside the container
    with tool_container:
        tool_row = st.columns([1, 2])

        with tool_row[0]:
            st.markdown('<div class="vscode-image">', unsafe_allow_html=True)
            st.image("content/Visual_Studio_Code_1.35_icon.svg.png", width=300)
            st.markdown('</div>', unsafe_allow_html=True)

        with tool_row[1]:
            st.markdown('<div class="tool-description">Visual Studio Code is a lightweight but powerful source code editor which runs on your desktop and is available for Windows, macOS and Linux. For MantaGuard development, VS Code provides essential features like integrated Git version control, debugging capabilities, and Python extensions that enhance productivity. Its customizable interface and extensive marketplace of extensions make it ideal for developing complex security applications that integrate multiple technologies and libraries.</div>', unsafe_allow_html=True)
    st.markdown("---")
    # Python
    st.markdown('<div class="tool-title">Python</div>', unsafe_allow_html=True)

    # Create a container for the tool content
    tool_container = st.container()

    # Create columns inside the container
    with tool_container:
        tool_row = st.columns([1, 2])

        with tool_row[0]:
            st.image("content/Python.svg.png", width=300)

        with tool_row[1]:
            st.markdown('<div class="tool-description">Python is a programming language that lets you work quickly and integrate systems more effectively. It is used extensively in data science, machine learning, and AI applications. In MantaGuard, Python serves as the core programming language, enabling rapid development and integration of various security components. Its rich ecosystem of libraries like pandas for data manipulation, scikit-learn for machine learning, and network analysis tools makes it perfect for implementing sophisticated intrusion detection algorithms and processing network traffic data efficiently.</div>', unsafe_allow_html=True)
    st.markdown("---")
    # OCSVM Algorithm
    st.markdown('<div class="tool-title">OCSVM Algorithm</div>', unsafe_allow_html=True)

    # Create a container for the tool content
    tool_container = st.container()

    # Create columns inside the container
    with tool_container:
        tool_row = st.columns([1, 2])

        with tool_row[0]:
            st.image("content/87ac3b54-afcc-40fe-84c2-515cc1415f3d.png", width=300)

        with tool_row[1]:
            st.markdown('<div class="tool-description">One-Class Support Vector Machine (OCSVM) is an unsupervised learning algorithm that learns a decision boundary that achieves the maximum separation between the points and the origin. In MantaGuard, OCSVM serves as the primary anomaly detection engine, capable of identifying unusual network patterns without requiring labeled training data. This makes it ideal for detecting zero-day attacks and previously unknown threats. The algorithm works by learning the normal behavior of network traffic and flagging deviations from this pattern, allowing MantaGuard to detect sophisticated intrusion attempts that might bypass traditional signature-based detection systems.</div>', unsafe_allow_html=True)
    st.markdown("---")
    # Zeek Network Monitor
    st.markdown('<div class="tool-title">Zeek Network Monitor</div>', unsafe_allow_html=True)

    # Create a container for the tool content
    tool_container = st.container()

    # Create columns inside the container
    with tool_container:
        tool_row = st.columns([1, 2])

        with tool_row[0]:
            st.markdown('<div class="zeek-image">', unsafe_allow_html=True)
            st.image("content/Zeek-Featured.png", width=300)
            st.markdown('</div>', unsafe_allow_html=True)

        with tool_row[1]:
            st.markdown('<div class="tool-description">Zeek (formerly Bro) is a powerful network analysis framework that is much different from the typical IDS you may know. It provides a comprehensive platform for network traffic analysis. In MantaGuard, Zeek serves as the primary data collection engine, capturing and parsing network traffic into structured logs that can be analyzed by the OCSVM algorithm. Its ability to extract detailed protocol-specific information from network flows enables MantaGuard to perform deep packet inspection and identify subtle patterns that might indicate malicious activity. Zeek\'s flexible scripting language also allows for customized detection rules tailored to specific network environments and threat landscapes.</div>', unsafe_allow_html=True)
    st.markdown("---")
elif selected_option == "Scanning":
    st.title("📡 Network Scanning")

    # Initialize section-specific session state variables
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

    # Create tabs for different scanning methods
    # Initialize the active tab in session state if it doesn't exist
    if "active_tab" not in st.session_state:
        st.session_state.active_tab = 0

    # Add a radio button to select the active tab
    tab_options = ["Timed Capture", "Upload PCAP", "Results"]
    selected_tab = st.radio("Select scanning method:", tab_options, index=st.session_state.active_tab, horizontal=True)

    # Update the active tab in session state
    current_tab_index = tab_options.index(selected_tab)

    # Check if the tab has changed
    if st.session_state.active_tab != current_tab_index:
        st.session_state.active_tab = current_tab_index
        # Make sure we preserve the current sidebar selection during rerun
        if selected_option:
            st.session_state.current_selection = selected_option
            # Also preserve the previous selection to avoid triggering another rerun
            st.session_state.previous_selection = selected_option
        # Force a rerun to refresh the page when tab changes
        st.rerun()

    # Display content based on selected tab
    if selected_tab == "Timed Capture":
        st.header("Timed Network Capture")

        # Network interface selection
        interface = st.text_input("Network Interface", "eth0", help="Enter your network interface (e.g., eth0, wlan0)")

        # Duration selection
        duration = st.slider("Capture Duration (seconds)", 5, 300, 60, 5)

        # Determine button label
        scan_label = "Start Capture" if not st.session_state.scanning else "🛑 Stop Capture"

        # Centered scan button
        left, center, right = st.columns([1, 2, 1])

        with center:
            if st.button(scan_label, key="scan_button"):
                if not st.session_state.scanning:
                    # Start a new capture
                    st.session_state.scanning = True
                    # Reset scan_completed, refreshed_after_scan, refresh_count, and success_message_displayed flags
                    st.session_state.scan_completed = False
                    st.session_state.refreshed_after_scan = False
                    st.session_state.refresh_count = 0
                    st.session_state.success_message_displayed = False

                    # Create pcaps directory if it doesn't exist
                    pcap_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "pcaps")
                    os.makedirs(pcap_dir, exist_ok=True)

                    # Generate output path
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_path = os.path.join(pcap_dir, f"capture_{timestamp}.pcap")
                    st.session_state.pcap_path = output_path

                    # Create local references to the queues
                    state_updates_queue = st.session_state.state_updates
                    error_queue = st.session_state.error_queue

                    # Run capture in a separate thread to keep UI responsive
                    def run_capture_thread(state_updates, error_q):
                        try:
                            timed_capture.run_capture(interface, duration, output_path)
                            # Process the PCAP file after capture
                            # Use queue for thread-safe state updates
                            state_updates.put(("processing", True))
                            results, analysis_dir = timed_capture.analyze_pcap_with_zeek(output_path)

                            # Save results to CSV
                            csv_path = os.path.join(analysis_dir, 'prediction_results.csv')
                            results_df = pd.DataFrame(results)
                            results_df.to_csv(csv_path, index=False)

                            # Generate visualizations
                            try:
                                # Create visualizations using the imported module
                                data, has_true_label = visualize_results.load_data(csv_path)
                                visualize_results.create_score_histogram(data, analysis_dir)
                                visualize_results.create_time_series(data, analysis_dir)

                                # Only create these if we have true labels
                                if has_true_label:
                                    visualize_results.create_roc_curve(data, has_true_label, analysis_dir)
                                    visualize_results.create_precision_recall_curve(data, has_true_label, analysis_dir)
                                    visualize_results.create_confusion_matrix(data, has_true_label, analysis_dir)
                            except Exception as vis_error:
                                error_q.put(f"Warning: Failed to generate visualizations: {str(vis_error)}")

                            # Store the analysis directory path in session state
                            state_updates.put(("analysis_dir", analysis_dir))
                            state_updates.put(("predictions", results))
                            state_updates.put(("processing", False))
                            # Set scan_completed flag to True
                            state_updates.put(("scan_completed", True))
                        except Exception as e:
                            # Use queue for thread-safe error reporting
                            error_q.put(f"Error during capture or analysis: {str(e)}")
                        finally:
                            state_updates.put(("scanning", False))

                    thread = threading.Thread(target=run_capture_thread, args=(state_updates_queue, error_queue))
                    thread.daemon = True
                    thread.start()
                else:
                    # Stop the current capture
                    st.session_state.scanning = False

        # Scanning animation
        if st.session_state.scanning:
            scan_placeholder = st.empty()
            scan_placeholder.info(f"Capturing packets on {interface} for {duration} seconds...")

        # Processing animation
        if st.session_state.processing:
            process_placeholder = st.empty()
            process_placeholder.info("Processing captured packets with Zeek and ML model...")

        # Display scan completed message
        if st.session_state.scan_completed:
            st.success("✅ Scan Completed! All files have been generated successfully.")
            st.info("You can view the results by clicking on the 'Results' tab above.")

            # Set the success_message_displayed flag to True
            st.session_state.success_message_displayed = True

            # Trigger a page refresh twice after a scan
            if st.session_state.refresh_count < 2:
                # Increment the refresh count
                st.session_state.refresh_count += 1
                # Set refreshed_after_scan to True after the final refresh
                if st.session_state.refresh_count >= 2:
                    st.session_state.refreshed_after_scan = True

                # Add a longer delay for the first refresh to ensure the success message is seen
                if st.session_state.refresh_count == 1:
                    time.sleep(3)  # 3 seconds for the first refresh
                else:
                    time.sleep(1)  # 1 second for subsequent refreshes

                st.rerun()

    elif selected_tab == "Upload PCAP":
        st.header("Upload PCAP File")

        # File uploader for PCAP files
        uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

        if uploaded_file is not None:
            # Create pcaps directory if it doesn't exist
            pcap_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "pcaps")
            os.makedirs(pcap_dir, exist_ok=True)

            # Check if we already have a save_path for this file in session state
            file_id = uploaded_file.name + str(uploaded_file.size)
            if "uploaded_file_id" not in st.session_state or st.session_state.uploaded_file_id != file_id:
                # This is a new file upload, generate a new save_path
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_path = os.path.join(pcap_dir, f"uploaded_{timestamp}.pcap")

                # Save the file
                with open(save_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                # Store the file ID and save_path in session state
                st.session_state.uploaded_file_id = file_id
                st.session_state.uploaded_file_path = save_path
            else:
                # Use the existing save_path for this file
                save_path = st.session_state.uploaded_file_path

            # Analyze button
            if st.button("Analyze PCAP"):
                st.session_state.pcap_path = save_path
                # Reset scan_completed, refreshed_after_scan, refresh_count, and success_message_displayed flags
                st.session_state.scan_completed = False
                st.session_state.refreshed_after_scan = False
                st.session_state.refresh_count = 0
                st.session_state.success_message_displayed = False

                # Create local references to the queues
                state_updates_queue = st.session_state.state_updates
                error_queue = st.session_state.error_queue

                # Run analysis in a separate thread to keep UI responsive
                def analyze_thread(state_updates, error_q):
                    try:
                        # Use queue for thread-safe state updates
                        state_updates.put(("processing", True))

                        # Use analyze_capture.py script instead of directly calling timed_capture.analyze_pcap_with_zeek
                        analyze_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "analyze_capture.py")
                        cmd = f"python {analyze_script_path} {save_path}"
                        print(f"Running command: {cmd}")

                        # Run the analyze_capture.py script
                        process = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)

                        # Extract the CSV path from the output
                        output_lines = process.stdout.splitlines()
                        csv_path = None
                        for line in output_lines:
                            if "Results saved to CSV:" in line:
                                csv_path = line.split("Results saved to CSV:")[1].strip()
                                break

                        if not csv_path or not os.path.exists(csv_path):
                            raise Exception("Could not find CSV file with results")

                        # Extract the analysis directory from the CSV path
                        analysis_dir = os.path.dirname(csv_path)

                        # Load the results from the CSV file
                        results_df = pd.read_csv(csv_path)
                        results = results_df.to_dict('records')

                        # Generate visualizations
                        try:
                            # Create visualizations using the imported module
                            data, has_true_label = visualize_results.load_data(csv_path)
                            visualize_results.create_score_histogram(data, analysis_dir)
                            visualize_results.create_time_series(data, analysis_dir)

                            # Only create these if we have true labels
                            if has_true_label:
                                visualize_results.create_roc_curve(data, has_true_label, analysis_dir)
                                visualize_results.create_precision_recall_curve(data, has_true_label, analysis_dir)
                                visualize_results.create_confusion_matrix(data, has_true_label, analysis_dir)
                        except Exception as vis_error:
                            error_q.put(f"Warning: Failed to generate visualizations: {str(vis_error)}")

                        # Store the analysis directory path in session state
                        state_updates.put(("analysis_dir", analysis_dir))
                        state_updates.put(("predictions", results))
                        state_updates.put(("processing", False))
                        # Set scan_completed flag to True
                        state_updates.put(("scan_completed", True))
                    except Exception as e:
                        # Use queue for thread-safe error reporting
                        error_q.put(f"Error during analysis: {str(e)}")

                thread = threading.Thread(target=analyze_thread, args=(state_updates_queue, error_queue))
                thread.daemon = True
                thread.start()

            # Processing animation
            if st.session_state.processing:
                process_placeholder = st.empty()
                process_placeholder.info("Processing PCAP file with Zeek and ML model...")

            # Display scan completed message
            if st.session_state.scan_completed:
                st.info("You can view the results by clicking on the 'Results' tab above.")

                # Set the success_message_displayed flag to True
                st.session_state.success_message_displayed = True

                # Trigger a page refresh twice after a scan
                if st.session_state.refresh_count < 2:
                    # Increment the refresh count
                    st.session_state.refresh_count += 1
                    # Set refreshed_after_scan to True after the final refresh
                    if st.session_state.refresh_count >= 2:
                        st.session_state.refreshed_after_scan = True

                    # Add a longer delay for the first refresh to ensure the success message is seen
                    if st.session_state.refresh_count == 1:
                        time.sleep(3)  # 3 seconds for the first refresh
                    else:
                        time.sleep(1)  # 1 second for subsequent refreshes

                    st.rerun()

    elif selected_tab == "Results":
        st.header("Analysis Results")

        if st.session_state.predictions:
            # Convert predictions to DataFrame for display
            df = pd.DataFrame(st.session_state.predictions)

            # Add a column for user labeling
            if 'user_label' not in df.columns:
                df['user_label'] = ""

            # Display the results
            st.dataframe(df)

            # Allow user to select a row and add a label
            st.subheader("Label a Prediction")

            # Get list of UIDs
            uids = df['uid'].tolist()

            # UID selection
            selected_uid = st.selectbox("Select Connection UID", uids)

            # Label selection
            label = st.radio("Select Label", ["normal", "anomaly", "unknown"])

            # Submit button
            if st.button("Submit Label"):
                # Get the selected row
                selected_row = df[df['uid'] == selected_uid].iloc[0].to_dict()

                # Add the label
                selected_row['user_label'] = label

                # Append to labeled_anomalies.csv
                csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "labeled_anomalies.csv")

                # Check if file exists to determine if we need to write headers
                file_exists = os.path.isfile(csv_path)

                with open(csv_path, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=selected_row.keys())

                    # Write headers if file doesn't exist
                    if not file_exists:
                        writer.writeheader()

                    writer.writerow(selected_row)

                st.success(f"Label '{label}' added for UID {selected_uid}")

            # Display visualizations from the analysis directory if available
            if "analysis_dir" in st.session_state:
                st.subheader("Analysis Visualizations")

                analysis_dir = st.session_state.analysis_dir

                # Find all PNG files in the analysis directory
                graph_files = glob.glob(os.path.join(analysis_dir, "*.png"))

                if graph_files:
                    st.success(f"Showing results from: {os.path.basename(analysis_dir)}")

                    # Display each graph
                    for graph_file in graph_files:
                        graph_name = os.path.basename(graph_file).replace(".png", "").replace("_", " ").title()
                        st.subheader(graph_name)
                        st.image(graph_file)

                    # Add option to open results folder
                    if st.button("Open Results Folder"):
                        # Create a clickable link to the results folder
                        st.markdown(f"[Click here to open results folder]({analysis_dir})")
                        st.code(f"Results folder path: {analysis_dir}")
                else:
                    st.warning(f"No visualization files found in the analysis directory: {analysis_dir}")
            else:
                # Generate graphs button (legacy support)
                if st.button("Generate Graphs"):
                    # Create output directory for graphs
                    graphs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "graphs")
                    os.makedirs(graphs_dir, exist_ok=True)

                    # Save predictions to CSV for visualization
                    csv_path = os.path.join(graphs_dir, "predictions.csv")
                    df.to_csv(csv_path, index=False)

                    # Create local references to the queues
                    state_updates_queue = st.session_state.state_updates
                    error_queue = st.session_state.error_queue

                    # Run visualization in a separate thread
                    def visualize_thread(state_updates, error_q):
                        try:
                            # Create a simple argparse-like object for visualize_results
                            class Args:
                                def __init__(self):
                                    self.input_csv = csv_path
                                    self.output_dir = graphs_dir
                                    self.title_prefix = ""

                            args = Args()

                            # Load data and create visualizations
                            data, has_true_label = visualize_results.load_data(args.input_csv)
                            visualize_results.create_score_histogram(data, args.output_dir, args.title_prefix)
                            visualize_results.create_time_series(data, args.output_dir, args.title_prefix)

                            # Only create these if we have true labels
                            if has_true_label:
                                visualize_results.create_roc_curve(data, has_true_label, args.output_dir, args.title_prefix)
                                visualize_results.create_precision_recall_curve(data, has_true_label, args.output_dir, args.title_prefix)
                                visualize_results.create_confusion_matrix(data, has_true_label, args.output_dir, args.title_prefix)

                            # Use queue for thread-safe state updates
                            state_updates.put(("graphs_generated", True))
                        except Exception as e:
                            # Use queue for thread-safe error reporting
                            error_q.put(f"Error generating graphs: {str(e)}")

                    thread = threading.Thread(target=visualize_thread, args=(state_updates_queue, error_queue))
                    thread.daemon = True
                    thread.start()

                    st.info("Generating graphs...")

                # Display graphs if they exist (legacy support)
                if st.session_state.get('graphs_generated', False):
                    st.subheader("Visualization Graphs")

                    graphs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "graphs")

                    # Find all PNG files in the graphs directory
                    graph_files = glob.glob(os.path.join(graphs_dir, "*.png"))

                    # Display each graph
                    for graph_file in graph_files:
                        graph_name = os.path.basename(graph_file).replace(".png", "").replace("_", " ").title()
                        st.subheader(graph_name)
                        st.image(graph_file)
        else:
            st.info("No analysis results available. Capture network traffic or upload a PCAP file to analyze.")



elif selected_option == "Reports":
    st.title("📊 Reports and Visualizations")

    # Find the most recent analysis results directory
    analysis_results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "output", "analysis_results")
    analysis_dirs = glob.glob(os.path.join(analysis_results_dir, "*"))

    # Sort by modification time (most recent first)
    analysis_dirs.sort(key=os.path.getmtime, reverse=True)

    if analysis_dirs:
        latest_analysis_dir = analysis_dirs[0]
        st.write(f"### Latest Analysis Results: {os.path.basename(latest_analysis_dir)}")

        # Find all PNG files in the latest analysis directory
        graph_files = glob.glob(os.path.join(latest_analysis_dir, "*.png"))

        if graph_files:
            # Display each graph
            for graph_file in graph_files:
                graph_name = os.path.basename(graph_file).replace(".png", "").replace("_", " ").title()
                st.subheader(graph_name)
                st.image(graph_file)

            # Add option to view results folder
            if st.button("Open Results Folder"):
                # Create a clickable link to the results folder
                st.markdown(f"[Click here to open results folder]({latest_analysis_dir})")
                st.code(f"Results folder path: {latest_analysis_dir}")

            # Show CSV data if available
            csv_path = os.path.join(latest_analysis_dir, "prediction_results.csv")
            if os.path.exists(csv_path):
                st.subheader("Prediction Results Data")
                try:
                    results_df = pd.read_csv(csv_path)

                    # Add toggle to show only anomalies
                    show_only_anomalies = st.checkbox("Show only anomalies", value=False)

                    # Filter results if toggle is on
                    if show_only_anomalies:
                        # Filter for entries where prediction is 'anomaly' or -1
                        filtered_df = results_df[
                            (results_df['prediction'] == 'anomaly') | 
                            (results_df['prediction'] == -1)
                        ]
                        # Show count of anomalies
                        st.info(f"Showing {len(filtered_df)} anomalies")
                        # Use filtered dataframe for display
                        display_df = filtered_df
                    else:
                        # Use original dataframe for display
                        display_df = results_df

                    # Create a container for extracted PCAP status messages
                    extract_status = st.empty()

                    # Create a container for download links
                    download_container = st.container()

                    # Function to extract PCAP for a specific UID
                    def extract_pcap_for_uid(uid, conn_log_path, pcap_path):
                        try:
                            # Create forensics directory if it doesn't exist
                            forensics_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                                        "ai-model", "forensics")
                            os.makedirs(forensics_dir, exist_ok=True)

                            # Determine the output path based on the analysis directory
                            analysis_dir_name = os.path.basename(latest_analysis_dir)
                            forensics_subdir = os.path.join(forensics_dir, analysis_dir_name)
                            os.makedirs(forensics_subdir, exist_ok=True)
                            output_filename = f"{uid}.pcap"
                            output_path = os.path.join(forensics_subdir, output_filename)

                            # Build the command to run extract_flow_by_uid.py
                            extract_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                                             "ai-model", "extract_flow_by_uid.py")
                            cmd = [
                                "python", extract_script_path,
                                "--uid", uid,
                                "--conn-log", conn_log_path,
                                "--pcap", pcap_path,
                                "--analysis-dir", latest_analysis_dir
                            ]

                            # Run the script
                            extract_status.info(f"Extracting flow for UID: {uid}...")
                            process = subprocess.run(cmd, capture_output=True, text=True)

                            if process.returncode != 0:
                                extract_status.error(f"Error extracting flow: {process.stderr}")
                                return None

                            # Check if the output file was created
                            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                                extract_status.success(f"Flow extracted: {output_filename}")

                                # Optional: Log the extraction for audit purposes
                                # Determine the actual output path (which might be in a subdirectory)
                                analysis_dir_name = os.path.basename(latest_analysis_dir)
                                forensics_subdir = os.path.join(forensics_dir, analysis_dir_name)

                                # Use the main forensics directory for the log
                                log_path = os.path.join(forensics_dir, "extraction_log.csv")
                                log_exists = os.path.exists(log_path)

                                with open(log_path, 'a', newline='') as f:
                                    writer = csv.writer(f)
                                    if not log_exists:
                                        writer.writerow(['timestamp', 'uid', 'output_file', 'analysis_dir'])
                                    writer.writerow([
                                        datetime.now().isoformat(), 
                                        uid, 
                                        os.path.join(analysis_dir_name, f"{uid}.pcap"),
                                        analysis_dir_name
                                    ])

                                return output_path
                            else:
                                extract_status.error(f"No packets found for UID: {uid}")
                                return None
                        except Exception as e:
                            extract_status.error(f"Error during extraction: {str(e)}")
                            return None

                    # Display the dataframe with an "Extract PCAP" button for each row
                    st.write("Click 'Extract PCAP' for any anomalous connection to extract the raw network flow:")

                    # Find the original PCAP file and conn.log file
                    pcap_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "pcaps")
                    zeek_logs_dir = os.path.join(latest_analysis_dir, "zeek_logs")

                    # Find the most recent PCAP file
                    pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap"))
                    pcap_path = max(pcap_files, key=os.path.getmtime) if pcap_files else None

                    # Find the conn.log file
                    conn_log_path = os.path.join(zeek_logs_dir, "conn.log") if os.path.exists(zeek_logs_dir) else None

                    if not pcap_path or not conn_log_path or not os.path.exists(conn_log_path):
                        st.warning("Cannot extract PCAPs: Missing original PCAP file or conn.log")
                        st.dataframe(display_df)
                    else:
                        # Create expanders for each row in the dataframe
                        for i, row in display_df.iterrows():
                            uid = row['uid']
                            # Check for both possible score column names
                            score = row.get('score', row.get('anomaly_score', 0))
                            proto = row.get('proto', 'unknown')
                            service = row.get('service', 'unknown')
                            prediction = row.get('prediction', 'unknown')

                            # Format prediction label to capitalize first letter
                            prediction_label = prediction.capitalize() if prediction else "Unknown"

                            # Create an expander for this row with styling based on prediction
                            expander_label = f"UID: {uid} | Prediction: {prediction_label} | Score: {score:.4f} | Proto: {proto} | Service: {service}"

                            # Apply styling based on prediction
                            if prediction == 'anomaly':
                                # Add visual indicator for anomalies in the label itself
                                expander_label = f"🚨 {expander_label}"

                            # Create expander without border parameters which are not supported in this Streamlit version
                            expander = st.expander(expander_label, expanded=False)

                            # Use the expander context
                            with expander:
                                # Display all row data
                                for col in results_df.columns:
                                    st.write(f"**{col}:** {row[col]}")

                                # Add Extract PCAP button
                                if st.button(f"Extract PCAP", key=f"extract_{uid}"):
                                    output_path = extract_pcap_for_uid(uid, conn_log_path, pcap_path)

                                    if output_path:
                                        # Read the file for download
                                        with open(output_path, 'rb') as f:
                                            pcap_data = f.read()

                                        # Create a download button in the download container
                                        with download_container:
                                            st.download_button(
                                                label=f"Download PCAP for {uid}",
                                                data=pcap_data,
                                                file_name=os.path.basename(output_path),
                                                mime="application/vnd.tcpdump.pcap"
                                            )

                    # Option to download the CSV
                    csv_data = display_df.to_csv(index=False)
                    download_label = "Download Anomalies CSV" if show_only_anomalies else "Download Results CSV"
                    st.download_button(
                        label=download_label,
                        data=csv_data,
                        file_name=f"prediction_results_{os.path.basename(latest_analysis_dir)}.csv",
                        mime="text/csv"
                    )
                except Exception as e:
                    st.error(f"Error loading results CSV: {str(e)}")
        else:
            st.warning(f"No visualization files found in the latest analysis directory: {latest_analysis_dir}")

        # Show previous analysis runs
        if len(analysis_dirs) > 1:
            st.subheader("Previous Analysis Runs")
            for i, analysis_dir in enumerate(analysis_dirs[1:5]):  # Show up to 4 previous runs
                timestamp = os.path.basename(analysis_dir)
                st.write(f"{i+1}. {timestamp}")
    else:
        # Fallback to legacy graphs directory
        graphs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "graphs")
        graph_files = glob.glob(os.path.join(graphs_dir, "*.png")) if os.path.exists(graphs_dir) else []

        if graph_files:
            st.write("Here are the visualization graphs generated from the latest analysis:")

            # Display each graph
            for graph_file in graph_files:
                graph_name = os.path.basename(graph_file).replace(".png", "").replace("_", " ").title()
                st.subheader(graph_name)
                st.image(graph_file)

            # Add option to regenerate graphs
            if st.button("Regenerate Graphs"):
                # Check if we have predictions to visualize
                if st.session_state.get('predictions'):
                    # Create output directory for graphs
                    os.makedirs(graphs_dir, exist_ok=True)

                    # Save predictions to CSV for visualization
                    csv_path = os.path.join(graphs_dir, "predictions.csv")
                    df = pd.DataFrame(st.session_state.predictions)
                    df.to_csv(csv_path, index=False)

                    # Create local references to the queues
                    state_updates_queue = st.session_state.state_updates
                    error_queue = st.session_state.error_queue

                    # Run visualization in a separate thread
                    def visualize_thread(state_updates, error_q):
                        try:
                            # Create a simple argparse-like object for visualize_results
                            class Args:
                                def __init__(self):
                                    self.input_csv = csv_path
                                    self.output_dir = graphs_dir
                                    self.title_prefix = ""

                            args = Args()

                            # Load data and create visualizations
                            data, has_true_label = visualize_results.load_data(args.input_csv)
                            visualize_results.create_score_histogram(data, args.output_dir, args.title_prefix)
                            visualize_results.create_time_series(data, args.output_dir, args.title_prefix)

                            # Only create these if we have true labels
                            if has_true_label:
                                visualize_results.create_roc_curve(data, has_true_label, args.output_dir, args.title_prefix)
                                visualize_results.create_precision_recall_curve(data, has_true_label, args.output_dir, args.title_prefix)
                                visualize_results.create_confusion_matrix(data, has_true_label, args.output_dir, args.title_prefix)

                            # Use queue for thread-safe state updates
                            state_updates.put(("graphs_generated", True))
                            # Add a flag to indicate that a rerun is needed
                            state_updates.put(("needs_rerun", True))
                        except Exception as e:
                            # Use queue for thread-safe error reporting
                            error_q.put(f"Error generating graphs: {str(e)}")

                    thread = threading.Thread(target=visualize_thread, args=(state_updates_queue, error_queue))
                    thread.daemon = True
                    thread.start()

                    st.info("Regenerating graphs...")
                else:
                    st.warning("No prediction data available. Run a scan or upload a PCAP file first.")
        else:
            st.info("No visualization graphs available. Run a scan or upload a PCAP file in the Scanning section, then generate graphs.")

    # Display labeled anomalies if available
    labeled_anomalies_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai-model", "labeled_anomalies.csv")

    if os.path.exists(labeled_anomalies_path):
        st.subheader("Labeled Anomalies")
        try:
            labeled_df = pd.read_csv(labeled_anomalies_path)
            st.dataframe(labeled_df)

            # Option to download the labeled anomalies CSV
            csv_data = labeled_df.to_csv(index=False)
            st.download_button(
                label="Download Labeled Anomalies CSV",
                data=csv_data,
                file_name="labeled_anomalies.csv",
                mime="text/csv"
            )
        except Exception as e:
            st.error(f"Error loading labeled anomalies: {str(e)}")
    else:
        st.info("No labeled anomalies available. Label some predictions in the Scanning section.")


elif selected_option == "Fix & Patches":
    st.title("🛠️ Fix & Patches")
    st.write("Suggested fixes and patches for identified vulnerabilities.")
    # Maybe upload patch files or show instructions
