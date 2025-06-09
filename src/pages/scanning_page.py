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
import netifaces

def get_network_interfaces():
    """Get available network interfaces on the system."""
    try:
        interfaces = netifaces.interfaces()
        # Filter out loopback interface for better UX
        filtered_interfaces = [iface for iface in interfaces if iface != 'lo']
        # If no interfaces after filtering, return all
        return filtered_interfaces if filtered_interfaces else interfaces
    except Exception:
        # Fallback to common interface names if netifaces fails
        return ['eth0', 'wlan0', 'enp0s3', 'wlp3s0']

def import_ai_modules():
    """Import AI model modules dynamically."""
    # Get the project root directory (two levels up from src/pages/)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Import timed_capture module
    timed_capture_path = os.path.join(project_root, 'ai-model', 'timed_capture.py')
    spec = importlib.util.spec_from_file_location("timed_capture", timed_capture_path)
    timed_capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(timed_capture)

    # Import visualize_results module
    visualize_results_path = os.path.join(project_root, 'ai-model', 'visualize_results.py')
    spec = importlib.util.spec_from_file_location("visualize_results", visualize_results_path)
    visualize_results = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(visualize_results)
    
    return timed_capture, visualize_results

def render_timed_capture_tab():
    """Render the timed capture tab content."""
    st.header("Timed Network Capture")
    
    # Process any pending state updates from background threads at the start of rendering
    from src.utils.session_state import process_state_updates
    needs_rerun = process_state_updates()
    if needs_rerun:
        st.rerun()
    
    timed_capture, visualize_results = import_ai_modules()

    # Network interface selection
    col1, col2 = st.columns([4, 1])
    
    with col1:
        # Get interfaces, using session state to cache and allow refresh
        if 'network_interfaces' not in st.session_state:
            st.session_state.network_interfaces = get_network_interfaces()
        
        interface = st.selectbox("Network Interface", st.session_state.network_interfaces, help="Select your network interface")
    
    with col2:
        st.markdown('<div style="margin-top: 31px;"></div>', unsafe_allow_html=True)
        if st.button("🔄 Refresh", help="Refresh network interfaces", type="secondary", use_container_width=True):
            with st.spinner("Refreshing..."):
                st.session_state.network_interfaces = get_network_interfaces()
            st.rerun()

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
                
                # Initialize capture timer
                st.session_state.capture_start_time = time.time()
                st.session_state.capture_duration = duration

                # Create pcaps directory if it doesn't exist
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                pcap_dir = os.path.join(project_root, "ai-model", "pcaps")
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
                        # Ensure we're in the project root directory
                        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                        original_cwd = os.getcwd()
                        os.chdir(project_root)
                        
                        # Step 1: Network capture
                        state_updates.put(("capture_progress", 0.1))
                        state_updates.put(("capture_status", "Starting network capture..."))
                        
                        # Start capture timer
                        start_time = time.time()
                        state_updates.put(("capture_timer_start", start_time))
                        
                        timed_capture.run_capture(interface, duration, output_path)
                        
                        # Step 2: Capture completed, starting analysis
                        state_updates.put(("capture_progress", 0.3))
                        state_updates.put(("capture_status", "Network capture completed. Starting analysis..."))
                        state_updates.put(("processing", True))
                        
                        # Step 3: Zeek processing
                        state_updates.put(("capture_progress", 0.5))
                        state_updates.put(("capture_status", "Processing packets with Zeek..."))
                        
                        results, analysis_dir = timed_capture.analyze_pcap_with_zeek(output_path)

                        # Step 4: Save results to CSV
                        state_updates.put(("capture_progress", 0.7))
                        state_updates.put(("capture_status", "Running ML analysis..."))
                        
                        csv_path = os.path.join(analysis_dir, 'prediction_results.csv')
                        results_df = pd.DataFrame(results)
                        results_df.to_csv(csv_path, index=False)

                        # Step 5: Generate visualizations
                        state_updates.put(("capture_progress", 0.85))
                        state_updates.put(("capture_status", "Generating visualizations..."))
                        
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

                        # Step 6: Complete
                        state_updates.put(("capture_progress", 1.0))
                        state_updates.put(("capture_status", "Analysis completed successfully!"))
                        
                        # Store the analysis directory path in session state
                        state_updates.put(("analysis_dir", analysis_dir))
                        state_updates.put(("predictions", results))
                        state_updates.put(("processing", False))
                        # Set scan_completed flag to True
                        state_updates.put(("scan_completed", True))
                        # Trigger a rerun to display the success message immediately
                        state_updates.put(("needs_rerun", True))
                    except Exception as e:
                        # Use queue for thread-safe error reporting
                        error_q.put(f"Error during capture or analysis: {str(e)}")
                        state_updates.put(("capture_progress", 0))
                        state_updates.put(("capture_status", ""))
                    finally:
                        # Restore original working directory
                        os.chdir(original_cwd)
                        state_updates.put(("scanning", False))

                thread = threading.Thread(target=run_capture_thread, args=(state_updates_queue, error_queue))
                thread.daemon = True
                thread.start()
            else:
                # Stop the current capture
                st.session_state.scanning = False

    # Progress tracking during capture and analysis
    if st.session_state.scanning or st.session_state.processing:
        # Show progress bar and status
        progress = st.session_state.get('capture_progress', 0)
        status = st.session_state.get('capture_status', 'Starting...')
        
        # Show countdown timer during capture phase
        if st.session_state.scanning and hasattr(st.session_state, 'capture_start_time'):
            elapsed_time = time.time() - st.session_state.capture_start_time
            remaining_time = max(0, st.session_state.capture_duration - elapsed_time)
            
            # Calculate timer progress (separate from analysis progress)
            timer_progress = min(elapsed_time / st.session_state.capture_duration, 1.0)
            
            # Display countdown info
            minutes, seconds = divmod(int(remaining_time), 60)
            if remaining_time > 0:
                st.info(f"📡 Capturing packets on {interface} - {minutes:02d}:{seconds:02d} remaining")
                # Timer progress bar
                capture_progress_bar = st.progress(timer_progress)
            else:
                st.info("📡 Capture completed, processing data...")
                capture_progress_bar = st.progress(1.0)
        else:
            st.info(status)
        
        # Analysis progress bar (shown during processing phase)
        if st.session_state.processing:
            analysis_progress_bar = st.progress(progress)
        
        # Auto-refresh more frequently during scanning for smoother timer, less frequently during processing
        if st.session_state.scanning:
            time.sleep(0.1)  # Update every 100ms for smooth timer progress
        else:
            time.sleep(1)    # Update every 1 second during processing
        st.rerun()

    # Display scan completed message
    if st.session_state.scan_completed:
        if not st.session_state.success_message_displayed:
            st.success("✅ Scan Completed! All files have been generated successfully.")
            st.info("You can view the results by clicking on the 'Results' tab above.")
            # Set the success_message_displayed flag to True to prevent repeated displays
            st.session_state.success_message_displayed = True
        else:
            # Keep showing the success message even after it's been displayed once
            st.success("✅ Scan Completed! All files have been generated successfully.")
            st.info("You can view the results by clicking on the 'Results' tab above.")

def render_upload_pcap_tab():
    """Render the upload PCAP tab content."""
    st.header("Upload PCAP File")
    
    # Process any pending state updates from background threads
    from src.utils.session_state import process_state_updates
    process_state_updates()
    
    # File uploader for PCAP files
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        # Create pcaps directory if it doesn't exist
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        pcap_dir = os.path.join(project_root, "ai-model", "pcaps")
        os.makedirs(pcap_dir, exist_ok=True)

        # Generate save path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = os.path.join(pcap_dir, f"uploaded_{timestamp}_{uploaded_file.name}")

        # Show upload progress
        upload_progress = st.progress(0)
        upload_status = st.empty()
        
        # Save the file with progress tracking
        upload_status.text("Uploading file...")
        upload_progress.progress(0.3)
        
        with open(save_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        upload_progress.progress(1.0)
        upload_status.text("Upload completed!")
        
        st.success(f"✅ PCAP file '{uploaded_file.name}' uploaded successfully!")

        # Analyze button
        if st.button("Analyze PCAP", key="analyze_uploaded_pcap"):
            # Reset states
            st.session_state.scan_completed = False
            st.session_state.success_message_displayed = False
            st.session_state.processing = True
            st.session_state.pcap_path = save_path

            # Start analysis in background thread
            state_updates_queue = st.session_state.state_updates
            error_queue = st.session_state.error_queue

            def analyze_thread(pcap_path, state_updates, error_q):
                try:
                    # Ensure we're in the project root directory
                    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                    original_cwd = os.getcwd()
                    os.chdir(project_root)
                    
                    # Step 1: Starting analysis
                    state_updates.put(("upload_progress", 0.1))
                    state_updates.put(("upload_status", "Starting PCAP analysis..."))
                    
                    # Run analyze_capture.py script
                    analyze_script_path = os.path.join(project_root, "ai-model", "analyze_capture.py")
                    cmd = f"python {analyze_script_path} {pcap_path}"

                    # Step 2: Processing with Zeek
                    state_updates.put(("upload_progress", 0.3))
                    state_updates.put(("upload_status", "Processing PCAP with Zeek..."))
                    
                    # Run the analysis
                    process = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)

                    # Step 3: ML Analysis
                    state_updates.put(("upload_progress", 0.6))
                    state_updates.put(("upload_status", "Running ML analysis..."))
                    
                    # Extract CSV path from output
                    csv_path = None
                    for line in process.stdout.splitlines():
                        if "Results saved to CSV:" in line:
                            csv_path = line.split("Results saved to CSV:")[1].strip()
                            break

                    if not csv_path or not os.path.exists(csv_path):
                        raise Exception("Could not find CSV file with results")

                    # Load results
                    analysis_dir = os.path.dirname(csv_path)
                    results_df = pd.read_csv(csv_path)
                    results = results_df.to_dict('records')

                    # Step 4: Generate visualizations
                    state_updates.put(("upload_progress", 0.8))
                    state_updates.put(("upload_status", "Generating visualizations..."))
                    
                    try:
                        visualize_results = import_ai_modules()[1]
                        data, has_true_label = visualize_results.load_data(csv_path)
                        visualize_results.create_score_histogram(data, analysis_dir)
                        visualize_results.create_time_series(data, analysis_dir)
                        if has_true_label:
                            visualize_results.create_roc_curve(data, has_true_label, analysis_dir)
                            visualize_results.create_precision_recall_curve(data, has_true_label, analysis_dir)
                            visualize_results.create_confusion_matrix(data, has_true_label, analysis_dir)
                    except Exception as vis_error:
                        error_q.put(f"Warning: Failed to generate visualizations: {str(vis_error)}")

                    # Step 5: Complete
                    state_updates.put(("upload_progress", 1.0))
                    state_updates.put(("upload_status", "Analysis completed successfully!"))
                    
                    # Update session state
                    state_updates.put(("analysis_dir", analysis_dir))
                    state_updates.put(("predictions", results))
                    state_updates.put(("scan_completed", True))
                    state_updates.put(("processing", False))
                    state_updates.put(("needs_rerun", True))

                except Exception as e:
                    error_q.put(f"Error during analysis: {str(e)}")
                    state_updates.put(("upload_progress", 0))
                    state_updates.put(("upload_status", ""))
                    state_updates.put(("processing", False))
                finally:
                    # Restore original working directory
                    os.chdir(original_cwd)

            thread = threading.Thread(target=analyze_thread, args=(save_path, state_updates_queue, error_queue))
            thread.daemon = True
            thread.start()
            st.rerun()

    # Show processing status with progress bar
    if st.session_state.processing:
        # Show progress bar and status for upload analysis
        progress = st.session_state.get('upload_progress', 0)
        status = st.session_state.get('upload_status', 'Processing PCAP file...')
        
        st.info(status)
        progress_bar = st.progress(progress)
        
        # Auto-refresh every 1 second during processing to check for updates
        time.sleep(1)
        st.rerun()

    # Show completion notification
    if st.session_state.scan_completed:
        if not st.session_state.success_message_displayed:
            st.success("✅ Analysis Complete! Results are ready.")
            st.info("Click on the 'Results' tab to view the analysis results.")
            st.session_state.success_message_displayed = True
        else:
            # Keep showing the success message even after it's been displayed once
            st.success("✅ Analysis Complete! Results are ready.")
            st.info("Click on the 'Results' tab to view the analysis results.")

def render_results_tab():
    """Render the results tab content."""
    st.header("Analysis Results")
    
    # Process any pending state updates from background threads at the start of rendering
    from src.utils.session_state import process_state_updates
    needs_rerun = process_state_updates()
    if needs_rerun:
        st.rerun()
    
    visualize_results = import_ai_modules()[1]

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
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            csv_path = os.path.join(project_root, "ai-model", "labeled_anomalies.csv")

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
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                graphs_dir = os.path.join(project_root, "ai-model", "graphs")
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

                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                graphs_dir = os.path.join(project_root, "ai-model", "graphs")

                # Find all PNG files in the graphs directory
                graph_files = glob.glob(os.path.join(graphs_dir, "*.png"))

                # Display each graph
                for graph_file in graph_files:
                    graph_name = os.path.basename(graph_file).replace(".png", "").replace("_", " ").title()
                    st.subheader(graph_name)
                    st.image(graph_file)
    else:
        st.info("No analysis results available. Capture network traffic or upload a PCAP file to analyze.")

def render_scanning_page():
    """Render the complete scanning page with tabs."""
    st.title("📡 Network Scanning")
    
    # Process any pending state updates from background threads
    from src.utils.session_state import process_state_updates
    needs_rerun = process_state_updates()
    if needs_rerun:
        st.rerun()

    # Create tabs for different scanning methods
    tab_options = ["Timed Capture", "Upload PCAP", "Results"]
    selected_tab = st.radio("Select scanning method:", tab_options, index=st.session_state.active_tab, horizontal=True)

    # Update the active tab in session state
    current_tab_index = tab_options.index(selected_tab)

    # Check if the tab has changed
    if st.session_state.active_tab != current_tab_index:
        st.session_state.active_tab = current_tab_index
        # Process any pending state updates before rerunning - do this multiple times to catch all updates
        from src.utils.session_state import process_state_updates
        for _ in range(3):  # Process multiple times to catch all pending updates
            process_state_updates()
            time.sleep(0.05)  # Small delay to allow updates to settle
        # Force a rerun to refresh the page when tab changes
        st.rerun()

    # Display content based on selected tab
    if selected_tab == "Timed Capture":
        render_timed_capture_tab()
    elif selected_tab == "Upload PCAP":
        render_upload_pcap_tab()
    elif selected_tab == "Results":
        render_results_tab()