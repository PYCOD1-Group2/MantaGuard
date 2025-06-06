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

def import_ai_modules():
    """Import AI model modules dynamically."""
    # Import timed_capture module
    timed_capture_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                    'ai-model', 'timed_capture.py')
    spec = importlib.util.spec_from_file_location("timed_capture", timed_capture_path)
    timed_capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(timed_capture)

    # Import visualize_results module
    visualize_results_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                        'ai-model', 'visualize_results.py')
    spec = importlib.util.spec_from_file_location("visualize_results", visualize_results_path)
    visualize_results = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(visualize_results)
    
    return timed_capture, visualize_results

def render_timed_capture_tab():
    """Render the timed capture tab content."""
    st.header("Timed Network Capture")
    
    timed_capture, visualize_results = import_ai_modules()

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
                pcap_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                      "ai-model", "pcaps")
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

def render_upload_pcap_tab():
    """Render the upload PCAP tab content."""
    st.header("Upload PCAP File")
    
    visualize_results = import_ai_modules()[1]

    # File uploader for PCAP files
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        # Create pcaps directory if it doesn't exist
        pcap_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                              "ai-model", "pcaps")
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
                    analyze_script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                                     "ai-model", "analyze_capture.py")
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

def render_results_tab():
    """Render the results tab content."""
    st.header("Analysis Results")
    
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
            csv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                  "ai-model", "labeled_anomalies.csv")

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
                graphs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                        "ai-model", "graphs")
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

                graphs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                        "ai-model", "graphs")

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

    # Create tabs for different scanning methods
    tab_options = ["Timed Capture", "Upload PCAP", "Results"]
    selected_tab = st.radio("Select scanning method:", tab_options, index=st.session_state.active_tab, horizontal=True)

    # Update the active tab in session state
    current_tab_index = tab_options.index(selected_tab)

    # Check if the tab has changed
    if st.session_state.active_tab != current_tab_index:
        st.session_state.active_tab = current_tab_index
        # Make sure we preserve the current sidebar selection during rerun
        if hasattr(st.session_state, 'current_selection'):
            # Also preserve the previous selection to avoid triggering another rerun
            st.session_state.previous_selection = st.session_state.current_selection
        # Force a rerun to refresh the page when tab changes
        st.rerun()

    # Display content based on selected tab
    if selected_tab == "Timed Capture":
        render_timed_capture_tab()
    elif selected_tab == "Upload PCAP":
        render_upload_pcap_tab()
    elif selected_tab == "Results":
        render_results_tab()