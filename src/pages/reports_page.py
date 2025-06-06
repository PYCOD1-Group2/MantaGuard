import streamlit as st
import os
import pandas as pd
import glob
import subprocess
import csv
import threading
import importlib.util
from datetime import datetime

def import_visualize_results():
    """Import visualize_results module dynamically."""
    visualize_results_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                        'ai-model', 'visualize_results.py')
    spec = importlib.util.spec_from_file_location("visualize_results", visualize_results_path)
    visualize_results = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(visualize_results)
    return visualize_results

def extract_pcap_for_uid(uid, conn_log_path, pcap_path, latest_analysis_dir):
    """Extract PCAP for a specific UID."""
    try:
        # Create forensics directory if it doesn't exist
        forensics_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                    "ai-model", "forensics")
        os.makedirs(forensics_dir, exist_ok=True)

        # Determine the output path based on the analysis directory
        analysis_dir_name = os.path.basename(latest_analysis_dir)
        forensics_subdir = os.path.join(forensics_dir, analysis_dir_name)
        os.makedirs(forensics_subdir, exist_ok=True)
        output_filename = f"{uid}.pcap"
        output_path = os.path.join(forensics_subdir, output_filename)

        # Build the command to run extract_flow_by_uid.py
        extract_script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                         "ai-model", "extract_flow_by_uid.py")
        cmd = [
            "python", extract_script_path,
            "--uid", uid,
            "--conn-log", conn_log_path,
            "--pcap", pcap_path,
            "--analysis-dir", latest_analysis_dir
        ]

        # Run the script
        process = subprocess.run(cmd, capture_output=True, text=True)

        if process.returncode != 0:
            st.error(f"Error extracting flow: {process.stderr}")
            return None

        # Check if the output file was created
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            st.success(f"Flow extracted: {output_filename}")

            # Optional: Log the extraction for audit purposes
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
            st.error(f"No packets found for UID: {uid}")
            return None
    except Exception as e:
        st.error(f"Error during extraction: {str(e)}")
        return None

def render_latest_analysis_results():
    """Render the latest analysis results section."""
    # Find the most recent analysis results directory
    analysis_results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                      "ai-model", "output", "analysis_results")
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
            render_csv_results(latest_analysis_dir)
        else:
            st.warning(f"No visualization files found in the latest analysis directory: {latest_analysis_dir}")

        # Show previous analysis runs
        if len(analysis_dirs) > 1:
            st.subheader("Previous Analysis Runs")
            for i, analysis_dir in enumerate(analysis_dirs[1:5]):  # Show up to 4 previous runs
                timestamp = os.path.basename(analysis_dir)
                st.write(f"{i+1}. {timestamp}")
        
        return True
    return False

def render_csv_results(latest_analysis_dir):
    """Render CSV results data with PCAP extraction functionality."""
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

            # Find the original PCAP file and conn.log file
            pcap_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                  "ai-model", "pcaps")
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
                # Display the results with extraction capability
                st.write("Click 'Extract PCAP' for any anomalous connection to extract the raw network flow:")
                
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

                    # Create expander
                    expander = st.expander(expander_label, expanded=False)

                    # Use the expander context
                    with expander:
                        # Display all row data
                        for col in results_df.columns:
                            st.write(f"**{col}:** {row[col]}")

                        # Add Extract PCAP button
                        if st.button(f"Extract PCAP", key=f"extract_{uid}"):
                            with extract_status:
                                st.info(f"Extracting flow for UID: {uid}...")
                            
                            output_path = extract_pcap_for_uid(uid, conn_log_path, pcap_path, latest_analysis_dir)

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

def render_legacy_graphs():
    """Render legacy graphs from the graphs directory."""
    graphs_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                            "ai-model", "graphs")
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
                visualize_results = import_visualize_results()
                
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
        return True
    return False

def render_labeled_anomalies():
    """Render labeled anomalies section."""
    labeled_anomalies_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                        "ai-model", "labeled_anomalies.csv")

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

def render_reports_page():
    """Render the complete reports and visualizations page."""
    st.title("📊 Reports and Visualizations")

    # Try to render latest analysis results first
    has_analysis_results = render_latest_analysis_results()
    
    # If no analysis results, try legacy graphs
    if not has_analysis_results:
        has_legacy_graphs = render_legacy_graphs()
        if not has_legacy_graphs:
            st.info("No visualization graphs available. Run a scan or upload a PCAP file in the Scanning section, then generate graphs.")

    # Always render labeled anomalies section
    render_labeled_anomalies()