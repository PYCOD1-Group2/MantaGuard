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
    # Get the project root directory (three levels up from src/pages/)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    visualize_results_path = os.path.join(project_root, 'ai-model', 'visualize_results.py')
    spec = importlib.util.spec_from_file_location("visualize_results", visualize_results_path)
    visualize_results = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(visualize_results)
    return visualize_results

def extract_pcap_for_uid(uid, conn_log_path, pcap_path, latest_analysis_dir):
    """Extract PCAP for a specific UID."""
    try:
        # Create forensics directory if it doesn't exist
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        forensics_dir = os.path.join(project_root, "ai-model", "forensics")
        os.makedirs(forensics_dir, exist_ok=True)

        # Determine the output path based on the analysis directory
        analysis_dir_name = os.path.basename(latest_analysis_dir)
        forensics_subdir = os.path.join(forensics_dir, analysis_dir_name)
        os.makedirs(forensics_subdir, exist_ok=True)
        output_filename = f"{uid}.pcap"
        output_path = os.path.join(forensics_subdir, output_filename)

        # Build the command to run extract_flow_by_uid.py
        extract_script_path = os.path.join(project_root, "ai-model", "extract_flow_by_uid.py")
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
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    analysis_results_dir = os.path.join(project_root, "ai-model", "output", "analysis_results")
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
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            pcap_dir = os.path.join(project_root, "ai-model", "pcaps")
            zeek_logs_dir = os.path.join(latest_analysis_dir, "zeek_logs")

            # Find the most recent PCAP file
            pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap"))
            pcap_path = max(pcap_files, key=os.path.getmtime) if pcap_files else None

            # Find the conn.log file
            conn_log_path = os.path.join(zeek_logs_dir, "conn.log") if os.path.exists(zeek_logs_dir) else None

            # Always show the dataframe first for quick overview
            st.subheader("Analysis Results")
            
            # Add selection column to dataframe for interactive selection
            selection_df = display_df.copy()
            selection_df.insert(0, "Select", False)
            
            # Use data_editor to allow row selection
            edited_df = st.data_editor(
                selection_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Select": st.column_config.CheckboxColumn("Select", width="small"),
                    "uid": st.column_config.TextColumn("UID", width="medium"),
                    "prediction": st.column_config.TextColumn("Prediction", width="small"),
                    "score": st.column_config.NumberColumn("Score", format="%.4f", width="small") if "score" in display_df.columns else None,
                    "anomaly_score": st.column_config.NumberColumn("Score", format="%.4f", width="small") if "anomaly_score" in display_df.columns else None,
                    "proto": st.column_config.TextColumn("Protocol", width="small"),
                    "service": st.column_config.TextColumn("Service", width="small")
                },
                disabled=[col for col in selection_df.columns if col != "Select"],  # Only allow editing Select column
                key="results_selector"
            )
            
            if pcap_path and conn_log_path and os.path.exists(conn_log_path):
                # PCAP extraction section
                st.subheader("PCAP Extraction")
                
                # Find selected rows
                selected_rows = edited_df[edited_df["Select"] == True]
                
                if len(selected_rows) > 0:
                    # Show selected connections info
                    num_selected = len(selected_rows)
                    selected_uids = selected_rows['uid'].tolist()
                    
                    if num_selected == 1:
                        selected_row = selected_rows.iloc[0]
                        prediction = selected_row.get('prediction', 'unknown')
                        score = selected_row.get('score', selected_row.get('anomaly_score', 0))
                        st.info(f"Selected connection: UID {selected_uids[0]} | Prediction: {prediction} | Score: {score:.4f}")
                    else:
                        st.info(f"Selected {num_selected} connections: {', '.join(selected_uids[:3])}{' ...' if num_selected > 3 else ''}")
                    
                    # Extract PCAP button
                    extract_label = f"Extract PCAP{'s' if num_selected > 1 else ''}"
                    if st.button(extract_label, key="extract_selected_pcap"):
                        # Extract all selected PCAPs
                        extracted_files = []
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        for i, (_, row) in enumerate(selected_rows.iterrows()):
                            uid = row['uid']
                            status_text.text(f"Extracting PCAP {i+1}/{num_selected}: {uid}")
                            progress_bar.progress((i) / num_selected)
                            
                            output_path = extract_pcap_for_uid(uid, conn_log_path, pcap_path, latest_analysis_dir)
                            if output_path:
                                extracted_files.append((uid, output_path))
                        
                        progress_bar.progress(1.0)
                        status_text.text("Extraction complete!")
                        
                        if extracted_files:
                            st.success(f"Successfully extracted {len(extracted_files)} PCAP file{'s' if len(extracted_files) > 1 else ''}")
                            
                            # Download buttons section
                            st.write("**Download extracted PCAPs:**")
                            for uid, file_path in extracted_files:
                                with open(file_path, 'rb') as f:
                                    pcap_data = f.read()
                                
                                st.download_button(
                                    label=f"📁 Download {uid}.pcap",
                                    data=pcap_data,
                                    file_name=os.path.basename(file_path),
                                    mime="application/vnd.tcpdump.pcap",
                                    key=f"download_{uid}"
                                )
                            
                            # Optional: Create a ZIP file with all PCAPs for batch download
                            if len(extracted_files) > 1:
                                import zipfile
                                import io
                                
                                zip_buffer = io.BytesIO()
                                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                                    for uid, file_path in extracted_files:
                                        zip_file.write(file_path, os.path.basename(file_path))
                                
                                zip_buffer.seek(0)
                                
                                st.download_button(
                                    label=f"📦 Download All PCAPs as ZIP ({len(extracted_files)} files)",
                                    data=zip_buffer.getvalue(),
                                    file_name=f"extracted_pcaps_{len(extracted_files)}_files.zip",
                                    mime="application/zip",
                                    key="download_all_pcaps_zip"
                                )
                        else:
                            st.error("No PCAP files could be extracted. Check that the connections exist in the original capture.")
                else:
                    st.info("👆 Check the 'Select' checkbox for any connection in the table above to extract its PCAP.")
            else:
                st.info("PCAP extraction not available - missing original PCAP file or Zeek logs.")

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
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    graphs_dir = os.path.join(project_root, "ai-model", "graphs")
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
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    labeled_anomalies_path = os.path.join(project_root, "ai-model", "labeled_anomalies.csv")

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
    
    # Process any pending state updates (but don't trigger reruns)
    from src.utils.session_state import process_state_updates
    process_state_updates()

    # Try to render latest analysis results first
    has_analysis_results = render_latest_analysis_results()
    
    # If no analysis results, try legacy graphs
    if not has_analysis_results:
        has_legacy_graphs = render_legacy_graphs()
        if not has_legacy_graphs:
            st.info("No visualization graphs available. Run a scan or upload a PCAP file in the Scanning section, then generate graphs.")

    # Always render labeled anomalies section
    render_labeled_anomalies()