import sys
import os
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_from_directory
import threading
import queue
from datetime import datetime
import pandas as pd
import subprocess
import glob
import importlib.util
import time
import csv
import netifaces

# Set matplotlib backend to non-GUI to prevent threading warnings
import matplotlib
matplotlib.use('Agg')

# Add the current directory to the Python path so we can import from src
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.utils.config import ensure_directories, get_base64_of_bin_file

app = Flask(__name__)
app.secret_key = 'mantaguard_secret_key_change_in_production'  # Change this in production!

# Global queues for thread communication
state_updates_queue = queue.Queue()
error_queue = queue.Queue()

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
    # Get the project root directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    
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

def get_security_analytics():
    """Generate security analytics from historical data."""
    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        
        # Get all analysis results directories
        results_dir = os.path.join(project_root, "ai-model", "output", "analysis_results")
        
        analytics = {
            'total_scans': 0,
            'total_connections': 0,
            'anomaly_count': 0,
            'normal_count': 0,
            'protocol_distribution': {},
            'threat_timeline': [],
            'recent_scans': [],
            'top_threats': [],
            'network_activity': {
                'peak_hours': {},
                'protocol_trends': {},
                'anomaly_rate': 0
            }
        }
        
        if not os.path.exists(results_dir):
            return analytics
        
        # Process each analysis directory
        for scan_dir in sorted(os.listdir(results_dir), reverse=True):
            scan_path = os.path.join(results_dir, scan_dir)
            if not os.path.isdir(scan_path):
                continue
                
            csv_file = os.path.join(scan_path, 'prediction_results.csv')
            if not os.path.exists(csv_file):
                continue
                
            try:
                # Read prediction results
                df = pd.read_csv(csv_file)
                analytics['total_scans'] += 1
                analytics['total_connections'] += len(df)
                
                # Count anomalies vs normal
                anomalies = len(df[df['prediction'] == 'anomaly'])
                normals = len(df[df['prediction'] == 'normal'])
                analytics['anomaly_count'] += anomalies
                analytics['normal_count'] += normals
                
                # Get scan timestamp from directory name
                scan_time = scan_dir.replace('_', ' ')
                analytics['recent_scans'].append({
                    'timestamp': scan_time,
                    'connections': len(df),
                    'anomalies': anomalies,
                    'anomaly_rate': round((anomalies / len(df)) * 100, 2) if len(df) > 0 else 0,
                    'directory': scan_dir
                })
                
                # Protocol analysis with conn.log
                conn_log = os.path.join(scan_path, 'zeek_logs', 'conn.log')
                if os.path.exists(conn_log):
                    try:
                        with open(conn_log, 'r') as f:
                            lines = f.readlines()
                        
                        # Find fields line
                        fields_line = None
                        for line in lines:
                            if line.startswith('#fields'):
                                fields_line = line.strip()
                                break
                        
                        if fields_line:
                            field_names = fields_line.split('\t')[1:]
                            data_lines = [line.strip() for line in lines 
                                        if not line.startswith('#') and line.strip()]
                            
                            for line in data_lines:
                                values = line.split('\t')
                                if len(values) >= len(field_names):
                                    proto = values[field_names.index('proto')] if 'proto' in field_names else 'unknown'
                                    analytics['protocol_distribution'][proto] = analytics['protocol_distribution'].get(proto, 0) + 1
                    except Exception:
                        pass
                        
            except Exception as e:
                print(f"Error processing scan {scan_dir}: {str(e)}")
                continue
        
        # Calculate overall anomaly rate
        total_connections = analytics['total_connections']
        if total_connections > 0:
            analytics['network_activity']['anomaly_rate'] = round(
                (analytics['anomaly_count'] / total_connections) * 100, 2
            )
        
        # Limit recent scans to last 10
        analytics['recent_scans'] = analytics['recent_scans'][:10]
        
        # Generate threat timeline
        for scan in analytics['recent_scans']:
            if scan['anomalies'] > 0:
                analytics['threat_timeline'].append({
                    'timestamp': scan['timestamp'],
                    'threat_count': scan['anomalies'],
                    'severity': 'high' if scan['anomaly_rate'] > 50 else 'medium' if scan['anomaly_rate'] > 20 else 'low'
                })
        
        return analytics
        
    except Exception as e:
        print(f"Error generating analytics: {str(e)}")
        return {
            'total_scans': 0,
            'total_connections': 0,
            'anomaly_count': 0,
            'normal_count': 0,
            'protocol_distribution': {},
            'threat_timeline': [],
            'recent_scans': [],
            'top_threats': [],
            'network_activity': {'anomaly_rate': 0}
        }

def initialize_session():
    """Initialize session variables."""
    if 'scanning' not in session:
        session['scanning'] = False
    if 'processing' not in session:
        session['processing'] = False
    if 'predictions_file' not in session:
        session['predictions_file'] = None
    if 'analysis_dir' not in session:
        session['analysis_dir'] = None
    if 'scan_completed' not in session:
        session['scan_completed'] = False
    if 'success_message_displayed' not in session:
        session['success_message_displayed'] = False
    if 'active_tab' not in session:
        session['active_tab'] = 0
    if 'graphs_generated' not in session:
        session['graphs_generated'] = False
    if 'network_interfaces' not in session:
        session['network_interfaces'] = get_network_interfaces()

@app.before_request
def before_request():
    """Initialize session before each request."""
    initialize_session()
    ensure_directories()

@app.route('/')
def home():
    """Render the home page."""
    hero_banner_base64 = get_base64_of_bin_file('content/hero-banner.png')
    logo_base64 = get_base64_of_bin_file('content/Group3.png')
    
    return render_template('home.html', 
                         hero_banner_base64=hero_banner_base64,
                         logo_base64=logo_base64)

@app.route('/scanning')
def scanning():
    """Render the scanning page."""
    return render_template('scanning.html', 
                         interfaces=session['network_interfaces'],
                         scanning=session['scanning'],
                         processing=session['processing'],
                         scan_completed=session['scan_completed'],
                         active_tab=session['active_tab'])

@app.route('/reports')
def reports():
    """Render the reports page."""
    # Get analytics data
    analytics = get_security_analytics()
    return render_template('reports.html', analytics=analytics)

@app.route('/fix-patches')
def fix_patches():
    """Render the fix & patches page."""
    return render_template('fix_patches.html')

@app.route('/api/refresh_interfaces', methods=['POST'])
def refresh_interfaces():
    """Refresh network interfaces."""
    session['network_interfaces'] = get_network_interfaces()
    return jsonify({'interfaces': session['network_interfaces']})

@app.route('/api/start_capture', methods=['POST'])
def start_capture():
    """Start network capture."""
    data = request.get_json()
    interface = data.get('interface')
    duration = data.get('duration', 60)
    
    if session['scanning']:
        return jsonify({'error': 'Capture already in progress'}), 400
    
    # Reset session state
    session['scanning'] = True
    session['scan_completed'] = False
    session['success_message_displayed'] = False
    session['processing'] = False
    
    # Create pcaps directory if it doesn't exist
    project_root = os.path.dirname(os.path.abspath(__file__))
    pcap_dir = os.path.join(project_root, "ai-model", "pcaps")
    os.makedirs(pcap_dir, exist_ok=True)

    # Generate output path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(pcap_dir, f"capture_{timestamp}.pcap")
    session['pcap_path'] = output_path
    session['capture_start_time'] = time.time()
    session['capture_duration'] = duration

    # Run capture in separate thread
    def run_capture_thread():
        try:
            project_root = os.path.dirname(os.path.abspath(__file__))
            original_cwd = os.getcwd()
            os.chdir(project_root)
            
            timed_capture, visualize_results = import_ai_modules()
            
            # Network capture
            timed_capture.run_capture(interface, duration, output_path)
            
            # Zeek processing
            results, analysis_dir = timed_capture.analyze_pcap_with_zeek(output_path)

            # Save results to CSV
            csv_path = os.path.join(analysis_dir, 'prediction_results.csv')
            results_df = pd.DataFrame(results)
            results_df.to_csv(csv_path, index=False)

            # Generate visualizations
            try:
                data, has_true_label = visualize_results.load_data(csv_path)
                visualize_results.create_score_histogram(data, analysis_dir)
                visualize_results.create_time_series(data, analysis_dir)

                if has_true_label:
                    visualize_results.create_roc_curve(data, has_true_label, analysis_dir)
                    visualize_results.create_precision_recall_curve(data, has_true_label, analysis_dir)
                    visualize_results.create_confusion_matrix(data, has_true_label, analysis_dir)
            except Exception as vis_error:
                print(f"Warning: Failed to generate visualizations: {str(vis_error)}")
            
            # Store results in global variables (thread-safe)
            with app.app_context():
                app.analysis_results = {
                    'analysis_dir': analysis_dir,
                    'predictions_file': csv_path,
                    'processing': False,
                    'scan_completed': True,
                    'scanning': False
                }
            
        except Exception as e:
            print(f"Error during capture or analysis: {str(e)}")
            with app.app_context():
                app.analysis_results = {
                    'processing': False,
                    'scanning': False,
                    'error': str(e)
                }
        finally:
            os.chdir(original_cwd)

    thread = threading.Thread(target=run_capture_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Capture started'})

@app.route('/api/stop_capture', methods=['POST'])
def stop_capture():
    """Stop network capture."""
    session['scanning'] = False
    return jsonify({'success': True, 'message': 'Capture stopped'})

@app.route('/api/capture_status')
def capture_status():
    """Get current capture status."""
    status = {
        'scanning': session['scanning'],
        'processing': session['processing'],
        'scan_completed': session['scan_completed'],
        'remaining_time': 0,
        'progress': 0,
        'status_text': ''
    }
    
    # Check if we have analysis progress from background thread
    if hasattr(app, 'analysis_progress'):
        status['progress'] = app.analysis_progress.get('progress', 0)
        status['status_text'] = app.analysis_progress.get('status', '')
        status['processing'] = app.analysis_progress.get('processing', False)
        session['processing'] = status['processing']
        
        
        # Only clear progress when analysis is completely done
        if not status['processing'] and status['progress'] >= 1.0:
            delattr(app, 'analysis_progress')
    
    # Check if we have analysis results from background thread
    if hasattr(app, 'analysis_results'):
        if 'scan_completed' in app.analysis_results:
            session['scan_completed'] = app.analysis_results['scan_completed']
            status['scan_completed'] = True
        if 'processing' in app.analysis_results:
            session['processing'] = app.analysis_results['processing']
            status['processing'] = False
        if 'scanning' in app.analysis_results:
            session['scanning'] = app.analysis_results['scanning']
            status['scanning'] = False
        if 'analysis_dir' in app.analysis_results:
            session['analysis_dir'] = app.analysis_results['analysis_dir']
        if 'predictions_file' in app.analysis_results:
            session['predictions_file'] = app.analysis_results['predictions_file']
        # Clear the results after updating session
        delattr(app, 'analysis_results')
    
    if session['scanning'] and 'capture_start_time' in session:
        elapsed_time = time.time() - session['capture_start_time']
        remaining_time = max(0, session['capture_duration'] - elapsed_time)
        status['remaining_time'] = remaining_time
        status['progress'] = min(elapsed_time / session['capture_duration'], 1.0)
    
    return jsonify(status)

@app.route('/api/upload_pcap', methods=['POST'])
def upload_pcap():
    """Handle PCAP file upload."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Create pcaps directory if it doesn't exist
    project_root = os.path.dirname(os.path.abspath(__file__))
    pcap_dir = os.path.join(project_root, "ai-model", "pcaps")
    os.makedirs(pcap_dir, exist_ok=True)

    # Generate save path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_path = os.path.join(pcap_dir, f"uploaded_{timestamp}_{file.filename}")
    
    # Save the file
    file.save(save_path)
    
    return jsonify({'success': True, 'path': save_path, 'filename': file.filename})

@app.route('/api/analyze_pcap', methods=['POST'])
def analyze_pcap():
    """Analyze uploaded PCAP file."""
    data = request.get_json()
    pcap_path = data.get('path')
    
    if not pcap_path or not os.path.exists(pcap_path):
        return jsonify({'error': 'Invalid PCAP file path'}), 400
    
    # Reset session state
    session['scan_completed'] = False
    session['success_message_displayed'] = False
    session['processing'] = True
    session['pcap_path'] = pcap_path

    # Start analysis in background thread
    def analyze_thread():
        try:
            project_root = os.path.dirname(os.path.abspath(__file__))
            original_cwd = os.getcwd()
            os.chdir(project_root)
            
            # Step 1: Starting analysis (10%)
            time.sleep(0.5)  # Small delay to ensure frontend has started polling
            with app.app_context():
                app.analysis_progress = {
                    'progress': 0.1,
                    'status': 'Starting PCAP analysis...',
                    'processing': True
                }
            
            # Step 2: Running Zeek analysis (30%)
            time.sleep(1)  # Give time for the status to be read
            with app.app_context():
                app.analysis_progress = {
                    'progress': 0.3,
                    'status': 'Processing PCAP with Zeek...',
                    'processing': True
                }
            
            # Run analyze_capture.py script
            analyze_script_path = os.path.join(project_root, "ai-model", "analyze_capture.py")
            cmd = f"python {analyze_script_path} {pcap_path}"
            
            process = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)

            # Step 3: ML Analysis (60%)
            with app.app_context():
                app.analysis_progress = {
                    'progress': 0.6,
                    'status': 'Running ML analysis...',
                    'processing': True
                }

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

            # Step 4: Generate visualizations (80%)
            with app.app_context():
                app.analysis_progress = {
                    'progress': 0.8,
                    'status': 'Generating visualizations...',
                    'processing': True
                }

            # Generate visualizations
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
                print(f"Warning: Failed to generate visualizations: {str(vis_error)}")

            # Step 5: Complete (100%)
            with app.app_context():
                app.analysis_progress = {
                    'progress': 1.0,
                    'status': 'Analysis completed successfully!',
                    'processing': False
                }

            # Store results in global variables (thread-safe)
            with app.app_context():
                # Use a global storage mechanism since we can't access session from thread
                app.analysis_results = {
                    'analysis_dir': analysis_dir,
                    'predictions_file': csv_path,
                    'scan_completed': True,
                    'processing': False
                }

        except Exception as e:
            print(f"Error during analysis: {str(e)}")
            with app.app_context():
                app.analysis_progress = {
                    'progress': 0,
                    'status': f'Error: {str(e)}',
                    'processing': False
                }
                app.analysis_results = {
                    'processing': False,
                    'error': str(e)
                }
        finally:
            os.chdir(original_cwd)

    thread = threading.Thread(target=analyze_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Analysis started'})

@app.route('/api/results')
def get_results():
    """Get analysis results."""
    if not session['predictions_file'] or not os.path.exists(session['predictions_file']):
        return jsonify({'error': 'No results available'}), 404
    
    # Load predictions from file
    try:
        results_df = pd.read_csv(session['predictions_file'])
        predictions = results_df.to_dict('records')
        
        # Try to enrich with protocol data from conn.log if available
        analysis_dir = session.get('analysis_dir')
        if analysis_dir:
            conn_log_path = os.path.join(analysis_dir, 'zeek_logs', 'conn.log')
            if os.path.exists(conn_log_path):
                try:
                    # Read conn.log with proper handling of Zeek format
                    with open(conn_log_path, 'r') as f:
                        lines = f.readlines()
                    
                    # Find the fields line to get proper column names
                    fields_line = None
                    for line in lines:
                        if line.startswith('#fields'):
                            fields_line = line.strip()
                            break
                    
                    if fields_line:
                        # Extract field names from the fields line
                        field_names = fields_line.split('\t')[1:]  # Skip '#fields'
                        
                        # Read data lines (skip comments and empty lines)
                        data_lines = [line.strip() for line in lines 
                                    if not line.startswith('#') and line.strip()]
                        
                        if data_lines:
                            # Parse data into DataFrame
                            data = []
                            for line in data_lines:
                                values = line.split('\t')
                                # Handle variable number of fields gracefully
                                if len(values) >= len(field_names):
                                    # Take only the expected number of fields
                                    values = values[:len(field_names)]
                                elif len(values) < len(field_names):
                                    # Pad with empty values if needed
                                    values.extend(['-'] * (len(field_names) - len(values)))
                                
                                data.append(dict(zip(field_names, values)))
                            
                            conn_df = pd.DataFrame(data)
                            
                            # Create protocol lookup dict
                            protocol_dict = dict(zip(conn_df['uid'], conn_df['proto']))
                            service_dict = dict(zip(conn_df['uid'], conn_df.get('service', ['-'] * len(conn_df))))
                            port_dict = dict(zip(conn_df['uid'], conn_df['id.resp_p']))
                            
                            # Add protocol info to predictions
                            for prediction in predictions:
                                uid = prediction['uid']
                                proto = protocol_dict.get(uid, 'not_found')
                                service = service_dict.get(uid, '-')
                                port = port_dict.get(uid, '-')
                                
                                # Use transport protocol (tcp/udp/icmp) - this should never be "-"
                                prediction['proto'] = proto
                                prediction['service'] = service if service != '-' else 'undetected'
                                prediction['dest_port'] = port
                        else:
                            # Fallback if no data found
                            for prediction in predictions:
                                prediction['proto'] = 'no_data'
                                prediction['service'] = 'no_data'
                                prediction['dest_port'] = 'no_data'
                    else:
                        # Fallback if no fields line found
                        for prediction in predictions:
                            prediction['proto'] = 'no_fields'
                            prediction['service'] = 'no_fields'
                            prediction['dest_port'] = 'no_fields'
                        
                except Exception as proto_error:
                    # Add default values if we can't load protocol data
                    for prediction in predictions:
                        prediction['proto'] = 'error'
                        prediction['service'] = 'error'
                        prediction['dest_port'] = 'error'
            else:
                # Add default values if conn.log doesn't exist
                for prediction in predictions:
                    prediction['proto'] = 'no_conn_log'
                    prediction['service'] = 'no_conn_log'
                    prediction['dest_port'] = 'no_conn_log'
        
    except Exception as e:
        return jsonify({'error': f'Failed to load results: {str(e)}'}), 500
    
    # Extract scan ID from analysis directory path
    scan_id = None
    if session['analysis_dir']:
        scan_id = os.path.basename(session['analysis_dir'])
    
    results = {
        'predictions': predictions,
        'analysis_dir': session['analysis_dir'],
        'graphs_available': session['graphs_generated'],
        'scan_id': scan_id
    }
    
    # Get available visualization files
    if session['analysis_dir']:
        graph_files = glob.glob(os.path.join(session['analysis_dir'], "*.png"))
        results['visualizations'] = [os.path.basename(f) for f in graph_files]
    
    return jsonify(results)

@app.route('/api/label_prediction', methods=['POST'])
def label_prediction():
    """Label a prediction."""
    data = request.get_json()
    uid = data.get('uid')
    label = data.get('label')
    
    if not session['predictions_file'] or not os.path.exists(session['predictions_file']):
        return jsonify({'error': 'No predictions available'}), 400
    
    try:
        # Load predictions from file
        df = pd.read_csv(session['predictions_file'])
        selected_row = df[df['uid'] == uid].iloc[0].to_dict()
        selected_row['user_label'] = label
        
        # Append to labeled_anomalies.csv
        project_root = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(project_root, "ai-model", "labeled_anomalies.csv")
        
        file_exists = os.path.isfile(csv_path)
        
        with open(csv_path, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=selected_row.keys())
            if not file_exists:
                writer.writeheader()
            writer.writerow(selected_row)
        
        return jsonify({'success': True, 'message': f'Label "{label}" added for UID {uid}'})
    except Exception as e:
        return jsonify({'error': f'Failed to label prediction: {str(e)}'}), 500

@app.route('/images/<path:filename>')
def serve_image(filename):
    """Serve analysis images."""
    if session['analysis_dir']:
        return send_from_directory(session['analysis_dir'], filename)
    return "Image not found", 404

@app.route('/content/<path:filename>')
def serve_content(filename):
    """Serve static content files."""
    return send_from_directory('content', filename)

@app.route('/api/reports/analytics')
def get_analytics_api():
    """API endpoint for analytics data."""
    analytics = get_security_analytics()
    return jsonify(analytics)

@app.route('/api/reports/scan/<scan_id>')
def get_scan_details(scan_id):
    """Get detailed information about a specific scan."""
    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        scan_path = os.path.join(project_root, "ai-model", "output", "analysis_results", scan_id)
        
        if not os.path.exists(scan_path):
            return jsonify({'error': 'Scan not found'}), 404
        
        # Read prediction results
        csv_file = os.path.join(scan_path, 'prediction_results.csv')
        if not os.path.exists(csv_file):
            return jsonify({'error': 'No results found for this scan'}), 404
        
        df = pd.read_csv(csv_file)
        
        # Try to read the original conn.log to get protocol information
        conn_log_path = os.path.join(scan_path, 'zeek_logs', 'conn.log')
        if os.path.exists(conn_log_path):
            try:
                # Read conn.log with proper column parsing
                with open(conn_log_path, 'r') as f:
                    for line in f:
                        if line.startswith('#fields'):
                            column_names = line.strip().split('\t')[1:]
                            break
                
                conn_df = pd.read_csv(
                    conn_log_path,
                    sep='\t',
                    comment='#',
                    names=column_names,
                    na_values='-',
                    low_memory=False
                )
                
                # Join with prediction results on uid to get protocol info
                if 'uid' in conn_df.columns and 'uid' in df.columns:
                    # Select only uid and proto columns from conn.log
                    conn_subset = conn_df[['uid', 'proto']].copy()
                    # Merge with prediction results
                    df = df.merge(conn_subset, on='uid', how='left')
                    
            except Exception as e:
                print(f"Warning: Could not load protocol data from conn.log: {e}")
                # Add empty protocol column if merge failed
                df['proto'] = 'unknown'
        else:
            # Add empty protocol column if conn.log not found
            df['proto'] = 'unknown'
        
        # Get visualizations
        visualizations = []
        viz_files = glob.glob(os.path.join(scan_path, "*.png"))
        for viz_file in viz_files:
            visualizations.append(os.path.basename(viz_file))
        
        scan_details = {
            'scan_id': scan_id,
            'total_connections': len(df),
            'anomalies': len(df[df['prediction'] == 'anomaly']),
            'normal': len(df[df['prediction'] == 'normal']),
            'anomaly_rate': round((len(df[df['prediction'] == 'anomaly']) / len(df)) * 100, 2) if len(df) > 0 else 0,
            'visualizations': visualizations,
            'connections': df.to_dict('records')[:100]  # Limit to first 100 for performance
        }
        
        return jsonify(scan_details)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/extract_pcaps', methods=['POST'])
def extract_pcaps():
    """Extract individual connections as separate PCAP files."""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        connection_uids = data.get('connection_uids', [])
        
        if not scan_id or not connection_uids:
            return jsonify({'error': 'Missing scan_id or connection_uids'}), 400
        
        project_root = os.path.dirname(os.path.abspath(__file__))
        scan_path = os.path.join(project_root, "ai-model", "output", "analysis_results", scan_id)
        
        if not os.path.exists(scan_path):
            return jsonify({'error': 'Scan not found'}), 404
        
        # Create forensics directory with timestamp
        forensics_dir = os.path.join(project_root, "ai-model", "forensics")
        os.makedirs(forensics_dir, exist_ok=True)
        
        # Create timestamped subdirectory matching the scan
        output_dir = os.path.join(forensics_dir, scan_id)
        os.makedirs(output_dir, exist_ok=True)
        
        # Find the original PCAP file for this scan
        # Look for PCAP files in the pcaps directory that match the timestamp pattern
        pcaps_dir = os.path.join(project_root, "ai-model", "pcaps")
        original_pcap = None
        
        # Try to find PCAP file by matching timestamp pattern
        for pcap_file in glob.glob(os.path.join(pcaps_dir, "*.pcap*")):
            # Extract timestamp from PCAP filename
            basename = os.path.basename(pcap_file)
            if scan_id in basename or basename.startswith('capture_' + scan_id.split('_')[0]):
                original_pcap = pcap_file
                break
        
        if not original_pcap or not os.path.exists(original_pcap):
            return jsonify({'error': 'Original PCAP file not found for this scan'}), 404
        
        # Use the extract_flow_by_uid.py script to extract connections
        extract_script_path = os.path.join(project_root, "ai-model", "extract_flow_by_uid.py")
        
        if not os.path.exists(extract_script_path):
            return jsonify({'error': 'PCAP extraction script not found'}), 500
        
        extracted_count = 0
        extraction_errors = []
        
        for uid in connection_uids:
            try:
                # Find the conn.log file for this scan
                conn_log_path = os.path.join(scan_path, 'zeek_logs', 'conn.log')
                
                # Run extraction script for this UID - it will create files in its own structure
                cmd = f"uv run python {extract_script_path} --uid {uid} --conn-log {conn_log_path} --pcap {original_pcap} --analysis-dir {scan_path}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                
                # The script creates files in ai-model/forensics/{scan_id}/{uid}.pcap
                expected_output = os.path.join(output_dir, f"{uid}.pcap")
                
                if result.returncode == 0 and os.path.exists(expected_output):
                    extracted_count += 1
                else:
                    extraction_errors.append(f"UID {uid}: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                extraction_errors.append(f"UID {uid}: Extraction timeout")
            except Exception as e:
                extraction_errors.append(f"UID {uid}: {str(e)}")
        
        response_data = {
            'success': True,
            'extracted_count': extracted_count,
            'total_requested': len(connection_uids),
            'output_path': output_dir
        }
        
        if extraction_errors:
            response_data['warnings'] = extraction_errors
        
        return jsonify(response_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)