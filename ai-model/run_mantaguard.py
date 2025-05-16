import os
import subprocess
import sys
import glob
import re  # Added import re at the top level
from datetime import datetime

# Define default values
DEFAULT_TRAIN_DATA = "data/KDDTrain_normal.csv"
DEFAULT_TEST_DATA = "data/KDDTest.csv"
DEFAULT_NET_TRAFFIC = "data/KDDTest.csv"  # Default KDD test file
DEFAULT_BASE_MODEL = "output/base_model"
DEFAULT_KNN_MODEL = "output/knn_model"
DEFAULT_K_VALUE = "5"
DEFAULT_THRESHOLD = "2.5"

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def select_option(prompt, options):
    """Display a menu and get user selection."""
    print(prompt)
    print()

    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")

    print()

    while True:
        try:
            choice = int(input(f"Enter your choice [1-{len(options)}]: "))
            if 1 <= choice <= len(options):
                return options[choice - 1]
            else:
                print(f"Invalid choice. Please enter a number between 1 and {len(options)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def get_input(prompt, default):
    """Get input with a default value."""
    user_input = input(f"{prompt} [{default}]: ")
    return user_input if user_input else default

def select_packet_file(prompt, default):
    """Display a list of available packet files and get user selection."""
    # Find all KDD CSV files in data directory
    kdd_files = glob.glob("data/KDD*.csv")

    # If no files found, fall back to manual input
    if not kdd_files:
        print("No KDD CSV files found in data directory.")
        return get_input(prompt, default)

    # Sort files alphabetically
    kdd_files.sort()

    # Display the files
    print(prompt)
    print()
    for i, file_path in enumerate(kdd_files, 1):
        print(f"  {i}. {file_path}")

    print(f"  {len(kdd_files) + 1}. (Enter manually)")
    print()

    # Get user selection
    while True:
        try:
            choice = int(input(f"Enter your choice [1-{len(kdd_files) + 1}]: "))
            if 1 <= choice <= len(kdd_files):
                return kdd_files[choice - 1]
            elif choice == len(kdd_files) + 1:
                # Manual entry
                return get_input(prompt, default)
            else:
                print(f"Invalid choice. Please enter a number between 1 and {len(kdd_files) + 1}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def get_yes_no(prompt, default="n"):
    """Get a yes/no input."""
    default_display = "Y/n" if default.lower() == "y" else "y/N"
    user_input = input(f"{prompt} [{default_display}]: ")
    user_input = user_input if user_input else default

    return user_input.lower().startswith("y")

def run_command(command):
    """Run a shell command and display output."""
    print(f"Running command: {command}")
    print("-" * 50)

    try:
        process = subprocess.run(command, shell=True, check=True)
        print("-" * 50)
        print("Command completed successfully.")
    except subprocess.CalledProcessError as e:
        print("-" * 50)
        print(f"Command failed with exit code {e.returncode}")

    input("\nPress Enter to continue...")

def train_base_model():
    """Train the base One-Class SVM model."""
    clear_screen()
    print("=" * 52)
    print("           Train Base Model (One-Class SVM)         ")
    print("=" * 52)
    print()
    print("This will train the base One-Class SVM model using normal traffic data.")
    print()

    train_data = get_input("Enter training data path", DEFAULT_TRAIN_DATA)
    test_data = get_input("Enter test data path", DEFAULT_TEST_DATA)
    output_dir = get_input("Enter output model directory", DEFAULT_BASE_MODEL)

    print()
    command = f"python src/train_nslkdd.py --train {train_data} --test {test_data} --output {output_dir}"
    print("Command to execute:")
    print(command)
    print()

    if get_yes_no("Do you want to proceed?", "y"):
        run_command(command)
    else:
        print("Operation cancelled.")
        input("\nPress Enter to return to the main menu...")

def init_knn_model():
    """Initialize the Incremental KNN model."""
    clear_screen()
    print("=" * 52)
    print("               Initialize KNN Model                 ")
    print("=" * 52)
    print()
    print("This will initialize an Incremental KNN model with normal traffic data.")
    print()

    train_data = get_input("Enter normal traffic data path", DEFAULT_TRAIN_DATA)
    output_dir = get_input("Enter KNN model output directory", DEFAULT_KNN_MODEL)
    base_model = get_input("Enter base model directory to reuse scaler", DEFAULT_BASE_MODEL)

    k_value = get_input("Enter k value for K-nearest neighbors", DEFAULT_K_VALUE)
    threshold = get_input("Enter distance threshold for anomaly detection", DEFAULT_THRESHOLD)

    create_scaler = get_yes_no("Create a new scaler instead of using base model?", "n")

    print()
    command = f"python src/init_knn_model.py --train {train_data} --output {output_dir} --base-model {base_model} --k {k_value} --threshold {threshold}"

    if create_scaler:
        command += " --create-new-scaler"

    print("Command to execute:")
    print(command)
    print()

    if get_yes_no("Do you want to proceed?", "y"):
        run_command(command)
    else:
        print("Operation cancelled.")
        input("\nPress Enter to return to the main menu...")

def test_knn_model():
    """Test the KNN model."""
    clear_screen()
    print("=" * 52)
    print("                 Test KNN Model                     ")
    print("=" * 52)
    print()
    print("This will test the Incremental KNN model on network traffic data.")
    print()

    model_dir = get_input("Enter KNN model directory", DEFAULT_KNN_MODEL)
    test_data = get_input("Enter test data path", DEFAULT_TEST_DATA)

    interactive = get_yes_no("Enable interactive mode for user feedback?", "n")
    show_plots = get_yes_no("Show plots interactively? (will pause execution)", "n")

    output_dir = get_input("Enter evaluation output directory (optional, press Enter for default)", "")

    print()
    command = f"python src/test_knn.py --model {model_dir} --test {test_data}"

    if interactive:
        command += " --interactive"

    if show_plots:
        command += " --show-plots"

    if output_dir:
        command += f" --output-dir {output_dir}"

    print("Command to execute:")
    print(command)
    print()

    if get_yes_no("Do you want to proceed?", "y"):
        run_command(command)
    else:
        print("Operation cancelled.")
        input("\nPress Enter to return to the main menu...")

def enhance_knn_with_packets():
    """Enhance existing KNN model with packet capture data."""
    clear_screen()
    print("=" * 52)
    print("        Enhance KNN Model with Packet Data          ")
    print("=" * 52)
    print()
    print("This will enhance an existing KNN model with packet capture data.")
    print("The model will learn from normal network traffic in packet format.")
    print()

    # Get input parameters
    model_dir = get_input("Enter existing KNN model directory", DEFAULT_KNN_MODEL)
    packet_data = select_packet_file("Select packet capture data file", DEFAULT_NET_TRAFFIC)
    output_dir = get_input("Enter output directory (leave empty to update existing model)", model_dir)

    # Ask if packets should be labeled as normal
    normal_traffic = get_yes_no("Is this traffic normal? (No means anomaly training)", "y")

    # Create command
    command = f"python src/enhance_knn.py --model {model_dir} --packets {packet_data}"

    if output_dir != model_dir:
        command += f" --output {output_dir}"

    if not normal_traffic:
        command += " --anomaly"

    print()
    print("Command to execute:")
    print(command)
    print()

    if get_yes_no("Do you want to proceed?", "y"):
        # Check if the script exists, if not create it
        if not os.path.exists("src/enhance_knn.py"):
            print("\nEnhance KNN script not found. Creating it...")
            create_enhance_knn_script()

        run_command(command)
    else:
        print("Operation cancelled.")
        input("\nPress Enter to return to the main menu...")

def create_enhance_knn_script():
    """Create the enhance_knn.py script if it doesn't exist."""
    script_content = """#!/usr/bin/env python3
# enhance_knn.py - Enhance KNN model with packet data

import os
import sys
import argparse
from datetime import datetime

# Add parent directory to path to import custom modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.knn_packet_adapter import KNNPacketAdapter

def parse_args():
    parser = argparse.ArgumentParser(description='Enhance KNN model with packet data')
    parser.add_argument('--model', required=True, help='Path to existing KNN model directory')
    parser.add_argument('--packets', required=True, help='Path to packet capture data file')
    parser.add_argument('--output', default=None, help='Output directory for enhanced model (default: update existing)')
    parser.add_argument('--anomaly', action='store_true', help='Treat packets as anomalies instead of normal traffic')
    return parser.parse_args()

def main():
    args = parse_args()

    try:
        # Initialize the adapter
        print(f"Loading KNN model from {args.model}...")
        adapter = KNNPacketAdapter(args.model)

        # Process the packet data
        print(f"Processing packet data from {args.packets}...")
        is_normal = not args.anomaly
        output_dir = args.output if args.output else args.model

        # Enhance the model
        result = adapter.enhance_model(args.packets, is_normal=is_normal, output_dir=output_dir)

        if result:
            print(f"\\nModel enhancement complete! Model saved to {output_dir}")
            return 0
        else:
            print("\\nModel enhancement failed.")
            return 1

    except Exception as e:
        print(f"\\nError: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
"""

    # Create the script file
    script_path = "src/enhance_knn.py"
    with open(script_path, 'w') as f:
        f.write(script_content)

    # Make it executable on Unix-like systems
    if os.name != 'nt':
        os.chmod(script_path, 0o755)

    print(f"Created {script_path}")

def test_knn_with_packets():
    """Test KNN model with packet capture data."""
    clear_screen()
    print("=" * 52)
    print("          Test KNN Model with Packet Data           ")
    print("=" * 52)
    print()
    print("This will test the KNN model against packet capture data.")
    print("The model will analyze packets and report anomalies.")
    print()

    # Get input parameters
    model_dir = get_input("Enter KNN model directory", DEFAULT_KNN_MODEL)
    packet_data = select_packet_file("Select packet capture data file", DEFAULT_NET_TRAFFIC)
    output_dir = get_input("Enter evaluation output directory (optional)", "")

    # Use default output directory if not specified
    if not output_dir:
        output_dir = os.path.join(model_dir, "packet_results")

    # Create command
    command = f"python src/test_knn_packets.py --model {model_dir} --packets {packet_data} --output {output_dir}"

    print()
    print("Command to execute:")
    print(command)
    print()

    if get_yes_no("Do you want to proceed?", "y"):
        # Check if the script exists, if not create it
        if not os.path.exists("src/test_knn_packets.py"):
            print("\nTest KNN packets script not found. Creating it...")
            create_test_knn_packets_script()

        run_command(command)
    else:
        print("Operation cancelled.")
        input("\nPress Enter to return to the main menu...")

def create_test_knn_packets_script():
    """Create the test_knn_packets.py script if it doesn't exist."""
    script_content = """#!/usr/bin/env python3
# test_knn_packets.py - Test KNN model with packet data

import os
import sys
import argparse
from datetime import datetime

# Add parent directory to path to import custom modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.knn_packet_adapter import KNNPacketAdapter

def parse_args():
    parser = argparse.ArgumentParser(description='Test KNN model with packet data')
    parser.add_argument('--model', required=True, help='Path to KNN model directory')
    parser.add_argument('--packets', required=True, help='Path to packet capture data file')
    parser.add_argument('--output', required=True, help='Output directory for evaluation results')
    return parser.parse_args()

def main():
    args = parse_args()

    try:
        # Initialize the adapter
        print(f"Loading KNN model from {args.model}...")
        adapter = KNNPacketAdapter(args.model)

        # Process and test the packet data
        print(f"Processing and testing packet data from {args.packets}...")
        results_df = adapter.test_packet_data(args.packets, output_dir=args.output)

        # Show analysis results if we have data
        if not results_df.empty:
            print("\\nAnalysis Results:")
            print(f"Total packets analyzed: {len(results_df)}")

            # If we have predictions, show stats
            if 'prediction' in results_df.columns:
                normal_count = len(results_df[results_df['prediction'] == 'normal'])
                anomaly_count = len(results_df[results_df['prediction'] == 'anomaly'])
                print(f"Normal packets: {normal_count}")
                print(f"Anomalous packets: {anomaly_count}")

            print(f"\\nResults and debug information saved to: {args.output}")
            return 0
        else:
            print("\\nNo results were generated.")
            return 1

    except Exception as e:
        print(f"\\nError: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
"""

    # Create the script file
    script_path = "src/test_knn_packets.py"
    with open(script_path, 'w') as f:
        f.write(script_content)

    # Make it executable on Unix-like systems
    if os.name != 'nt':
        os.chmod(script_path, 0o755)

    print(f"Created {script_path}")

def generate_enhance_knn_script():
    """Generate a template script for enhancing KNN with packet data."""
    clear_screen()
    print("=" * 52)
    print("      Generate Enhance KNN Script Template          ")
    print("=" * 52)
    print()
    print("This will generate a template script for enhancing KNN with packet data.")
    print("The script can be used as a starting point for custom packet processing.")
    print()

    output_file = get_input("Enter output script filename", "enhance_knn.py")

    script_content = """#!/usr/bin/env python3
# enhance_knn.py - Enhance KNN model with packet data

import os
import argparse
import pandas as pd
import numpy as np
import joblib
import sys
import re  # Import re for regex operations
from datetime import datetime

# Add the parent directory to path to import custom modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.incremental_knn import IncrementalKNN

def parse_args():
    parser = argparse.ArgumentParser(description='Enhance KNN model with packet data')
    parser.add_argument('--model', required=True, help='Path to existing KNN model directory')
    parser.add_argument('--packets', required=True, help='Path to packet capture data file')
    parser.add_argument('--output', default=None, help='Output directory for enhanced model (default: update existing)')
    parser.add_argument('--anomaly', action='store_true', help='Treat packets as anomalies instead of normal traffic')
    return parser.parse_args()

def parse_packet_data(packet_file):
    \"\"\"Parse the packet capture data file into features.\"\"\"
    print(f"Parsing packet data from {packet_file}...")

    # TODO: Implement packet parsing logic
    # This should extract relevant features from the packet data format
    # Example features: protocol type, ports, packet sizes, flags, etc.

    # For now, we'll create a placeholder dataframe
    features = []

    # Read the raw packet data
    with open(packet_file, 'r', encoding='utf-8') as file:
        # Skip the header line
        lines = file.readlines()[1:]

        current_packet = {}
        for line in lines:
            # Start of a new packet
            if line.startswith('"') and ',' in line[:20]:
                # Process the previous packet if it exists
                if current_packet:
                    # Extract features from the current packet
                    packet_features = extract_features_from_packet(current_packet)
                    features.append(packet_features)

                # Start a new packet
                parts = line.split(',')
                if len(parts) >= 7:
                    current_packet = {
                        'no': parts[0],
                        'timestamp': parts[1],
                        'source_ip': parts[2],
                        'destination_ip': parts[3],
                        'protocol': parts[4],
                        'length': parts[5],
                        'raw_data': [parts[6]]
                    }
            else:
                # Continue adding lines to the current packet
                if current_packet:
                    current_packet['raw_data'].append(line)

        # Don't forget to process the last packet
        if current_packet:
            packet_features = extract_features_from_packet(current_packet)
            features.append(packet_features)

    if not features:
        print("Error: No features extracted from packet data.")
        return None

    # Convert to DataFrame
    df = pd.DataFrame(features)
    print(f"Extracted features for {len(df)} packets.")
    return df

def extract_features_from_packet(packet):
    \"\"\"Extract features from a single packet.\"\"\"
    # TODO: Implement feature extraction logic
    # This should convert raw packet data into numerical features

    features = {
        'source_ip': packet['source_ip'],
        'destination_ip': packet['destination_ip'],
        'protocol': packet['protocol'],
        'length': float(packet['length']) if packet['length'].isdigit() else 0,
    }

    # Extract protocol-specific features
    raw_data = ''.join(packet['raw_data'])

    # Example feature extraction (customize based on your needs):

    # Layer 2 Features
    if 'Layer ETH' in raw_data:
        features['has_eth_layer'] = 1
    else:
        features['has_eth_layer'] = 0

    # IP Features
    if 'Layer IP' in raw_data:
        features['has_ip_layer'] = 1
        # Extract TTL if available
        ttl_match = re.search(r'Time to Live:[^0-9]*([0-9]+)', raw_data)
        if ttl_match:
            features['ip_ttl'] = int(ttl_match.group(1))
    else:
        features['has_ip_layer'] = 0
        features['ip_ttl'] = 0

    # TCP/UDP Features
    if 'Layer TCP' in raw_data:
        features['transport_protocol'] = 'tcp'
        # Extract port information
        src_port_match = re.search(r'Source Port:[^0-9]*([0-9]+)', raw_data)
        dst_port_match = re.search(r'Destination Port:[^0-9]*([0-9]+)', raw_data)
        if src_port_match:
            features['src_port'] = int(src_port_match.group(1))
        if dst_port_match:
            features['dst_port'] = int(dst_port_match.group(1))
    elif 'Layer UDP' in raw_data:
        features['transport_protocol'] = 'udp'
        src_port_match = re.search(r'Source Port:[^0-9]*([0-9]+)', raw_data)
        dst_port_match = re.search(r'Destination Port:[^0-9]*([0-9]+)', raw_data)
        if src_port_match:
            features['src_port'] = int(src_port_match.group(1))
        if dst_port_match:
            features['dst_port'] = int(dst_port_match.group(1))
    else:
        features['transport_protocol'] = 'other'
        features['src_port'] = 0
        features['dst_port'] = 0

    # Add more feature extraction as needed

    return features

def prepare_features_for_knn(df, knn_model):
    \"\"\"Prepare packet features for KNN model.\"\"\"
    print("Preparing features for KNN model...")

    # TODO: Align features with what the KNN model expects
    # You may need to:
    # 1. Convert categorical features to numerical
    # 2. Scale numerical features
    # 3. Add/remove columns to match the KNN model's expected input

    # For now, we'll create a simple numerical representation
    numeric_features = []

    # Process each row (packet)
    for _, row in df.iterrows():
        # Create a numeric feature vector
        # Replace this with your actual feature extraction
        feature_vector = [
            float(row.get('length', 0)),
            float(row.get('ip_ttl', 0)),
            float(row.get('src_port', 0)),
            float(row.get('dst_port', 0)),
            1.0 if row.get('transport_protocol') == 'tcp' else 0.0,
            1.0 if row.get('transport_protocol') == 'udp' else 0.0
        ]

        numeric_features.append(feature_vector)

    # Convert to numpy array
    X = np.array(numeric_features)

    # Apply the same scaling as the KNN model expects
    X_scaled = knn_model.scaler.transform(X)

    return X_scaled

def main():
    args = parse_args()

    # Load the KNN model
    print(f"Loading KNN model from {args.model}...")
    try:
        knn_model = IncrementalKNN.load_model(args.model)
    except Exception as e:
        print(f"Error loading KNN model: {e}")
        return 1

    # Parse the packet data
    packet_df = parse_packet_data(args.packets)
    if packet_df is None:
        print("Failed to parse packet data.")
        return 1

    # Prepare features for the KNN model
    X_scaled = prepare_features_for_knn(packet_df, knn_model)

    # Determine the output directory
    output_dir = args.output if args.output else args.model

    # Add the packets to the KNN model
    print(f"Adding {'anomaly' if args.anomaly else 'normal'} packets to KNN model...")
    for i, feature_vector in enumerate(X_scaled):
        # Add each packet to the model's memory
        if args.anomaly:
            # For anomalies, we might want to just detect them
            label, distance = knn_model.classify_packet_knn(feature_vector)
            print(f"Packet {i+1}/{len(X_scaled)}: Classified as {label}, distance: {distance:.4f}")
        else:
            # For normal traffic, we add them to the model
            knn_model.store_sample(feature_vector, 'normal')
            if (i+1) % 100 == 0 or i == len(X_scaled)-1:
                print(f"Processed {i+1}/{len(X_scaled)} packets")

    # Save the enhanced model
    print(f"Saving enhanced model to {output_dir}...")
    knn_model.save_model(output_dir)

    # Add a log entry about the enhancement
    log_file = os.path.join(output_dir, "enhancement_log.txt")
    with open(log_file, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_type = "anomaly" if args.anomaly else "normal"
        f.write(f"{timestamp}: Enhanced with {len(X_scaled)} {packet_type} packets from {os.path.basename(args.packets)}\\n")

    print("Model enhancement complete!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""

    # Write the script to file
    try:
        with open(output_file, 'w') as f:
            f.write(script_content)

        print(f"\nScript template generated successfully: {output_file}")
        print("You can customize this script for your specific packet format.")

        # Make the script executable on Unix-like systems
        if os.name != 'nt':
            os.chmod(output_file, 0o755)
            print("Script has been made executable.")

        input("\nPress Enter to return to the main menu...")
    except Exception as e:
        print(f"\nError generating script: {str(e)}")
        input("\nPress Enter to return to the main menu...")

def main_menu():
    """Display the main menu."""
    while True:
        clear_screen()
        print("=" * 52)
        print("           MantaGuard AI Model Operations           ")
        print("=" * 52)
        print()

        operations = [
            "Train Base Model (One-Class SVM)",
            "Initialize KNN Model",
            "Test KNN Model",
            "Enhance KNN with Packet Data",
            "Test KNN with Packet Data",
            "Generate Enhance KNN Script Template",  # Added new option
            "Quit"
        ]

        selected = select_option("Select an operation:", operations)

        if selected == "Train Base Model (One-Class SVM)":
            train_base_model()
        elif selected == "Initialize KNN Model":
            init_knn_model()
        elif selected == "Test KNN Model":
            test_knn_model()
        elif selected == "Enhance KNN with Packet Data":
            enhance_knn_with_packets()
        elif selected == "Test KNN with Packet Data":
            test_knn_with_packets()
        elif selected == "Generate Enhance KNN Script Template":  # Added handler for new option
            generate_enhance_knn_script()
        elif selected == "Quit":
            print("Exiting MantaGuard AI operations. Goodbye!")
            sys.exit(0)

# Start the script
if __name__ == "__main__":
    main_menu()
