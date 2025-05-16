#!/usr/bin/env python3
import subprocess
import sys

# Run the retrain_ocsvm.py script with --help flag
try:
    result = subprocess.run(['python', 'training/retrain_ocsvm.py', '--help'], 
                           capture_output=True, text=True, check=True)
    print("Success! The script ran without errors.")
    print("Output:")
    print(result.stdout)
except subprocess.CalledProcessError as e:
    print("Error running the script:")
    print(e.stderr)
    sys.exit(1)