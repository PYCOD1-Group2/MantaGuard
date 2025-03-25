import subprocess
import sys

def main():
    print("Initializing the scanning process...")
    try:
        subprocess.run([sys.executable, "FirstScan.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing FirstScan.py: {e}")
    except FileNotFoundError:
        print("Error: FirstScan.py not found. Make sure it's in the same directory.")

if __name__ == "__main__":
    main()
