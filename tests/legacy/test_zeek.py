import subprocess

# Test the Zeek command
zeek_cmd = "zeek -r data/zeek/capture.pcap -O ZAM -o data/zeek/zeek_output"
print(f"Running command: {zeek_cmd}")
try:
    subprocess.run(zeek_cmd, shell=True, check=True)
    print("Zeek command executed successfully!")
except subprocess.CalledProcessError as e:
    print(f"Error running Zeek: {e}")
