# Forensics Directory

This directory contains packet captures saved when anomalies are detected by the MantaGuard system.

## File Naming Convention

Files are named using the following format:
```
<uid>_<timestamp>.pcap
```

Where:
- `<uid>` is the Zeek unique identifier for the connection that triggered the anomaly
- `<timestamp>` is the date and time when the anomaly was detected (format: YYYYMMDD_HHMMSS)

## File Contents

Each .pcap file contains the 500 most recent network packets captured before the anomaly was detected. These packets are stored with their original timestamps, which allows them to be aligned with Zeek logs for further analysis.

## Usage

These packet captures can be analyzed using tools like:
- Wireshark
- Zeek
- Tshark
- Other network analysis tools that support PCAP format

## Integration with MantaGuard

When an anomaly is detected by MantaGuard's machine learning models, the `on_anomaly(uid)` function in `live_packet_buffer.py` is called, which automatically saves the most recent packets to this directory.

This provides valuable context for security analysts to investigate the anomaly and determine if it represents a genuine security threat.