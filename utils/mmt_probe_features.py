#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import csv
import pandas as pd
import glob
import time
from pathlib import Path

def process_pcap_file(pcap_file, output_file, output_dir=None):
    """
    Process a pcap file using mmt-probe and generate a cleaned CSV file with proper headers

    Args:
        pcap_file: Path to the input pcap file
        output_file: Path to save the final cleaned CSV output
        output_dir: Directory to store intermediate mmt-probe output (default: /tmp/)
    """
    # Use default temp directory if not specified
    if output_dir is None:
        output_dir = "/tmp/"

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Get the base name of the pcap file for intermediate file
    pcap_name = os.path.basename(pcap_file)

    print(f"Processing {pcap_file} with mmt-probe...")

    # Store the timestamp before running mmt-probe to find new files later
    before_time = time.time()

    # Execute mmt-probe command
    cmd = [
        "mmt-probe",
        "-t", pcap_file,
        "-X", f"file-output.output-dir={output_dir}",
        "-X", f"file-output.output-file={pcap_name}.csv"
    ]

    try:
        subprocess.run(cmd, check=True)
        print(f"mmt-probe processing complete. Looking for generated output in {output_dir}")
    except subprocess.CalledProcessError as e:
        print(f"Error running mmt-probe: {e}")
        return False
    except FileNotFoundError:
        print("Error: mmt-probe command not found. Please ensure mmt-probe is installed and in your PATH.")
        return False

    # Find the latest CSV file that matches the pcap filename pattern
    # mmt-probe generates files with timestamp prefix like: 1742734168.752090_0_association_negotiation.pcap.csv
    csv_pattern = os.path.join(output_dir, f"*_{pcap_name}.csv")
    matching_files = glob.glob(csv_pattern)

    # If no matching files with timestamp prefix, try the original expected name
    if not matching_files:
        original_pattern = os.path.join(output_dir, f"{pcap_name}.csv")
        matching_files = glob.glob(original_pattern)

    # Try to find files created after we started the processing
    if not matching_files:
        # Get all csv files in the directory
        all_csv_files = glob.glob(os.path.join(output_dir, "*.csv"))
        # Filter for files created after we started processing
        matching_files = [f for f in all_csv_files if os.path.getctime(f) >= before_time]
        # Sort by creation time (newest first)
        matching_files.sort(key=os.path.getctime, reverse=True)

    if not matching_files:
        print(f"Error: No matching CSV output files found in {output_dir}")
        return False

    # Use the latest file
    intermediate_csv = matching_files[0]
    print(f"Found output CSV file: {intermediate_csv}")

    # Define column headers with consistent naming (lowercase, no spaces)
    column_headers = [
        "format_id", "probe", "source", "timestamp", "report_number", "protocol_app_id",
        "protocol_path_uplink", "protocol_path_downlink", "nb_active_flows", "data_volume",
        "payload_volume", "packet_count", "ul_data_volume", "ul_payload_volume", "ul_packet_count",
        "dl_data_volume", "dl_payload_volume", "dl_packet_count", "start_timestamp", "client_address",
        "server_address", "mac_source", "mac_destination", "session_id", "server_port", "client_port",
        "thread_number", "handshake_time", "app_response_time", "data_transfer_time", "client_rtt_data_min",
        "server_rtt_data_min", "client_rtt_data_max", "server_rtt_data_max", "client_rtt_data_avg",
        "server_rtt_data_avg", "client_retransmission", "server_retransmission", "format",
        "application_family", "content_class"
    ]

    # Clean up the CSV file (skip first line, add headers)
    try:
        # Check if the intermediate file exists and has content
        if not os.path.exists(intermediate_csv) or os.path.getsize(intermediate_csv) == 0:
            print(f"Error: Intermediate CSV file {intermediate_csv} not found or empty.")
            return False

        print(f"Cleaning up the CSV output and adding proper headers...")
        # Read the CSV file skipping the first line
        df = pd.read_csv(intermediate_csv, skiprows=1, header=None)

        # Check if the number of columns matches our headers
        if len(df.columns) != len(column_headers):
            print(f"Warning: Expected {len(column_headers)} columns but found {len(df.columns)}.")
            print("Will attempt to proceed by truncating or padding the headers as needed.")

            # Adjust headers to match the actual number of columns
            if len(df.columns) < len(column_headers):
                column_headers = column_headers[:len(df.columns)]
            else:
                # Add generic headers for extra columns
                for i in range(len(column_headers), len(df.columns)):
                    column_headers.append(f"extra_column_{i+1}")

        # Assign the headers
        df.columns = column_headers

        # Save the cleaned CSV file
        df.to_csv(output_file, index=False)
        print(f"Successfully created cleaned CSV file: {output_file}")
        return True

    except Exception as e:
        print(f"Error processing CSV file: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process pcap files with mmt-probe and clean output CSV")
    parser.add_argument('-i', '--input', required=True, help="Input pcap file")
    parser.add_argument('-o', '--output', required=True, help="Output CSV file path")
    parser.add_argument('-d', '--tempdir', help="Directory for intermediate output (default: /tmp/)")

    args = parser.parse_args()

    # Call the main function
    success = process_pcap_file(args.input, args.output, args.tempdir)

    if success:
        print("Processing completed successfully.")
    else:
        print("Processing failed.")
        sys.exit(1)