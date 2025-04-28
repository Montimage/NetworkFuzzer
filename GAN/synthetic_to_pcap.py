#!/usr/bin/env python3
"""
Modify legitimate DICOM pcap files with synthetic values while preserving network layer information.

Usage: python synthetic_to_pcap.py <template_pcap> <synthetic_csv> <output_dir> [--num-flows NUM]
  - template_pcap: Path to a legitimate DICOM pcap file to use as template
  - synthetic_csv: Path to the CSV file containing synthetic DICOM flows
  - output_dir: Directory to save the modified PCAP files
  - --num-flows NUM: Number of flows to generate (default: 100)
"""

import os
import sys
import argparse
import pandas as pd
import numpy as np
import logging
from datetime import datetime
import pyshark
from scapy.all import *
import random
import socket
import struct

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("synthetic_conversion.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def denormalize_value(value, min_val, max_val):
    """Denormalize a value from [-1, 1] range back to original range."""
    try:
        # Ensure value is within [-1, 1] range
        value = max(-1.0, min(1.0, float(value)))
        return int(((value + 1) / 2) * (max_val - min_val) + min_val)
    except (ValueError, TypeError):
        logger.warning(f"Invalid value for denormalization: {value}, using default value")
        return min_val

def modify_dicom_packet(packet, flow_data):
    """Modify a DICOM packet with synthetic values while preserving network layer information."""
    try:
        # Create a copy of the packet
        modified_packet = packet.copy()

        # We don't modify IP or TCP layers to preserve flow characteristics

        # If there's a payload, modify it while preserving DICOM structure
        if Raw in modified_packet:
            raw = modified_packet[Raw].load

            # Check if this is a DICOM PDU (starts with PDU type byte)
            if len(raw) >= 1:
                # Get current PDU type
                current_pdu_type = raw[0]

                # Modify PDU type if specified
                if 'dicom.pdu.type' in flow_data:
                    pdu_type = denormalize_value(flow_data['dicom.pdu.type'], 1, 7)
                    # Only modify if it's a valid PDU type
                    if 1 <= pdu_type <= 7:
                        raw = bytes([pdu_type]) + raw[1:]

                # Modify PDU length if specified and if we have enough bytes
                if 'dicom.pdu.len' in flow_data and len(raw) >= 4:
                    pdu_length = denormalize_value(flow_data['dicom.pdu.len'], 100, 65535)
                    # Update length in the PDU header (bytes 2-3)
                    raw = raw[:2] + struct.pack('!H', pdu_length) + raw[4:]

                # Update the packet's payload
                modified_packet[Raw].load = raw

        return modified_packet
    except Exception as e:
        logger.error(f"Error modifying DICOM packet: {str(e)}")
        return packet

def create_modified_pcap(template_pcap, flow_data, output_file):
    """Create a modified PCAP file based on template and synthetic data."""
    try:
        # Read the template pcap file
        packets = rdpcap(template_pcap)
        modified_packets = []

        # Modify each packet
        for packet in packets:
            modified_packet = modify_dicom_packet(packet, flow_data)
            modified_packets.append(modified_packet)

        # Write modified packets to new pcap file
        wrpcap(output_file, modified_packets)
        logger.info(f"Created modified PCAP file: {output_file}")

    except Exception as e:
        logger.error(f"Error creating modified PCAP: {str(e)}")
        raise

def convert_synthetic_to_pcap(template_pcap, synthetic_data, output_dir, num_flows=100):
    """Convert synthetic data to modified PCAP files."""
    try:
        os.makedirs(output_dir, exist_ok=True)

        # Load synthetic data
        logger.info(f"Loading synthetic data from {synthetic_data}")
        df = pd.read_csv(synthetic_data)
        logger.info(f"Loaded {len(df)} synthetic flows")

        # Select random flows to convert
        selected_flows = df.sample(min(num_flows, len(df)))
        logger.info(f"Selected {len(selected_flows)} flows to convert")

        # Create modified PCAP files
        for idx, flow in selected_flows.iterrows():
            try:
                # Convert flow data to dictionary
                flow_data = flow.to_dict()

                # Create modified pcap file
                output_file = os.path.join(output_dir, f"flow_{idx}.pcap")
                create_modified_pcap(template_pcap, flow_data, output_file)

            except Exception as e:
                logger.error(f"Error processing flow {idx}: {str(e)}")
                continue

        logger.info(f"Successfully created {len(selected_flows)} modified PCAP files in {output_dir}")

    except Exception as e:
        logger.error(f"Error converting synthetic data to PCAP: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Modify legitimate DICOM pcap files with synthetic values while preserving network layer information")
    parser.add_argument("template_pcap", help="Path to a legitimate DICOM pcap file to use as template")
    parser.add_argument("synthetic_csv", help="Path to the CSV file containing synthetic DICOM flows")
    parser.add_argument("output_dir", help="Directory to save the modified PCAP files")
    parser.add_argument("--num-flows", type=int, default=100, help="Number of flows to generate")

    args = parser.parse_args()

    convert_synthetic_to_pcap(args.template_pcap, args.synthetic_csv, args.output_dir, args.num_flows)

if __name__ == "__main__":
    main()