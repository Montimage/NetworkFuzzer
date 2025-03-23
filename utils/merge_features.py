import pandas as pd
import os
import argparse
import glob
from pathlib import Path


def process_files(cic_path, zeek_path, output_path, time_diff_hours=1):
    """
    Process CICFlowMeter and Zeek files for merging
    """
    # Check if inputs are files or directories
    cic_is_dir = os.path.isdir(cic_path)
    zeek_is_dir = os.path.isdir(zeek_path)

    # If both are files, merge them directly
    if not cic_is_dir and not zeek_is_dir:
        merge_files(cic_path, zeek_path, output_path, time_diff_hours)

    # If both are directories, process all files in the directories
    elif cic_is_dir and zeek_is_dir:
        # Create output directory if it doesn't exist
        os.makedirs(output_path, exist_ok=True)

        # Get all CSV files in CIC directory
        cic_files = glob.glob(os.path.join(cic_path, "*.csv"))

        for cic_file in cic_files:
            # Extract the base name from the CIC file
            cic_base_name = os.path.basename(cic_file)

            # Look for a matching Zeek file (with 'zeek_' prefix)
            zeek_file_name = f"zeek_{cic_base_name}"
            zeek_file = os.path.join(zeek_path, zeek_file_name)

            # If we can't find an exact match, try a more flexible approach
            if not os.path.exists(zeek_file):
                # Try to find any matching file based on name
                name_part = os.path.splitext(cic_base_name)[0]
                potential_matches = glob.glob(os.path.join(zeek_path, f"*{name_part}*.csv"))
                if potential_matches:
                    zeek_file = potential_matches[0]
                else:
                    print(f"No matching Zeek file found for {cic_base_name}, skipping...")
                    continue

            # Create output file path
            output_file = os.path.join(output_path, f"merged_{cic_base_name}")

            # Merge the files
            print(f"Merging {cic_file} with {zeek_file}...")
            merge_files(cic_file, zeek_file, output_file, time_diff_hours)
    else:
        raise ValueError("Both inputs must be either files or directories")


def merge_files(cic_file, zeek_file, output_file, time_diff_hours=1):
    """
    Merge CICFlowMeter and Zeek CSV files
    """
    # Load the CSV files
    print(f"Loading CICFlowMeter data from {cic_file}")
    cic_df = pd.read_csv(cic_file)

    print(f"Loading Zeek data from {zeek_file}")
    zeek_df = pd.read_csv(zeek_file)

    # Convert Zeek's 'ts' column to datetime format (matching CICFlowMeter's 'timestamp')
    zeek_df['ts'] = pd.to_datetime(zeek_df['ts'], unit='s')

    # Rename Zeek columns to match CICFlowMeter's naming convention where applicable
    zeek_df.rename(columns={
        'ts': 'timestamp',  # Rename 'ts' to 'timestamp' to match CICFlowMeter
        'id.orig_h': 'src_ip',
        'id.orig_p': 'src_port',
        'id.resp_h': 'dst_ip',
        'id.resp_p': 'dst_port',
        'duration': 'flow_duration_zeek',
        'orig_bytes': 'flow_byts_s_zeek',
        'resp_bytes': 'totlen_bwd_pkts_zeek',
        'orig_pkts': 'tot_fwd_pkts_zeek',
        'resp_pkts': 'tot_bwd_pkts_zeek',
        'orig_ip_bytes': 'totlen_fwd_pkts_zeek',
        'resp_ip_bytes': 'totlen_bwd_pkts_zeek',
        'ip_proto': 'protocol'  # Map 'ip_proto' to 'protocol' to match CICFlowMeter
    }, inplace=True)

    # Ensure the 'protocol' column is of the same type in both DataFrames
    zeek_df['protocol'] = zeek_df['protocol'].astype(str)
    cic_df['protocol'] = cic_df['protocol'].astype(str)

    # Convert the 'timestamp' column in CICFlowMeter to datetime (if not already in datetime format)
    cic_df['timestamp'] = pd.to_datetime(cic_df['timestamp'])

    # Adjust Zeek timestamps to match CICFlowMeter timestamps
    # Example: If Zeek timestamps are 1 hour behind, add 1 hour
    zeek_df['timestamp'] = zeek_df['timestamp'] + pd.Timedelta(hours=time_diff_hours)

    # Round timestamps to the same precision (e.g., seconds)
    zeek_df['timestamp'] = zeek_df['timestamp'].dt.round('s')
    cic_df['timestamp'] = cic_df['timestamp'].dt.round('s')

    # Print key columns for debugging
    print("CICFlowMeter Key Columns Sample:")
    print(cic_df[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'timestamp']].head())
    print("\nZeek Key Columns Sample:")
    print(zeek_df[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'timestamp']].head())

    # Merge the dataframes on common columns
    common_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'timestamp']
    merged_df = pd.merge(cic_df, zeek_df, on=common_columns, how='left', suffixes=('_cic', '_zeek'))

    # Copy original Zeek columns to the merged DataFrame
    for col in zeek_df.columns:
        if col not in common_columns:  # Skip common columns (already merged)
            merged_df[col] = zeek_df[col]

    # Save the merged dataframe to a new CSV file
    merged_df.to_csv(output_file, index=False)

    print(f"\nMerged CSV file saved as '{output_file}'")


if __name__ == "__main__":
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="Merge CICFlowMeter and Zeek CSV files")
    parser.add_argument("-c", "--cic", required=True, help="Path to CICFlowMeter CSV file or directory")
    parser.add_argument("-z", "--zeek", required=True, help="Path to Zeek CSV file or directory")
    parser.add_argument("-o", "--output", required=True, help="Path for output file or directory")
    parser.add_argument("-t", "--time", type=int, default=1, help="Hours to adjust Zeek timestamps (default: 1)")

    args = parser.parse_args()

    # Process the files based on command line arguments
    process_files(args.cic, args.zeek, args.output, args.time)
