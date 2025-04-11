#!/usr/bin/env python3
"""
Labeling Script

This script combines all CSV files in a folder into one CSV file and adds labels to each line.
Usage: python labeling.py <folder_path> <label>
  - folder_path: Path to the folder containing CSV files
  - label: 0 for normal, 1 for malicious
"""

import os
import sys
import glob
import pandas as pd
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("labeling.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def combine_csv_files(folder_path, label):
    """
    Combine all CSV files in the specified folder into one CSV file and add labels.

    Args:
        folder_path (str): Path to the folder containing CSV files
        label (int): Label to add to each line (0 for normal, 1 for malicious)

    Returns:
        str: Path to the combined CSV file
    """
    # Check if folder exists
    if not os.path.exists(folder_path):
        logger.error(f"Folder not found: {folder_path}")
        return None

    # Get all CSV files in the folder
    csv_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not csv_files:
        logger.warning(f"No CSV files found in {folder_path}")
        return None

    logger.info(f"Found {len(csv_files)} CSV files in {folder_path}")

    # Create a list to store all dataframes
    all_dfs = []

    # Process each CSV file
    for i, csv_file in enumerate(csv_files, 1):
        try:
            logger.info(f"Processing file {i}/{len(csv_files)}: {os.path.basename(csv_file)}")

            # Read the CSV file
            df = pd.read_csv(csv_file)

            # Add label column
            df['label'] = label

            # Append to the list
            all_dfs.append(df)

            logger.info(f"Added {len(df)} rows from {os.path.basename(csv_file)}")
        except Exception as e:
            logger.error(f"Error processing {csv_file}: {e}")

    if not all_dfs:
        logger.error("No data was loaded from any CSV files")
        return None

    # Combine all dataframes
    combined_df = pd.concat(all_dfs, ignore_index=True)
    logger.info(f"Combined {len(combined_df)} rows from {len(csv_files)} files")

    # Ensure label column is the last column
    if 'label' in combined_df.columns:
        # Get all columns except 'label'
        cols = [col for col in combined_df.columns if col != 'label']
        # Reorder columns to put 'label' last
        combined_df = combined_df[cols + ['label']]
        logger.info("Reordered columns to ensure 'label' is the last column")

    # Create output filename based on the folder name and timestamp
    folder_name = os.path.basename(os.path.normpath(folder_path))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{folder_name}_labeled_{timestamp}.csv"

    # Save the combined dataframe
    combined_df.to_csv(output_file, index=False)
    logger.info(f"Saved combined data to {output_file}")

    return output_file

def main():
    """Main function to parse arguments and run the script."""
    # Check if the correct number of arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python labeling.py <folder_path> <label>")
        print("  - folder_path: Path to the folder containing CSV files")
        print("  - label: 0 for normal, 1 for malicious")
        sys.exit(1)

    # Get arguments
    folder_path = sys.argv[1]
    try:
        label = int(sys.argv[2])
        if label not in [0, 1]:
            print("Error: Label must be 0 (normal) or 1 (malicious)")
            sys.exit(1)
    except ValueError:
        print("Error: Label must be an integer (0 or 1)")
        sys.exit(1)

    # Print header
    print("\n" + "="*80)
    print("CSV FILES LABELING TOOL")
    print("="*80 + "\n")

    # Run the script
    output_file = combine_csv_files(folder_path, label)

    if output_file:
        print("\n" + "-"*80)
        print(f"SUCCESS: Combined and labeled CSV files saved to {output_file}")
        print(f"Total rows: {len(pd.read_csv(output_file))}")
        print("-"*80 + "\n")
    else:
        print("\n" + "!"*80)
        print("ERROR: Failed to combine and label CSV files")
        print("!"*80 + "\n")
        sys.exit(1)

if __name__ == "__main__":
    main()