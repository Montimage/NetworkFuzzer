#!/usr/bin/env python3
"""
DICOM Flow GAN Generator

This script uses CTGAN (Conditional Tabular GAN) to generate synthetic DICOM flow data
based on existing normal and malicious DICOM flow data.

Usage: python gan.py <normal_csv> <malicious_csv> <output_dir> [--samples N]
  - normal_csv: Path to the CSV file containing normal DICOM flows
  - malicious_csv: Path to the CSV file containing malicious DICOM flows
  - output_dir: Directory to save the generated synthetic data
  - --samples N: Number of synthetic samples to generate (default: 1000)
"""

import os
import sys
import argparse
import pandas as pd
import numpy as np
import logging
import re
from datetime import datetime

# Import CTGAN from the ctgan package
try:
    from ctgan import CTGAN
    print("Successfully imported CTGAN from ctgan package")
except ImportError as e:
    print(f"Error importing CTGAN: {e}")
    print("\nError: Could not import CTGAN from ctgan package.")
    print("Please make sure ctgan is installed correctly: pip install ctgan")
    sys.exit(1)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gan_generation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_and_prepare_data(normal_csv, malicious_csv):
    """
    Load and prepare the normal and malicious DICOM flow data.

    Args:
        normal_csv (str): Path to the CSV file containing normal DICOM flows
        malicious_csv (str): Path to the CSV file containing malicious DICOM flows

    Returns:
        pd.DataFrame: Combined data
    """
    logger.info(f"Loading normal DICOM flows from {normal_csv}")
    normal_data = pd.read_csv(normal_csv)
    logger.info(f"Loaded {len(normal_data)} normal DICOM flows")

    logger.info(f"Loading malicious DICOM flows from {malicious_csv}")
    malicious_data = pd.read_csv(malicious_csv)
    logger.info(f"Loaded {len(malicious_data)} malicious DICOM flows")

    # Combine the data
    combined_data = pd.concat([normal_data, malicious_data], ignore_index=True)
    logger.info(f"Combined data contains {len(combined_data)} rows")

    # Log column information
    logger.info(f"Data contains {len(combined_data.columns)} columns")
    logger.info(f"Columns: {', '.join(combined_data.columns)}")

    return combined_data

def clean_data(data):
    """
    Clean the data by handling null values and malformed data.

    Args:
        data (pd.DataFrame): The data to clean

    Returns:
        pd.DataFrame: Cleaned data
    """
    logger.info("Cleaning data by handling null values and malformed data")

    # Make a copy of the data to avoid modifying the original
    cleaned_data = data.copy()

    # First, identify and remove problematic columns
    columns_to_remove = []

    # Check for datetime columns and remove them
    for column in cleaned_data.columns:
        if 'time' in column.lower() or 'date' in column.lower():
            logger.info(f"Removing datetime column '{column}' to avoid issues")
            columns_to_remove.append(column)

    # Check for columns with extremely long strings
    for column in cleaned_data.columns:
        if not pd.api.types.is_numeric_dtype(cleaned_data[column]) and column not in columns_to_remove:
            max_length = cleaned_data[column].astype(str).str.len().max()
            if max_length > 50:  # Lower threshold to be more aggressive
                logger.info(f"Removing column '{column}' with long strings (max length: {max_length})")
                columns_to_remove.append(column)

    # Remove the identified columns
    if columns_to_remove:
        logger.info(f"Removing {len(columns_to_remove)} problematic columns: {', '.join(columns_to_remove)}")
        cleaned_data = cleaned_data.drop(columns=columns_to_remove)

    # Check for null values
    null_counts = cleaned_data.isnull().sum()
    if null_counts.sum() > 0:
        logger.info(f"Found null values in the following columns: {null_counts[null_counts > 0].to_dict()}")

        # For each column with null values, decide how to handle them
        for column in cleaned_data.columns:
            if cleaned_data[column].isnull().sum() > 0:
                # For numeric columns, fill with median
                if pd.api.types.is_numeric_dtype(cleaned_data[column]):
                    median_value = cleaned_data[column].median()
                    cleaned_data[column] = cleaned_data[column].fillna(median_value)
                    logger.info(f"Filled null values in column '{column}' with median value: {median_value}")
                # For categorical columns, fill with mode
                else:
                    mode_value = cleaned_data[column].mode()[0]
                    cleaned_data[column] = cleaned_data[column].fillna(mode_value)
                    logger.info(f"Filled null values in column '{column}' with mode value: {mode_value}")
    else:
        logger.info("No null values found in the data")

    # Verify that all null values have been handled
    if cleaned_data.isnull().sum().sum() > 0:
        logger.warning("Some null values could not be handled. Dropping rows with null values.")
        cleaned_data = cleaned_data.dropna()
        logger.info(f"Dropped rows with null values. Remaining rows: {len(cleaned_data)}")

    # Ensure all remaining columns are numeric
    non_numeric_columns = []
    for column in cleaned_data.columns:
        if not pd.api.types.is_numeric_dtype(cleaned_data[column]):
            non_numeric_columns.append(column)

    if non_numeric_columns:
        logger.info(f"Converting {len(non_numeric_columns)} non-numeric columns to numeric: {', '.join(non_numeric_columns)}")
        for column in non_numeric_columns:
            # Try to convert to numeric, replacing non-numeric values with NaN
            cleaned_data[column] = pd.to_numeric(cleaned_data[column], errors='coerce')
            # Fill NaN values with 0
            cleaned_data[column] = cleaned_data[column].fillna(0)
            logger.info(f"Converted column '{column}' to numeric")

    logger.info(f"Data cleaning complete. Final data shape: {cleaned_data.shape}")
    return cleaned_data

def train_ctgan(data, epochs=100, batch_size=500):
    """
    Train a CTGAN model on the provided data.

    Args:
        data (pd.DataFrame): The training data
        epochs (int): Number of training epochs
        batch_size (int): Batch size for training

    Returns:
        CTGAN: Trained CTGAN model
    """
    logger.info("Initializing CTGAN model")

    # Clean the data to handle null values and malformed data
    cleaned_data = clean_data(data)

    # Identify categorical columns (including 'label')
    categorical_columns = ['label']  # Add other categorical columns if needed

    # Check if there are any string columns that should be categorical
    for column in cleaned_data.columns:
        if not pd.api.types.is_numeric_dtype(cleaned_data[column]) and column not in categorical_columns:
            # If a column has a small number of unique values, treat it as categorical
            unique_count = cleaned_data[column].nunique()
            if unique_count < 50:  # Arbitrary threshold
                logger.info(f"Adding column '{column}' to categorical columns (has {unique_count} unique values)")
                categorical_columns.append(column)

    logger.info(f"Categorical columns: {categorical_columns}")

    model = CTGAN(
        epochs=epochs,
        batch_size=batch_size,
        verbose=True,
        cuda=False
    )

    logger.info(f"Training CTGAN model for {epochs} epochs")
    model.fit(cleaned_data, categorical_columns)
    logger.info("CTGAN model training completed")

    return model

def generate_synthetic_data(model, num_samples, output_dir):
    """
    Generate synthetic data using the trained CTGAN model.

    Args:
        model (CTGAN): Trained CTGAN model
        num_samples (int): Number of synthetic samples to generate
        output_dir (str): Directory to save the generated data

    Returns:
        str: Path to the generated synthetic data file
    """
    logger.info(f"Generating {num_samples} synthetic samples")

    # Generate synthetic data
    synthetic_data = model.sample(num_samples)
    logger.info(f"Generated {len(synthetic_data)} synthetic samples")

    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"Created output directory: {output_dir}")

    # Save the synthetic data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"synthetic_dicom_flows_{timestamp}.csv")
    synthetic_data.to_csv(output_file, index=False)
    logger.info(f"Saved synthetic data to {output_file}")

    # Analyze the distribution of labels in the synthetic data
    label_counts = synthetic_data['label'].value_counts()
    logger.info(f"Label distribution in synthetic data: {label_counts.to_dict()}")

    return output_file

def main():
    """Main function to parse arguments and run the script."""
    parser = argparse.ArgumentParser(description='Generate synthetic DICOM flow data using CTGAN')
    parser.add_argument('normal_csv', help='Path to the CSV file containing normal DICOM flows')
    parser.add_argument('malicious_csv', help='Path to the CSV file containing malicious DICOM flows')
    parser.add_argument('output_dir', help='Directory to save the generated synthetic data')
    parser.add_argument('--samples', type=int, default=1000, help='Number of synthetic samples to generate (default: 1000)')
    parser.add_argument('--epochs', type=int, default=100, help='Number of training epochs (default: 100)')
    parser.add_argument('--batch-size', type=int, default=500, help='Batch size for training (default: 500)')

    args = parser.parse_args()

    # Print header
    print("\n" + "="*80)
    print("DICOM FLOW GAN GENERATOR")
    print("="*80 + "\n")

    try:
        # Load and prepare data
        data = load_and_prepare_data(args.normal_csv, args.malicious_csv)

        # Train CTGAN model
        model = train_ctgan(data, epochs=args.epochs, batch_size=args.batch_size)

        # Generate synthetic data
        output_file = generate_synthetic_data(model, args.samples, args.output_dir)

        # Print success message
        print("\n" + "-"*80)
        print(f"SUCCESS: Generated {args.samples} synthetic DICOM flows")
        print(f"Output saved to: {output_file}")
        print("-"*80 + "\n")

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        print("\n" + "!"*80)
        print(f"ERROR: {str(e)}")
        print("!"*80 + "\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
