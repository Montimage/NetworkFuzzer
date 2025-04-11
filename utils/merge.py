import pandas as pd
import numpy as np
import os
import logging
import glob
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("merge.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add a custom formatter for console output to make important messages stand out
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

def create_flow_id(row, is_packet=True):
    """Create a consistent flow ID from IP addresses and ports."""
    if is_packet:
        return f"{row['ip.src']}-{row['ip.dst']}-{row['tcp.srcport']}-{row['tcp.dstport']}-TCP"
    else:
        return f"{row['src_ip']}-{row['dst_ip']}-{row['src_port']}-{row['dst_port']}-TCP"

def extract_dicom_features(packet_df):
    """Extract meaningful DICOM features from packet data."""
    logger.info("Extracting DICOM features from packet data...")

    # Create flow_id column
    packet_df['flow_id'] = packet_df.apply(lambda row: create_flow_id(row, True), axis=1)

    # Get all DICOM-related columns
    dicom_columns = [col for col in packet_df.columns if col.startswith('dicom.')]
    logger.info(f"Found {len(dicom_columns)} DICOM-related columns")

    # Log the specific columns we're interested in
    pctx_columns = [col for col in dicom_columns if 'pctx' in col]
    logger.info(f"Found {len(pctx_columns)} presentation context columns: {pctx_columns}")

    # Group by flow_id and extract features
    dicom_features = {}

    # Process each flow
    for flow_id, group in packet_df.groupby('flow_id'):
        features = {}

        # Basic DICOM PDU statistics
        features['dicom_pdu_types'] = ','.join(group['dicom.pdu.type'].dropna().astype(str).unique())
        features['dicom_pdu_count'] = len(group)

        # Process each DICOM column
        for col in dicom_columns:
            # Skip columns that are already processed in a special way
            if col in ['dicom.pdu.type', 'dicom.pdu.len']:
                continue

            # Get non-null values for this column
            non_null_values = group[col].dropna()

            if len(non_null_values) > 0:
                # For numeric columns, calculate statistics
                if pd.api.types.is_numeric_dtype(non_null_values):
                    features[f'{col}_mean'] = non_null_values.mean()
                    features[f'{col}_max'] = non_null_values.max()
                    features[f'{col}_min'] = non_null_values.min()
                    if len(non_null_values) > 1:
                        features[f'{col}_std'] = non_null_values.std()
                # For string columns, join unique values
                else:
                    unique_values = non_null_values.astype(str).unique()
                    if len(unique_values) == 1:
                        features[col] = unique_values[0]
                    else:
                        features[col] = ','.join(unique_values)

        # Special handling for PDU length - ensure it's numeric
        if 'dicom.pdu.len' in group.columns:
            try:
                # Convert PDU length to numeric, handling any non-numeric values
                pdu_lengths = pd.to_numeric(group['dicom.pdu.len'].dropna(), errors='coerce')
                pdu_lengths = pdu_lengths.dropna()  # Remove any NaN values after conversion

                if len(pdu_lengths) > 0:
                    features['dicom_pdu_len_mean'] = pdu_lengths.mean()
                    features['dicom_pdu_len_max'] = pdu_lengths.max()
                    features['dicom_pdu_len_min'] = pdu_lengths.min()
                    if len(pdu_lengths) > 1:
                        features['dicom_pdu_len_std'] = pdu_lengths.std()
            except Exception as e:
                logger.warning(f"Error processing PDU length: {e}")
                # Store the raw values as a string if conversion fails
                pdu_lengths_str = group['dicom.pdu.len'].dropna().astype(str).unique()
                if len(pdu_lengths_str) > 0:
                    features['dicom_pdu_len'] = ','.join(pdu_lengths_str)

        # Special handling for presentation context columns
        for col in pctx_columns:
            if col in group.columns:
                # For presentation context columns, we want to preserve the original values
                # as they often contain important information about the DICOM negotiation
                non_null_values = group[col].dropna()
                if len(non_null_values) > 0:
                    # Convert to string and join with commas
                    values_str = ','.join(non_null_values.astype(str))
                    features[col] = values_str
                    logger.debug(f"Extracted {col} values: {values_str[:100]}...")

        # Association features - detailed extraction
        assoc_requests = group[group['dicom.pdu.type'] == '0x01']
        if not assoc_requests.empty:
            features['dicom_assoc_request_count'] = len(assoc_requests)

            # Extract all association request fields
            for col in dicom_columns:
                if 'assoc' in col and col not in features:
                    non_null_values = assoc_requests[col].dropna()
                    if len(non_null_values) > 0:
                        if pd.api.types.is_numeric_dtype(non_null_values):
                            features[f'{col}_mean'] = non_null_values.mean()
                        else:
                            unique_values = non_null_values.astype(str).unique()
                            if len(unique_values) == 1:
                                features[col] = unique_values[0]
                            else:
                                features[col] = ','.join(unique_values)

            # Special handling for presentation context in association requests
            for col in pctx_columns:
                if col in assoc_requests.columns and col not in features:
                    non_null_values = assoc_requests[col].dropna()
                    if len(non_null_values) > 0:
                        values_str = ','.join(non_null_values.astype(str))
                        features[col] = values_str

        # Association response features
        assoc_responses = group[group['dicom.pdu.type'] == '0x02']
        if not assoc_responses.empty:
            features['dicom_assoc_response_count'] = len(assoc_responses)

            # Extract all association response fields
            for col in dicom_columns:
                if 'assoc' in col and col not in features:
                    non_null_values = assoc_responses[col].dropna()
                    if len(non_null_values) > 0:
                        if pd.api.types.is_numeric_dtype(non_null_values):
                            features[f'{col}_mean'] = non_null_values.mean()
                        else:
                            unique_values = non_null_values.astype(str).unique()
                            if len(unique_values) == 1:
                                features[col] = unique_values[0]
                            else:
                                features[col] = ','.join(unique_values)

            # Special handling for presentation context in association responses
            for col in pctx_columns:
                if col in assoc_responses.columns and col not in features:
                    non_null_values = assoc_responses[col].dropna()
                    if len(non_null_values) > 0:
                        values_str = ','.join(non_null_values.astype(str))
                        features[col] = values_str

        # Data transfer features
        data_transfers = group[group['dicom.pdu.type'] == '0x04']
        if not data_transfers.empty:
            features['dicom_data_transfer_count'] = len(data_transfers)

            # Extract all data transfer fields
            for col in dicom_columns:
                if col not in features:
                    non_null_values = data_transfers[col].dropna()
                    if len(non_null_values) > 0:
                        if pd.api.types.is_numeric_dtype(non_null_values):
                            features[f'{col}_mean'] = non_null_values.mean()
                        else:
                            unique_values = non_null_values.astype(str).unique()
                            if len(unique_values) == 1:
                                features[col] = unique_values[0]
                            else:
                                features[col] = ','.join(unique_values)

        # Release request/response features
        release_requests = group[group['dicom.pdu.type'] == '0x05']
        release_responses = group[group['dicom.pdu.type'] == '0x06']
        features['dicom_release_request_count'] = len(release_requests)
        features['dicom_release_response_count'] = len(release_responses)

        # Abort features
        aborts = group[group['dicom.pdu.type'] == '0x07']
        if not aborts.empty:
            features['dicom_abort_count'] = len(aborts)

            # Extract all abort fields
            for col in dicom_columns:
                if 'abort' in col and col not in features:
                    non_null_values = aborts[col].dropna()
                    if len(non_null_values) > 0:
                        if pd.api.types.is_numeric_dtype(non_null_values):
                            features[f'{col}_mean'] = non_null_values.mean()
                        else:
                            unique_values = non_null_values.astype(str).unique()
                            if len(unique_values) == 1:
                                features[col] = unique_values[0]
                            else:
                                features[col] = ','.join(unique_values)

        # Store features for this flow
        dicom_features[flow_id] = features

    # Convert to DataFrame
    dicom_features_df = pd.DataFrame.from_dict(dicom_features, orient='index')
    dicom_features_df = dicom_features_df.reset_index().rename(columns={'index': 'flow_id'})

    # Check if presentation context columns are present in the output
    pctx_columns_in_output = [col for col in dicom_features_df.columns if 'pctx' in col]
    logger.info(f"Presentation context columns in output: {pctx_columns_in_output}")

    # Log a sample of the data to verify
    if len(dicom_features_df) > 0:
        sample_row = dicom_features_df.iloc[0]
        pctx_values = {col: sample_row[col] for col in pctx_columns_in_output if col in sample_row.index}
        #logger.info(f"Sample presentation context values: {pctx_values}")

    logger.info(f"Extracted {len(dicom_features_df)} flow-based DICOM features with {len(dicom_features_df.columns)} columns")
    return dicom_features_df

def merge_flow_and_dicom_features(flow_df, dicom_features_df):
    """Merge flow-based features with DICOM features."""
    logger.info("Merging flow-based features with DICOM features...")

    # Create flow_id column in flow_df
    flow_df['flow_id'] = flow_df.apply(lambda row: create_flow_id(row, False), axis=1)

    # Merge the dataframes
    merged_df = flow_df.merge(dicom_features_df, on='flow_id', how='left')

    # Fill NaN values with appropriate defaults
    numeric_columns = merged_df.select_dtypes(include=[np.number]).columns
    merged_df[numeric_columns] = merged_df[numeric_columns].fillna(0)

    # Fill string columns with empty strings
    string_columns = merged_df.select_dtypes(include=['object']).columns
    merged_df[string_columns] = merged_df[string_columns].fillna('')

    logger.info(f"Merged dataset contains {len(merged_df)} flows with {len(merged_df.columns)} features")
    return merged_df

def process_file_pair(tshark_file, cicflowmeter_file, output_dir):
    """Process a pair of corresponding files from tshark and cicflowmeter folders."""
    # Print a prominent header for this file pair
    print("\n" + "="*80)
    print(f"PROCESSING FILE PAIR:")
    print(f"  TSHARK FILE: {os.path.basename(tshark_file)}")
    print(f"  CICFLOWMETER FILE: {os.path.basename(cicflowmeter_file)}")
    print("="*80 + "\n")

    logger.info(f"Processing file pair: {os.path.basename(tshark_file)} and {os.path.basename(cicflowmeter_file)}")

    try:
        # Load the data
        logger.info(f"Loading tshark data from {tshark_file}...")
        packet_df = pd.read_csv(tshark_file)
        logger.info(f"Loaded {len(packet_df)} rows from tshark file")

        logger.info(f"Loading cicflowmeter data from {cicflowmeter_file}...")
        flow_df = pd.read_csv(cicflowmeter_file)
        logger.info(f"Loaded {len(flow_df)} rows from cicflowmeter file")

        # Extract DICOM features
        dicom_features_df = extract_dicom_features(packet_df)

        # Merge features
        merged_df = merge_flow_and_dicom_features(flow_df, dicom_features_df)

        # Create output filename based on the original filename
        base_name = os.path.basename(cicflowmeter_file).replace('.csv', '')
        output_file = os.path.join(output_dir, f"{base_name}_merged.csv")

        # Save the merged dataset
        merged_df.to_csv(output_file, index=False)
        logger.info(f"Merged dataset saved to {output_file}")

        # Print a success message
        print("\n" + "-"*80)
        print(f"SUCCESS: Merged {os.path.basename(tshark_file)} and {os.path.basename(cicflowmeter_file)}")
        print(f"Output saved to: {output_file}")
        print("-"*80 + "\n")

        return True
    except Exception as e:
        logger.error(f"Error processing file pair: {e}", exc_info=True)

        # Print an error message
        print("\n" + "!"*80)
        print(f"ERROR: Failed to process {os.path.basename(tshark_file)} and {os.path.basename(cicflowmeter_file)}")
        print(f"Error: {str(e)}")
        print("!"*80 + "\n")

        return False

def main():
    """Main function to process and merge files from tshark and cicflowmeter folders."""
    print("\n" + "="*80)
    print("DICOM FEATURE MERGING TOOL")
    print("="*80 + "\n")

    logger.info("Starting merge process...")

    # Define input and output directories
    tshark_dir = 'dicom_dataset/abnormal_tshark'
    cicflowmeter_dir = 'dicom_dataset/abnormal_cicflowmeter'
    output_dir = 'dicom_dataset/abnormal_merged_features'

    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"Created output directory: {output_dir}")

    # Get all CSV files from the cicflowmeter directory
    cicflowmeter_files = glob.glob(os.path.join(cicflowmeter_dir, '*.csv'))
    logger.info(f"Found {len(cicflowmeter_files)} files in {cicflowmeter_dir}")

    print(f"Found {len(cicflowmeter_files)} files to process in {cicflowmeter_dir}")

    # Process each file pair
    success_count = 0
    for i, cicflowmeter_file in enumerate(cicflowmeter_files, 1):
        # Get the base filename without extension
        base_name = os.path.basename(cicflowmeter_file).replace('.csv', '')

        # Find the corresponding tshark file
        tshark_file = os.path.join(tshark_dir, f"{base_name}_dicom.csv")

        print(f"\nProcessing file pair {i}/{len(cicflowmeter_files)}")

        if os.path.exists(tshark_file):
            if process_file_pair(tshark_file, cicflowmeter_file, output_dir):
                success_count += 1
        else:
            logger.warning(f"No matching tshark file found for {cicflowmeter_file}")
            print(f"\n" + "!"*80)
            print(f"WARNING: No matching tshark file found for {os.path.basename(cicflowmeter_file)}")
            print(f"Expected: {os.path.basename(tshark_file)}")
            print("!"*80 + "\n")

    # Print summary
    print("\n" + "="*80)
    print("MERGE PROCESS COMPLETE")
    print(f"Successfully processed {success_count} out of {len(cicflowmeter_files)} file pairs")
    print(f"All merged files are saved in {output_dir}")
    print("="*80 + "\n")

    logger.info(f"Successfully processed {success_count} out of {len(cicflowmeter_files)} file pairs")
    logger.info(f"All merged files are saved in {output_dir}")

if __name__ == "__main__":
    main()