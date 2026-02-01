#!/usr/bin/env python3
"""
DICOM Flow GAN Generator

Uses CTGAN (Conditional Tabular GAN) to generate synthetic DICOM flow data.
Supports three modes:
  - flow:     Legacy mode - trains on all numeric flow statistics (CICFlowMeter)
  - protocol: Trains on DICOM protocol fields (categorical + numeric), producing
              session-level parameters for PCAP generation
  - attack:   Trains on malicious samples only, with attack profile constraints

Usage:
  python gan.py <normal_csv> <malicious_csv> <output_dir> [options]
  python gan.py --mode protocol <normal_csv> <malicious_csv> <output_dir>
  python gan.py --mode attack --attack-type ae_manipulation <normal_csv> <malicious_csv> <output_dir>
"""

import os
import sys
import argparse
import pandas as pd
import numpy as np
import logging
import random
from datetime import datetime

try:
    from ctgan import CTGAN
except ImportError as e:
    print(f"Error importing CTGAN: {e}")
    print("Please install ctgan: pip install ctgan")
    sys.exit(1)

from attack_profiles import (
    ATTACK_PROFILES, get_attack_profile, list_attack_types, get_pdu_sequence,
    LEGITIMATE_AE_TITLES, VERIFICATION_SOP, CT_IMAGE_STORAGE, MR_IMAGE_STORAGE,
    US_IMAGE_STORAGE, IMPLICIT_VR_LE, EXPLICIT_VR_LE, DICOM_APP_CONTEXT,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gan_generation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Column definitions ---

# DICOM protocol columns to retain in protocol/attack modes (categorical)
DICOM_CATEGORICAL_COLS = [
    "dicom_pdu_types",
    "dicom.assoc.ae.called",
    "dicom.assoc.ae.calling",
    "dicom.pctx.abss.syntax",
    "dicom.pctx.xfer.syntax",
    "dicom.actx",
    "dicom.userinfo.uid",
    "dicom.userinfo.version",
    "dicom.pdv.flags",
    "dicom.pctx.result",
    "dicom.pctx.id",
    "dicom.assoc.item.type",
]

# DICOM numeric columns
DICOM_NUMERIC_COLS = [
    "dicom_pdu_count",
    "dicom.assoc.version_mean",
    "dicom.max_pdu_len_mean",
    "dicom.max_pdu_len_max",
    "dicom.max_pdu_len_min",
    "dicom_pdu_len_mean",
    "dicom_pdu_len_max",
    "dicom_pdu_len_min",
    "dicom_pdu_len_std",
    "dicom_assoc_request_count",
    "dicom_assoc_response_count",
    "dicom_release_request_count",
    "dicom_release_response_count",
    "dicom_data_transfer_count",
    "dicom_abort_count",
    "dicom.pdv.len_mean",
    "dicom.pdv.len_max",
    "dicom.pdv.len_min",
    "dicom.pdv.len_std",
    "dicom.pdv.ctx_mean",
    "dicom.pdv.ctx_max",
    "dicom.pdv.ctx_min",
    "dicom.pdv.ctx_std",
    "dicom.assoc.reject.result_mean",
    "dicom.assoc.reject.source_mean",
    "dicom.assoc.reject.reason_mean",
    "dicom.assoc.abort.source_mean",
    "dicom.assoc.abort.reason_mean",
]

# Columns for the structured session output
SESSION_OUTPUT_COLS = [
    "session_id", "pdu_sequence", "called_ae", "calling_ae",
    "abstract_syntax", "transfer_syntax", "max_pdu_len",
    "pdu_count", "pdu_len_mean", "pdu_len_max",
    "pdv_len_mean", "pdv_len_max", "pdv_ctx", "pdv_flags",
    "data_transfer_count", "assoc_request_count",
    "release_request_count", "abort_count",
    "patient_name", "attack_type", "label",
]


def load_and_prepare_data(normal_csv, malicious_csv):
    """Load and combine normal and malicious DICOM flow CSVs."""
    logger.info(f"Loading normal DICOM flows from {normal_csv}")
    normal_data = pd.read_csv(normal_csv)
    logger.info(f"Loaded {len(normal_data)} normal DICOM flows")

    logger.info(f"Loading malicious DICOM flows from {malicious_csv}")
    malicious_data = pd.read_csv(malicious_csv)
    logger.info(f"Loaded {len(malicious_data)} malicious DICOM flows")

    combined_data = pd.concat([normal_data, malicious_data], ignore_index=True)
    logger.info(f"Combined data: {len(combined_data)} rows, {len(combined_data.columns)} columns")
    return combined_data


def clean_data_flow(data):
    """
    Legacy flow-mode cleaning: removes datetime and long-string columns,
    converts everything to numeric. This is the original behavior.
    """
    logger.info("Flow mode: cleaning data (legacy behavior)")
    cleaned = data.copy()

    columns_to_remove = []
    for col in cleaned.columns:
        if 'time' in col.lower() or 'date' in col.lower():
            columns_to_remove.append(col)

    for col in cleaned.columns:
        if not pd.api.types.is_numeric_dtype(cleaned[col]) and col not in columns_to_remove:
            max_length = cleaned[col].astype(str).str.len().max()
            if max_length > 50:
                columns_to_remove.append(col)

    if columns_to_remove:
        logger.info(f"Removing {len(columns_to_remove)} columns: {', '.join(columns_to_remove)}")
        cleaned = cleaned.drop(columns=columns_to_remove, errors='ignore')

    # Fill nulls
    for col in cleaned.columns:
        if cleaned[col].isnull().sum() > 0:
            if pd.api.types.is_numeric_dtype(cleaned[col]):
                cleaned[col] = cleaned[col].fillna(cleaned[col].median())
            else:
                cleaned[col] = cleaned[col].fillna(cleaned[col].mode().iloc[0] if len(cleaned[col].mode()) > 0 else "")

    # Force numeric
    for col in cleaned.columns:
        if not pd.api.types.is_numeric_dtype(cleaned[col]):
            cleaned[col] = pd.to_numeric(cleaned[col], errors='coerce').fillna(0)

    logger.info(f"Flow mode cleaned data: {cleaned.shape}")
    return cleaned


def clean_data_protocol(data):
    """
    Protocol-mode cleaning: retains DICOM categorical columns as discrete features,
    keeps DICOM numeric columns, and the label. Drops flow-statistics columns that
    aren't relevant to protocol-level generation.
    """
    logger.info("Protocol mode: extracting DICOM protocol features")
    cleaned = data.copy()

    # Select only DICOM-relevant columns + label
    keep_cols = []
    for col in DICOM_CATEGORICAL_COLS:
        if col in cleaned.columns:
            keep_cols.append(col)
        else:
            logger.warning(f"Categorical column '{col}' not found in data")

    for col in DICOM_NUMERIC_COLS:
        if col in cleaned.columns:
            keep_cols.append(col)

    if "label" in cleaned.columns:
        keep_cols.append("label")

    cleaned = cleaned[keep_cols].copy()

    # Clean categorical columns: strip whitespace, replace empty with "UNKNOWN"
    for col in DICOM_CATEGORICAL_COLS:
        if col not in cleaned.columns:
            continue
        cleaned[col] = cleaned[col].astype(str).str.strip()
        cleaned[col] = cleaned[col].replace({"nan": "UNKNOWN", "": "UNKNOWN", "None": "UNKNOWN"})
        # Truncate very long values to keep CTGAN happy (max 200 chars)
        cleaned[col] = cleaned[col].str[:200]
        n_unique = cleaned[col].nunique()
        logger.info(f"  Categorical '{col}': {n_unique} unique values")

    # Clean numeric columns: fill NaN with 0
    for col in DICOM_NUMERIC_COLS:
        if col not in cleaned.columns:
            continue
        cleaned[col] = pd.to_numeric(cleaned[col], errors='coerce').fillna(0)

    if "label" in cleaned.columns:
        cleaned["label"] = pd.to_numeric(cleaned["label"], errors='coerce').fillna(0).astype(int)

    cleaned = cleaned.dropna(axis=1, how='all')
    logger.info(f"Protocol mode cleaned data: {cleaned.shape}")
    return cleaned


def clean_data_attack(data, attack_type=None):
    """
    Attack-mode cleaning: filters to malicious samples only (label=1),
    then applies protocol-mode cleaning.
    """
    logger.info("Attack mode: filtering to malicious samples")

    if "label" in data.columns:
        malicious = data[pd.to_numeric(data["label"], errors='coerce') == 1].copy()
        if len(malicious) == 0:
            logger.warning("No malicious samples found (label=1), using all data")
            malicious = data.copy()
        else:
            logger.info(f"Filtered to {len(malicious)} malicious samples")
    else:
        logger.warning("No 'label' column found, using all data")
        malicious = data.copy()

    cleaned = clean_data_protocol(malicious)

    if attack_type:
        profile = get_attack_profile(attack_type)
        if profile:
            logger.info(f"Attack profile '{attack_type}': {profile['description']}")

    return cleaned


def get_categorical_columns(data, mode):
    """Identify categorical columns for CTGAN based on mode."""
    categorical = []

    if mode == "flow":
        if "label" in data.columns:
            categorical.append("label")
        for col in data.columns:
            if not pd.api.types.is_numeric_dtype(data[col]):
                if data[col].nunique() < 50:
                    categorical.append(col)
    else:
        # protocol and attack modes: DICOM categorical cols + label
        for col in DICOM_CATEGORICAL_COLS:
            if col in data.columns:
                categorical.append(col)
        if "label" in data.columns:
            categorical.append("label")

    return list(set(categorical))


def train_ctgan(data, categorical_columns, epochs=100, batch_size=500):
    """Train a CTGAN model."""
    # Adjust batch size if data is too small
    if len(data) < batch_size:
        batch_size = max(10, len(data))
        logger.info(f"Adjusted batch_size to {batch_size} (data has {len(data)} rows)")

    logger.info(f"Training CTGAN: {len(data)} rows, {len(data.columns)} columns, "
                f"{len(categorical_columns)} categorical, {epochs} epochs, batch_size={batch_size}")
    logger.info(f"Categorical columns: {categorical_columns}")

    model = CTGAN(
        epochs=epochs,
        batch_size=batch_size,
        verbose=True,
        cuda=False,
    )
    model.fit(data, categorical_columns)
    logger.info("CTGAN training completed")
    return model


def generate_samples(model, num_samples):
    """Generate synthetic samples from trained model."""
    logger.info(f"Generating {num_samples} synthetic samples")
    synthetic = model.sample(num_samples)
    logger.info(f"Generated {len(synthetic)} samples")
    return synthetic


def postprocess_to_sessions(synthetic_data, attack_type=None):
    """
    Convert raw CTGAN output into structured session parameters.
    Each row becomes a DICOM session description suitable for PCAP generation.
    """
    sessions = []

    for idx, row in synthetic_data.iterrows():
        session = {
            "session_id": idx,
            "attack_type": attack_type or "",
            "label": int(row.get("label", 1)),
        }

        # PDU sequence: derive from attack profile or from data
        if attack_type:
            profile = get_attack_profile(attack_type)
            if profile:
                sequences = get_pdu_sequence(profile)
                session["pdu_sequence"] = random.choice(sequences) if isinstance(sequences[0], list) else sequences[0]
                # Apply field overrides from profile
                session = _apply_attack_overrides(session, profile, row)
            else:
                session["pdu_sequence"] = _derive_pdu_sequence(row)
        else:
            session["pdu_sequence"] = _derive_pdu_sequence(row)

        # Convert pdu_sequence list to comma-separated string for CSV
        if isinstance(session["pdu_sequence"], list):
            session["pdu_sequence"] = ",".join(session["pdu_sequence"])

        # Extract DICOM fields from GAN output, but don't overwrite
        # values already set by attack profile overrides
        session.setdefault("called_ae", _get_str(row, "dicom.assoc.ae.called", "ANY-SCP"))
        session.setdefault("calling_ae", _get_str(row, "dicom.assoc.ae.calling", "PYNETDICOM"))
        session.setdefault("abstract_syntax", _get_str(row, "dicom.pctx.abss.syntax", VERIFICATION_SOP))
        session.setdefault("transfer_syntax", _get_str(row, "dicom.pctx.xfer.syntax", IMPLICIT_VR_LE))
        session.setdefault("max_pdu_len", int(max(4096, _get_num(row, "dicom.max_pdu_len_mean", 16384))))
        session.setdefault("pdu_count", int(max(1, _get_num(row, "dicom_pdu_count", 4))))
        session.setdefault("pdu_len_mean", _get_num(row, "dicom_pdu_len_mean", 1000))
        session.setdefault("pdu_len_max", _get_num(row, "dicom_pdu_len_max", 16384))
        session.setdefault("pdv_len_mean", _get_num(row, "dicom.pdv.len_mean", 1000))
        session.setdefault("pdv_len_max", _get_num(row, "dicom.pdv.len_max", 16380))
        session.setdefault("pdv_ctx", int(max(1, _get_num(row, "dicom.pdv.ctx_mean", 1))))
        session.setdefault("pdv_flags", _get_str(row, "dicom.pdv.flags", "0x00,0x02"))
        session.setdefault("data_transfer_count", int(max(0, _get_num(row, "dicom_data_transfer_count", 1))))
        session.setdefault("assoc_request_count", int(max(0, _get_num(row, "dicom_assoc_request_count", 1))))
        session.setdefault("release_request_count", int(max(0, _get_num(row, "dicom_release_request_count", 0))))
        session.setdefault("abort_count", int(max(0, _get_num(row, "dicom_abort_count", 0))))
        session.setdefault("patient_name", "")

        sessions.append(session)

    return pd.DataFrame(sessions, columns=SESSION_OUTPUT_COLS)


def _derive_pdu_sequence(row):
    """Derive a PDU sequence from the GAN-generated flow statistics."""
    sequence = []
    assoc_req = _get_num(row, "dicom_assoc_request_count", 1)
    assoc_resp = _get_num(row, "dicom_assoc_response_count", 0)
    data_count = _get_num(row, "dicom_data_transfer_count", 0)
    release_req = _get_num(row, "dicom_release_request_count", 0)
    release_resp = _get_num(row, "dicom_release_response_count", 0)
    abort_count = _get_num(row, "dicom_abort_count", 0)

    if assoc_req > 0:
        sequence.append("assoc_rq")
    if assoc_resp > 0:
        sequence.append("assoc_ac")
    for _ in range(min(int(data_count), 10)):  # cap at 10 P-DATA PDUs
        sequence.append("pdata")
    if abort_count > 0:
        sequence.append("abort")
    elif release_req > 0:
        sequence.append("release_rq")
        if release_resp > 0:
            sequence.append("release_rp")

    if not sequence:
        sequence = ["assoc_rq", "assoc_ac", "pdata", "release_rq", "release_rp"]

    return sequence


def _apply_attack_overrides(session, profile, row):
    """Apply attack-profile-specific field overrides to a session."""
    attack_type = session.get("attack_type", "")

    if attack_type == "ae_manipulation":
        if "ae_called_variants" in profile:
            session["called_ae"] = random.choice(profile["ae_called_variants"])
        if "ae_calling_variants" in profile:
            session["calling_ae"] = random.choice(profile["ae_calling_variants"])
        if profile.get("swap_ae_titles") and random.random() < 0.3:
            session["called_ae"], session["calling_ae"] = session.get("calling_ae", ""), session.get("called_ae", "")

    elif attack_type == "abort_injection":
        if "field_overrides" in profile:
            overrides = profile["field_overrides"]
            session["abort_source"] = random.choice(overrides.get("abort_source", [0]))
            session["abort_reason"] = random.choice(overrides.get("abort_reason", [0]))

    elif attack_type == "pdu_length_attack":
        if "pdu_len_variants" in profile:
            session["pdu_len_override"] = random.choice(profile["pdu_len_variants"])

    elif attack_type == "cve_payloads":
        if "abstract_syntax_variants" in profile:
            session["abstract_syntax"] = random.choice(profile["abstract_syntax_variants"])
        if "transfer_syntax_variants" in profile:
            session["transfer_syntax"] = random.choice(profile["transfer_syntax_variants"])
        if "app_context_variants" in profile:
            session["app_context"] = random.choice(profile["app_context_variants"])

    elif attack_type == "association_flood":
        if "num_associations" in profile:
            n = random.choice(profile["num_associations"])
            session["pdu_sequence"] = ["assoc_rq"] * n
        if "max_pdu_len_variants" in profile:
            session["max_pdu_len"] = random.choice(profile["max_pdu_len_variants"])

    elif attack_type == "patient_enum":
        if "patient_name_variants" in profile:
            session["patient_name"] = random.choice(profile["patient_name_variants"])
        if "patient_id_variants" in profile:
            session["patient_id"] = random.choice(profile["patient_id_variants"])

    elif attack_type == "patient_data_injection":
        if "patient_name_variants" in profile:
            session["patient_name"] = random.choice(profile["patient_name_variants"])
        if "patient_id_variants" in profile:
            session["patient_id"] = random.choice(profile["patient_id_variants"])

    elif attack_type == "imaging_manipulation":
        if "window_center_variants" in profile:
            session["window_center"] = random.choice(profile["window_center_variants"])
        if "window_width_variants" in profile:
            session["window_width"] = random.choice(profile["window_width_variants"])

    # Use abstract/transfer syntaxes from profile if present
    if "abstract_syntaxes" in profile:
        session.setdefault("abstract_syntax", random.choice(profile["abstract_syntaxes"]))
    if "transfer_syntaxes" in profile:
        session.setdefault("transfer_syntax", random.choice(profile["transfer_syntaxes"]))

    return session


def _get_str(row, col, default=""):
    """Safely extract a string value from a row."""
    val = row.get(col, default)
    if pd.isna(val) or str(val).strip() in ("", "nan", "UNKNOWN", "None"):
        return default
    return str(val).strip()


def _get_num(row, col, default=0):
    """Safely extract a numeric value from a row."""
    val = row.get(col, default)
    try:
        result = float(val)
        if np.isnan(result) or np.isinf(result):
            return float(default)
        return result
    except (ValueError, TypeError):
        return float(default)


def save_output(data, output_dir, prefix="synthetic_dicom"):
    """Save output CSV and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"{prefix}_flows_{timestamp}.csv")
    data.to_csv(output_file, index=False)
    logger.info(f"Saved output to {output_file}")
    return output_file


def main():
    parser = argparse.ArgumentParser(
        description='Generate synthetic DICOM flow data using CTGAN')
    parser.add_argument('normal_csv',
                        help='Path to CSV with normal DICOM flows')
    parser.add_argument('malicious_csv',
                        help='Path to CSV with malicious DICOM flows')
    parser.add_argument('output_dir',
                        help='Directory to save generated data')
    parser.add_argument('--mode', choices=['flow', 'protocol', 'attack'],
                        default='protocol',
                        help='Generation mode (default: protocol)')
    parser.add_argument('--attack-type', type=str, default=None,
                        help='Attack profile name (for attack mode)')
    parser.add_argument('--samples', type=int, default=1000,
                        help='Number of synthetic samples (default: 1000)')
    parser.add_argument('--epochs', type=int, default=100,
                        help='Training epochs (default: 100)')
    parser.add_argument('--batch-size', type=int, default=500,
                        help='Training batch size (default: 500)')

    args = parser.parse_args()

    print("\n" + "=" * 80)
    print(f"DICOM GAN GENERATOR — Mode: {args.mode.upper()}")
    if args.attack_type:
        print(f"Attack Type: {args.attack_type}")
    print("=" * 80 + "\n")

    if args.mode == "attack" and args.attack_type:
        if args.attack_type not in ATTACK_PROFILES:
            print(f"ERROR: Unknown attack type '{args.attack_type}'")
            print(f"Available types: {', '.join(list_attack_types())}")
            sys.exit(1)

    try:
        # Load data
        data = load_and_prepare_data(args.normal_csv, args.malicious_csv)

        # Clean based on mode
        if args.mode == "flow":
            cleaned = clean_data_flow(data)
        elif args.mode == "attack":
            cleaned = clean_data_attack(data, args.attack_type)
        else:
            cleaned = clean_data_protocol(data)

        # Identify categorical columns
        categorical_cols = get_categorical_columns(cleaned, args.mode)

        # Train CTGAN
        model = train_ctgan(cleaned, categorical_cols,
                            epochs=args.epochs, batch_size=args.batch_size)

        # Generate synthetic data
        synthetic = generate_samples(model, args.samples)

        # Post-process based on mode
        if args.mode in ("protocol", "attack"):
            output_data = postprocess_to_sessions(synthetic, args.attack_type)
            prefix = f"synthetic_dicom_{args.attack_type}" if args.attack_type else "synthetic_dicom"
        else:
            output_data = synthetic
            prefix = "synthetic_dicom"

        # Save
        output_file = save_output(output_data, args.output_dir, prefix)

        # Report
        print("\n" + "-" * 80)
        print(f"SUCCESS: Generated {args.samples} synthetic DICOM sessions")
        print(f"Mode: {args.mode}")
        if args.attack_type:
            print(f"Attack type: {args.attack_type}")
        print(f"Output: {output_file}")
        if "label" in output_data.columns:
            label_counts = output_data["label"].value_counts().to_dict()
            print(f"Label distribution: {label_counts}")
        print("-" * 80 + "\n")

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        print(f"\nERROR: {str(e)}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
