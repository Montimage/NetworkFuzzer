#!/usr/bin/env python3
"""
Evaluate feature similarity between real and synthetic data using advanced metrics
for both discrete and continuous features. Also provides PCAP-level validation
for generated DICOM traffic.

Usage:
  python evaluate_feature_similarity.py <real_csv> <synthetic_csv> <output_dir>
  python evaluate_feature_similarity.py <real_csv> <synthetic_csv> <output_dir> --pcap-dir <dir>
  python evaluate_feature_similarity.py <real_csv> <synthetic_csv> <output_dir> --pcap-dir <dir> --attack-type <type>
"""
import os
import sys
import glob
import argparse
import subprocess
import pandas as pd
import numpy as np
import logging
from scipy.stats import chi2_contingency, ks_2samp, pearsonr, entropy
from collections import Counter

from attack_profiles import ATTACK_PROFILES, PDU_TYPE_MAP, get_attack_profile

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("feature_similarity_evaluation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Discrete Metrics ---
def total_variation_distance(p, q):
    return 0.5 * np.sum(np.abs(p - q))

def chi2_pvalue(real_counts, synth_counts):
    # Add a small value to avoid zero counts
    observed = np.array(list(synth_counts.values())) + 1e-8
    expected = np.array(list(real_counts.values())) + 1e-8
    try:
        chi2, p, _, _ = chi2_contingency([observed, expected])
        return p
    except Exception as e:
        logger.warning(f"Chi2 test failed: {e}")
        return np.nan

def category_coverage(real_categories, synth_categories):
    if len(real_categories) == 0:
        return np.nan
    covered = len(set(real_categories) & set(synth_categories))
    return covered / len(set(real_categories))

def discrete_kld(p, q):
    # Add small value to avoid log(0)
    p = p + 1e-10
    q = q + 1e-10
    dkl = entropy(p, q)
    return 1 / (1 + dkl)

# --- Continuous Metrics ---
def inverted_ks(real, synth):
    stat, _ = ks_2samp(real, synth)
    return 1 - stat

def pearson_corr(real, synth):
    try:
        corr, _ = pearsonr(real, synth)
        return corr
    except Exception as e:
        logger.warning(f"Pearson correlation failed: {e}")
        return np.nan

def statistic_similarity(real, synth):
    # StatS = 1 - |mean_r - mean_s| / (|mean_r| + |mean_s| + 1e-10)
    mean_r = np.mean(real)
    mean_s = np.mean(synth)
    return 1 - abs(mean_r - mean_s) / (abs(mean_r) + abs(mean_s) + 1e-10)

def continuous_kld(real, synth, bins=50):
    # Estimate PDFs with histograms
    p_hist, bin_edges = np.histogram(real, bins=bins, density=True)
    q_hist, _ = np.histogram(synth, bins=bin_edges, density=True)
    # Add small value to avoid log(0)
    p_hist = p_hist + 1e-10
    q_hist = q_hist + 1e-10
    dkl = entropy(p_hist, q_hist)
    return 1 / (1 + dkl)

# --- Main Evaluation ---
def detect_discrete_columns(df, max_unique=20):
    # Discrete if dtype is object or int, or few unique values
    discrete_cols = []
    continuous_cols = []
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            if df[col].nunique() <= max_unique:
                discrete_cols.append(col)
            else:
                continuous_cols.append(col)
        else:
            discrete_cols.append(col)
    return discrete_cols, continuous_cols

def aggregate_metrics(results, feature_type):
    filtered = [r for r in results if r['type'] == feature_type]
    if not filtered:
        return {}
    metrics = {k: [] for k in filtered[0] if k not in ['feature', 'type']}
    for r in filtered:
        for k in metrics:
            metrics[k].append(r[k])
    # Compute mean for each metric
    return {f"{feature_type}_{k}_mean": np.nanmean(metrics[k]) for k in metrics}

def evaluate_features(real_data, synth_data, output_dir):
    logger.info("Detecting discrete and continuous columns...")
    discrete_cols, continuous_cols = detect_discrete_columns(real_data)
    logger.info(f"Discrete columns: {discrete_cols}")
    logger.info(f"Continuous columns: {continuous_cols}")
    results = []
    # Discrete features
    for col in discrete_cols:
        try:
            real_col = real_data[col].dropna().astype(str)
            synth_col = synth_data[col].dropna().astype(str)
            real_counts = Counter(real_col)
            synth_counts = Counter(synth_col)
            all_cats = sorted(set(real_counts) | set(synth_counts))
            real_dist = np.array([real_counts.get(cat, 0) for cat in all_cats], dtype=float)
            synth_dist = np.array([synth_counts.get(cat, 0) for cat in all_cats], dtype=float)
            real_dist /= real_dist.sum() if real_dist.sum() > 0 else 1
            synth_dist /= synth_dist.sum() if synth_dist.sum() > 0 else 1
            tvd = total_variation_distance(real_dist, synth_dist)
            pval = chi2_pvalue(real_counts, synth_counts)
            catcov = category_coverage(real_counts, synth_counts)
            dkld = discrete_kld(real_dist, synth_dist)
            results.append({
                'feature': col,
                'type': 'discrete',
                'TVD': tvd,
                'Chi2_pvalue': pval,
                'CatCov': catcov,
                'D-KLD': dkld
            })
        except Exception as e:
            logger.warning(f"Skipping discrete feature {col} due to: {e}")
    # Continuous features
    for col in continuous_cols:
        try:
            real_col = pd.to_numeric(real_data[col], errors='coerce').dropna()
            synth_col = pd.to_numeric(synth_data[col], errors='coerce').dropna()
            if len(real_col) == 0 or len(synth_col) == 0:
                continue
            iks = inverted_ks(real_col, synth_col)
            pcc = pearson_corr(real_col, synth_col)
            stats = statistic_similarity(real_col, synth_col)
            ckld = continuous_kld(real_col, synth_col)
            results.append({
                'feature': col,
                'type': 'continuous',
                'IKS': iks,
                'PCC': pcc,
                'StatS': stats,
                'C-KLD': ckld
            })
        except Exception as e:
            logger.warning(f"Skipping continuous feature {col} due to: {e}")
    # Save per-feature results
    out_csv = os.path.join(output_dir, "feature_similarity_metrics.csv")
    pd.DataFrame(results).to_csv(out_csv, index=False)
    logger.info(f"Feature similarity metrics saved to {out_csv}")
    # Aggregate and save summary
    agg_discrete = aggregate_metrics(results, 'discrete')
    agg_continuous = aggregate_metrics(results, 'continuous')
    summary_file = os.path.join(output_dir, "feature_similarity_summary.txt")
    with open(summary_file, "w") as f:
        f.write("=== Discrete Features ===\n")
        for k, v in agg_discrete.items():
            f.write(f"{k}: {v:.4f}\n")
        f.write("\n=== Continuous Features ===\n")
        for k, v in agg_continuous.items():
            f.write(f"{k}: {v:.4f}\n")
    logger.info(f"Feature similarity summary saved to {summary_file}")

# --- PCAP Validation ---

def validate_pcap_dicom(pcap_path):
    """
    Validate a single PCAP file for DICOM protocol content using tshark.

    Returns dict with:
      - valid: bool (tshark found DICOM packets)
      - dicom_packets: int (number of DICOM packets)
      - pdu_types: list of PDU type codes found
      - errors: list of error strings
    """
    result = {
        "pcap": os.path.basename(pcap_path),
        "valid": False,
        "dicom_packets": 0,
        "pdu_types": [],
        "errors": [],
    }

    try:
        # Run tshark to extract DICOM PDU types
        cmd = [
            "tshark", "-r", pcap_path,
            "-Y", "dicom",
            "-T", "fields",
            "-e", "dicom.pdu.type",
            "-E", "separator=,",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if proc.returncode != 0:
            result["errors"].append(f"tshark error: {proc.stderr.strip()}")
            return result

        lines = [l.strip() for l in proc.stdout.strip().split('\n') if l.strip()]
        result["dicom_packets"] = len(lines)
        result["valid"] = len(lines) > 0

        # Collect unique PDU types
        pdu_types = set()
        for line in lines:
            for val in line.split(','):
                val = val.strip()
                if val:
                    pdu_types.add(val)
        result["pdu_types"] = sorted(pdu_types)

    except FileNotFoundError:
        result["errors"].append("tshark not found in PATH")
    except subprocess.TimeoutExpired:
        result["errors"].append("tshark timed out")
    except Exception as e:
        result["errors"].append(str(e))

    return result


def validate_pcap_directory(pcap_dir, output_dir):
    """
    Validate all PCAPs in a directory for DICOM content.
    Saves results to a CSV report.
    """
    pcap_files = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap")))
    if not pcap_files:
        logger.warning(f"No PCAP files found in {pcap_dir}")
        return []

    logger.info(f"Validating {len(pcap_files)} PCAP files in {pcap_dir}")
    results = []
    for pcap_path in pcap_files:
        result = validate_pcap_dicom(pcap_path)
        results.append(result)

    # Summary
    valid_count = sum(1 for r in results if r["valid"])
    total_dicom = sum(r["dicom_packets"] for r in results)
    error_count = sum(1 for r in results if r["errors"])

    logger.info(f"PCAP validation: {valid_count}/{len(results)} valid, "
                f"{total_dicom} total DICOM packets, {error_count} errors")

    # Save report
    report_file = os.path.join(output_dir, "pcap_validation_report.csv")
    report_df = pd.DataFrame(results)
    report_df.to_csv(report_file, index=False)
    logger.info(f"PCAP validation report saved to {report_file}")

    return results


def evaluate_attack_coverage(pcap_dir, attack_type, output_dir):
    """
    Check if generated PCAPs match expected attack patterns for a given attack type.
    """
    profile = get_attack_profile(attack_type)
    if not profile:
        logger.warning(f"Unknown attack type: {attack_type}")
        return

    pcap_files = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap")))
    if not pcap_files:
        logger.warning(f"No PCAP files found in {pcap_dir}")
        return

    logger.info(f"Evaluating attack coverage for '{attack_type}' across {len(pcap_files)} PCAPs")

    coverage_results = []
    for pcap_path in pcap_files:
        result = validate_pcap_dicom(pcap_path)
        check = {
            "pcap": result["pcap"],
            "has_dicom": result["valid"],
            "pdu_types_found": ",".join(result["pdu_types"]),
        }

        # Check for expected PDU types based on profile
        expected_types = set()
        if "pdu_sequence" in profile:
            for pdu_name in profile["pdu_sequence"]:
                if pdu_name in PDU_TYPE_MAP:
                    expected_types.add(f"0x{PDU_TYPE_MAP[pdu_name]:02x}")
        elif "pdu_sequence_variants" in profile:
            for seq in profile["pdu_sequence_variants"]:
                for pdu_name in seq:
                    if pdu_name in PDU_TYPE_MAP:
                        expected_types.add(f"0x{PDU_TYPE_MAP[pdu_name]:02x}")

        found_types = set(result["pdu_types"])
        check["expected_types"] = ",".join(sorted(expected_types))
        check["type_coverage"] = len(found_types & expected_types) / max(1, len(expected_types))
        coverage_results.append(check)

    # Save coverage report
    report_file = os.path.join(output_dir, f"attack_coverage_{attack_type}.csv")
    pd.DataFrame(coverage_results).to_csv(report_file, index=False)
    logger.info(f"Attack coverage report saved to {report_file}")

    # Summary
    avg_coverage = np.mean([r["type_coverage"] for r in coverage_results])
    dicom_rate = np.mean([r["has_dicom"] for r in coverage_results])
    logger.info(f"Attack coverage summary for '{attack_type}': "
                f"DICOM detection rate={dicom_rate:.1%}, "
                f"PDU type coverage={avg_coverage:.1%}")


def evaluate_detection_rate(pcap_dir, output_dir, rule_range="1-229"):
    """
    Run mmt_sec_standalone on generated PCAPs and report which detection rules fire.
    Requires mmt_sec_standalone to be installed and in PATH.
    """
    pcap_files = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap")))
    if not pcap_files:
        logger.warning(f"No PCAP files found in {pcap_dir}")
        return

    logger.info(f"Running mmt-security detection on {len(pcap_files)} PCAPs")

    results = []
    for pcap_path in pcap_files:
        result = {
            "pcap": os.path.basename(pcap_path),
            "rules_triggered": [],
            "alert_count": 0,
            "error": "",
        }
        try:
            cmd = ["mmt_sec_standalone", "-t", pcap_path, "-x", rule_range]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if proc.returncode != 0 and proc.returncode != 1:
                result["error"] = proc.stderr.strip()[:200]
            else:
                # Parse output for rule triggers
                for line in proc.stdout.split('\n'):
                    if 'rule' in line.lower() and ('satisfied' in line.lower() or 'detected' in line.lower()):
                        result["alert_count"] += 1
                        result["rules_triggered"].append(line.strip()[:100])

        except FileNotFoundError:
            result["error"] = "mmt_sec_standalone not found"
        except subprocess.TimeoutExpired:
            result["error"] = "mmt_sec_standalone timed out"
        except Exception as e:
            result["error"] = str(e)

        result["rules_triggered"] = "; ".join(result["rules_triggered"])
        results.append(result)

    # Save detection report
    report_file = os.path.join(output_dir, "detection_report.csv")
    pd.DataFrame(results).to_csv(report_file, index=False)
    logger.info(f"Detection report saved to {report_file}")

    total_alerts = sum(r["alert_count"] for r in results)
    pcaps_with_alerts = sum(1 for r in results if r["alert_count"] > 0)
    logger.info(f"Detection summary: {total_alerts} alerts across "
                f"{pcaps_with_alerts}/{len(results)} PCAPs")


def main():
    parser = argparse.ArgumentParser(
        description='Evaluate feature similarity and PCAP validity')
    parser.add_argument('real_csv',
                        help='Path to the CSV file containing real data')
    parser.add_argument('synthetic_csv',
                        help='Path to the CSV file containing synthetic data')
    parser.add_argument('output_dir',
                        help='Directory to save evaluation results')
    parser.add_argument('--pcap-dir', type=str, default=None,
                        help='Directory containing generated PCAPs to validate')
    parser.add_argument('--attack-type', type=str, default=None,
                        help='Attack type for coverage evaluation')
    parser.add_argument('--detect', action='store_true',
                        help='Run mmt-security detection on PCAPs')
    parser.add_argument('--rule-range', type=str, default="1-229",
                        help='Rule range for mmt-security (default: 1-229)')

    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    # Feature similarity evaluation (original functionality)
    real_data = pd.read_csv(args.real_csv)
    synth_data = pd.read_csv(args.synthetic_csv)

    # Only evaluate common columns
    common_cols = [c for c in real_data.columns if c in synth_data.columns]
    if common_cols:
        evaluate_features(
            real_data[common_cols], synth_data[common_cols], args.output_dir
        )
    else:
        logger.warning("No common columns between real and synthetic data; "
                       "skipping feature similarity evaluation")

    # PCAP validation (new functionality)
    if args.pcap_dir:
        validate_pcap_directory(args.pcap_dir, args.output_dir)

        if args.attack_type:
            evaluate_attack_coverage(args.pcap_dir, args.attack_type, args.output_dir)

        if args.detect:
            evaluate_detection_rate(args.pcap_dir, args.output_dir, args.rule_range)

    logger.info("Evaluation completed successfully.")


if __name__ == "__main__":
    main()