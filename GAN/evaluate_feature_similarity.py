#!/usr/bin/env python3
"""
Evaluate feature similarity between real and synthetic data using advanced metrics for both discrete and continuous features.

Usage: python evaluate_feature_similarity.py <real_csv> <synthetic_csv> <output_dir>
"""
import os
import sys
import argparse
import pandas as pd
import numpy as np
import logging
from scipy.stats import chi2_contingency, ks_2samp, pearsonr, entropy
from collections import Counter

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

def main():
    parser = argparse.ArgumentParser(description='Evaluate feature similarity between real and synthetic data')
    parser.add_argument('real_csv', help='Path to the CSV file containing real data')
    parser.add_argument('synthetic_csv', help='Path to the CSV file containing synthetic data')
    parser.add_argument('output_dir', help='Directory to save evaluation results')
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    real_data = pd.read_csv(args.real_csv)
    synth_data = pd.read_csv(args.synthetic_csv)
    evaluate_features(real_data, synth_data, args.output_dir)
    logger.info("Feature similarity evaluation completed successfully.")

if __name__ == "__main__":
    main()