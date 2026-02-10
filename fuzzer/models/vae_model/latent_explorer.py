#!/usr/bin/env python3
"""
Controlled malformation generation using trained VAE latent space.

Strategies:
  interpolate  — Blend between valid and random/malformed latent vectors
  boundary     — Sample from the edge of the learned distribution
  walk         — Step through latent space from a valid starting point
  targeted     — Perturb specific latent dimensions

Usage:
    python -m fuzzer.models.vae_model.latent_explorer --model fuzzer/data/models/assoc_rq_vae.pt --strategy interpolate --degree 0.5 --count 100
    python -m fuzzer.models.vae_model.latent_explorer --model fuzzer/data/models/assoc_rq_vae.pt --strategy boundary --count 50
    python -m fuzzer.models.vae_model.latent_explorer --model fuzzer/data/models/assoc_rq_vae.pt --strategy walk --steps 20
"""

import os
import sys
import argparse
import logging
import glob

import numpy as np
import torch
import torch.nn.functional as F

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from fuzzer.models.vae_model.vae import ConvVAE

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("vae_generate.log"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)

PAD_VALUE = 256


def load_vae(model_path, device="cpu"):
    """Load a trained ConvVAE from checkpoint."""
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    config = checkpoint["config"]
    model = ConvVAE(
        max_length=config["max_length"],
        latent_dim=config["latent_dim"],
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model = model.to(device)
    model.eval()
    return model, config


def load_seed_pdus(data_dir, max_length, max_pdus=200):
    """Load PDU byte sequences for encoding into latent space."""
    sequences = []

    bytes_path = os.path.join(data_dir, "bytes.npy")
    offsets_path = os.path.join(data_dir, "offsets.npy")

    if os.path.exists(bytes_path) and os.path.exists(offsets_path):
        all_bytes = np.load(bytes_path)
        offsets = np.load(offsets_path)
        for i in range(min(len(offsets) - 1, max_pdus)):
            seq = all_bytes[offsets[i]:offsets[i + 1]].tolist()
            if seq:
                sequences.append(seq)
    else:
        for f in sorted(glob.glob(os.path.join(data_dir, "*.bin")))[:max_pdus]:
            with open(f, 'rb') as fh:
                sequences.append(list(fh.read()))

    # Pad/truncate to max_length
    padded = []
    for seq in sequences:
        if len(seq) > max_length:
            seq = seq[:max_length]
        seq = seq + [PAD_VALUE] * (max_length - len(seq))
        padded.append(seq)

    return torch.tensor(padded, dtype=torch.long) if padded else None


def decode_to_bytes(model, z):
    """Decode latent vectors to raw byte sequences."""
    with torch.no_grad():
        logits = model.decode(z)  # (batch, max_length, 256)
        byte_vals = logits.argmax(dim=-1)  # (batch, max_length)

    results = []
    for i in range(byte_vals.size(0)):
        seq = byte_vals[i].cpu().numpy()
        # Trim trailing zeros (likely padding region)
        nonzero = np.where(seq != 0)[0]
        if len(nonzero) > 0:
            end = nonzero[-1] + 1
            results.append(bytes(seq[:end].astype(np.uint8)))
        else:
            results.append(bytes(seq.astype(np.uint8)))

    return results


def encode_seeds(model, seed_tensor):
    """Encode seed PDUs to latent vectors."""
    with torch.no_grad():
        mu, log_var = model.encode(seed_tensor)
    return mu, log_var


def strategy_interpolate(model, seed_tensor, degree, count):
    """
    Interpolate between valid PDU centroids and random latent vectors.

    degree=0.0: faithful reconstruction of valid PDUs
    degree=0.5: novel borderline PDUs
    degree=1.0: fully random/malformed
    """
    mu, _ = encode_seeds(model, seed_tensor)
    z_normal = mu.mean(dim=0, keepdim=True)  # Centroid of valid data

    results = []
    for i in range(count):
        z_random = torch.randn_like(z_normal) * 2.0  # Random point in latent space
        z = (1.0 - degree) * z_normal + degree * z_random
        pdus = decode_to_bytes(model, z)
        results.extend(pdus)

    return results[:count]


def strategy_boundary(model, seed_tensor, count):
    """
    Sample from the boundary of the learned distribution.

    These PDUs have the highest reconstruction error — most unusual structure.
    Samples at 2-3 standard deviations from the mean.
    """
    mu, log_var = encode_seeds(model, seed_tensor)
    z_mean = mu.mean(dim=0)
    z_std = mu.std(dim=0).clamp(min=0.01)

    results = []
    for i in range(count):
        # Sample direction on unit sphere
        direction = torch.randn_like(z_mean)
        direction = direction / direction.norm()
        # Scale to 2-3 standard deviations
        scale = 2.0 + torch.rand(1).item()
        z = (z_mean + direction * z_std * scale).unsqueeze(0)
        pdus = decode_to_bytes(model, z)
        results.extend(pdus)

    return results[:count]


def strategy_walk(model, seed_tensor, steps, count):
    """
    Walk through latent space starting from valid PDUs.

    Take small steps in a random direction, observe how decoded PDU changes.
    Each walk produces `steps` PDUs; repeat for multiple starting points.
    """
    mu, _ = encode_seeds(model, seed_tensor)
    n_seeds = mu.size(0)

    results = []
    walks_needed = max(1, count // steps)

    for w in range(walks_needed):
        # Pick a random starting seed
        start_z = mu[w % n_seeds].unsqueeze(0)
        # Random direction
        direction = torch.randn_like(start_z)
        direction = direction / direction.norm()
        step_size = 0.3

        for s in range(steps):
            z = start_z + direction * step_size * (s + 1)
            pdus = decode_to_bytes(model, z)
            results.extend(pdus)

    return results[:count]


def strategy_targeted(model, seed_tensor, count, dimensions=None):
    """
    Perturb specific latent dimensions while keeping others fixed.

    Discovers which latent dimensions control which PDU fields.
    """
    mu, _ = encode_seeds(model, seed_tensor)
    z_base = mu.mean(dim=0, keepdim=True)
    latent_dim = z_base.size(1)

    if dimensions is None:
        # Perturb each dimension in turn
        dimensions = list(range(min(latent_dim, count)))

    results = []
    for dim_idx in dimensions:
        for scale in [-3.0, -1.5, 1.5, 3.0]:
            z = z_base.clone()
            z[0, dim_idx % latent_dim] += scale
            pdus = decode_to_bytes(model, z)
            results.extend(pdus)

            if len(results) >= count:
                return results[:count]

    return results[:count]


def save_pdus(pdus, output_dir, prefix="vae"):
    """Save generated PDUs as binary files."""
    os.makedirs(output_dir, exist_ok=True)
    for i, pdu_bytes in enumerate(pdus):
        out_path = os.path.join(output_dir, f"{prefix}_{i:06d}.bin")
        with open(out_path, 'wb') as f:
            f.write(pdu_bytes)
    logger.info(f"Saved {len(pdus)} PDUs to {output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate DICOM PDUs using VAE latent space exploration"
    )
    parser.add_argument("--model", type=str, required=True,
                        help="Path to trained VAE checkpoint")
    parser.add_argument("--data-dir", type=str, default=None,
                        help="Directory with seed PDU data (for encoding)")
    parser.add_argument("--strategy", type=str, default="interpolate",
                        choices=["interpolate", "boundary", "walk", "targeted"])
    parser.add_argument("--degree", type=float, default=0.5,
                        help="Malformation degree for interpolation (0.0-1.0)")
    parser.add_argument("--count", type=int, default=100,
                        help="Number of PDUs to generate")
    parser.add_argument("--steps", type=int, default=20,
                        help="Steps per walk (walk strategy)")
    parser.add_argument("--output-dir", type=str, default="fuzzer/data/pcap_output/vae_generated",
                        help="Output directory")
    parser.add_argument("--to-pcap", action="store_true",
                        help="Also convert to PCAP files")

    args = parser.parse_args()

    # Load model
    model, config = load_vae(args.model)
    max_length = config["max_length"]
    logger.info(f"VAE loaded: latent_dim={config['latent_dim']}, max_length={max_length}")

    # Load seed data
    data_dir = args.data_dir
    if data_dir is None:
        # Guess from model path: fuzzer/data/models/assoc_rq_vae.pt -> fuzzer/data/training_data/pdus/assoc_rq
        model_name = os.path.basename(args.model).replace('_vae.pt', '')
        data_dir = os.path.join("fuzzer/data/training_data/pdus", model_name)
        if not os.path.exists(data_dir):
            logger.error(
                f"Cannot find seed data. Provide --data-dir or ensure {data_dir} exists."
            )
            sys.exit(1)

    seed_tensor = load_seed_pdus(data_dir, max_length)
    if seed_tensor is None:
        logger.error(f"No seed PDUs in {data_dir}")
        sys.exit(1)
    logger.info(f"Loaded {seed_tensor.size(0)} seed PDUs from {data_dir}")

    print("\n" + "=" * 70)
    print("VAE LATENT SPACE GENERATION")
    print("=" * 70)
    print(f"Strategy: {args.strategy}")
    if args.strategy == "interpolate":
        print(f"Degree: {args.degree}")
    print(f"Count: {args.count}")
    print(f"Output: {args.output_dir}")
    print("=" * 70 + "\n")

    # Generate
    if args.strategy == "interpolate":
        pdus = strategy_interpolate(model, seed_tensor, args.degree, args.count)
    elif args.strategy == "boundary":
        pdus = strategy_boundary(model, seed_tensor, args.count)
    elif args.strategy == "walk":
        pdus = strategy_walk(model, seed_tensor, args.steps, args.count)
    elif args.strategy == "targeted":
        pdus = strategy_targeted(model, seed_tensor, args.count)

    # Save
    save_pdus(pdus, args.output_dir, prefix=f"vae_{args.strategy}")

    # Optionally convert to PCAP
    if args.to_pcap:
        try:
            from fuzzer.models.byte_model.to_pcap import pdus_to_pcap
            pcap_dir = os.path.join(args.output_dir, "pcap")
            pdus_to_pcap(pdus, pcap_dir)
        except ImportError as e:
            logger.error(f"Cannot import to_pcap: {e}")

    print(f"\nDone: {len(pdus)} PDUs generated")
    print(f"Output: {args.output_dir}\n")


if __name__ == "__main__":
    main()
