#!/usr/bin/env python3
"""
Generate fuzzing PDUs using a trained byte-level Transformer model.

Four generation strategies:
  1. temperature  — Sample from softmax(logits/T), higher T = more malformed
  2. topk-error   — Top-k sampling with random forced errors
  3. prefix       — Fix first N bytes and let model generate the rest
  4. gradient     — Gradient-guided mutation of seed PDUs

Usage:
    python -m fuzzer.models.byte_model.generate --model fuzzer/data/models/assoc_rq_transformer.pt --count 100 --strategy temperature --temp 1.5
    python -m fuzzer.models.byte_model.generate --model fuzzer/data/models/assoc_rq_transformer.pt --strategy prefix --prefix-hex 0100000000
    python -m fuzzer.models.byte_model.generate --model fuzzer/data/models/pdata_transformer.pt --strategy gradient --seed-pcap pcap/dump.pcap
"""

import os
import sys
import argparse
import logging
import struct
import random

import numpy as np
import torch
import torch.nn.functional as F

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from fuzzer.models.byte_model.transformer_model import build_model
from fuzzer.models.byte_model.pdu_tokenizer import (
    BOS_TOKEN, EOS_TOKEN, PAD_TOKEN, VOCAB_SIZE,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("byte_model_generate.log"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)


def load_model(model_path, device="cpu"):
    """Load a trained ByteTransformer from checkpoint."""
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    config = checkpoint["config"]

    model = build_model(
        d_model=config["d_model"],
        n_heads=config["n_heads"],
        n_layers=config["n_layers"],
        d_ff=config["d_ff"],
        max_seq_len=config["max_seq_len"],
        dropout=config.get("dropout", 0.1),
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model = model.to(device)
    model.eval()
    return model, config


def generate_temperature(model, count, temperature=1.5, max_length=1024, device="cpu"):
    """
    Generate PDUs by sampling from softmax(logits / temperature).

    temperature=1.0: faithful reproduction of training distribution.
    temperature>1.0: more random/diverse (more malformed).
    temperature<1.0: more conservative (closer to valid).
    """
    generated = []

    for i in range(count):
        tokens = [BOS_TOKEN]

        for step in range(max_length - 2):
            input_ids = torch.tensor([tokens], dtype=torch.long, device=device)
            with torch.no_grad():
                logits, _ = model(input_ids)

            # Get logits for the last position
            next_logits = logits[0, -1, :VOCAB_SIZE - 3]  # Exclude special tokens
            next_logits = next_logits / temperature
            probs = F.softmax(next_logits, dim=-1)
            next_token = torch.multinomial(probs, 1).item()

            if next_token == EOS_TOKEN:
                break

            tokens.append(next_token)

        # Convert to bytes (skip BOS)
        pdu_bytes = bytes(tokens[1:])
        generated.append(pdu_bytes)

        if (i + 1) % 10 == 0:
            logger.info(f"Generated {i+1}/{count} PDUs (temp={temperature})")

    return generated


def generate_topk_error(model, count, k=10, error_rate=0.05,
                        max_length=1024, device="cpu"):
    """
    Generate PDUs using top-k sampling with forced random errors.

    Normally samples from top-k most likely bytes. With probability error_rate,
    forces a completely random byte instead. Creates targeted anomalies at
    model-identified sensitive positions.
    """
    generated = []

    for i in range(count):
        tokens = [BOS_TOKEN]

        for step in range(max_length - 2):
            input_ids = torch.tensor([tokens], dtype=torch.long, device=device)
            with torch.no_grad():
                logits, _ = model(input_ids)

            next_logits = logits[0, -1, :256]  # Only byte values

            if random.random() < error_rate:
                # Force a random byte
                next_token = random.randint(0, 255)
            else:
                # Top-k sampling
                topk_vals, topk_idx = torch.topk(next_logits, min(k, 256))
                probs = F.softmax(topk_vals, dim=-1)
                sampled = torch.multinomial(probs, 1).item()
                next_token = topk_idx[sampled].item()

            tokens.append(next_token)

        pdu_bytes = bytes(tokens[1:])
        generated.append(pdu_bytes)

        if (i + 1) % 10 == 0:
            logger.info(f"Generated {i+1}/{count} PDUs (top-{k}, err={error_rate})")

    return generated


def generate_prefix_constrained(model, count, prefix_bytes, max_length=1024, device="cpu"):
    """
    Generate PDUs with a fixed prefix and model-generated suffix.

    Fixes the first N bytes (e.g., valid PDU header) and lets the model
    generate the rest. Ensures packets reach deep parser code paths.
    """
    generated = []

    for i in range(count):
        # Start with BOS + prefix bytes
        tokens = [BOS_TOKEN] + list(prefix_bytes)

        for step in range(max_length - len(tokens) - 1):
            input_ids = torch.tensor([tokens], dtype=torch.long, device=device)
            with torch.no_grad():
                logits, _ = model(input_ids)

            next_logits = logits[0, -1, :256]
            probs = F.softmax(next_logits, dim=-1)
            next_token = torch.multinomial(probs, 1).item()

            if next_token == EOS_TOKEN:
                break

            tokens.append(next_token)

        pdu_bytes = bytes(tokens[1:])
        generated.append(pdu_bytes)

        if (i + 1) % 10 == 0:
            logger.info(
                f"Generated {i+1}/{count} PDUs "
                f"(prefix={len(prefix_bytes)} bytes)"
            )

    return generated


def generate_gradient_guided(model, seed_pdus, count, top_n=10,
                             max_length=1024, device="cpu"):
    """
    Gradient-guided mutation of seed PDUs.

    For each seed PDU:
      1. Compute loss gradient w.r.t. each byte position
      2. Identify positions with highest gradient magnitude (most sensitive)
      3. Mutate those positions with alternative bytes

    Generates minimally-different variants that maximally stress the parser.
    """
    generated = []

    for i in range(count):
        seed = seed_pdus[i % len(seed_pdus)]
        seed_tokens = [BOS_TOKEN] + list(seed)

        # Pad to max_length
        padded = seed_tokens + [PAD_TOKEN] * (max_length - len(seed_tokens))
        input_ids = torch.tensor([padded[:max_length]], dtype=torch.long, device=device)

        # Create shifted target
        target_tokens = list(seed) + [EOS_TOKEN]
        target_padded = target_tokens + [PAD_TOKEN] * (max_length - len(target_tokens))
        target_ids = torch.tensor(
            [target_padded[:max_length]], dtype=torch.long, device=device
        )

        # Enable gradient computation for embeddings
        model.eval()
        input_ids_grad = input_ids.clone().detach().requires_grad_(False)

        # Use embedding hook to get gradients
        embeddings = model.token_embedding(input_ids_grad)
        positions = torch.arange(max_length, device=device).unsqueeze(0)
        pos_embed = model.position_embedding(positions)
        x = embeddings + pos_embed
        x.requires_grad_(True)
        x_with_grad = model.dropout(x)

        # Forward through transformer encoder (causal self-attention)
        causal_mask = model._make_causal_mask(max_length, device)
        pad_mask = (input_ids_grad == PAD_TOKEN)
        out = model.transformer(x_with_grad, mask=causal_mask,
                                src_key_padding_mask=pad_mask)
        out = model.ln_f(out)
        logits = model.output_proj(out)

        # Compute loss
        loss_fn = torch.nn.CrossEntropyLoss(ignore_index=PAD_TOKEN)
        loss = loss_fn(logits.view(-1, logits.size(-1)), target_ids.view(-1))
        loss.backward()

        # Get gradient magnitudes per position
        grad_mag = x.grad[0].norm(dim=-1).detach().cpu().numpy()

        # Find top-N most sensitive positions (skip BOS at index 0)
        actual_len = min(len(seed) + 1, max_length)
        if actual_len > 1:
            sensitive_positions = np.argsort(grad_mag[1:actual_len])[-top_n:]
        else:
            sensitive_positions = []

        # Mutate sensitive positions
        mutated = list(seed)
        for pos in sensitive_positions:
            if pos < len(mutated):
                # Replace with a random byte that differs from original
                original = mutated[pos]
                new_byte = random.choice([b for b in range(256) if b != original])
                mutated[pos] = new_byte

        pdu_bytes = bytes(mutated)
        generated.append(pdu_bytes)

        if (i + 1) % 10 == 0:
            logger.info(
                f"Generated {i+1}/{count} PDUs (gradient-guided, "
                f"top-{top_n} positions)"
            )

    return generated


def load_seed_pdus(seed_path, max_pdus=100):
    """Load seed PDUs from a PCAP file or directory of .bin files."""
    seed_pdus = []

    if seed_path.endswith(('.pcap', '.pcapng')):
        # Extract from PCAP using our extractor
        try:
            from fuzzer.gan.data_gen.extract_pdus import extract_pdus_from_pcap
            pdus = extract_pdus_from_pcap(seed_path)
            seed_pdus = [pdu_bytes for _, pdu_bytes, _ in pdus[:max_pdus]]
        except ImportError:
            # Fallback: read raw bytes from PCAP payloads
            from scapy.all import rdpcap, Raw
            packets = rdpcap(seed_path)
            for pkt in packets:
                if Raw in pkt:
                    seed_pdus.append(bytes(pkt[Raw].load))
                    if len(seed_pdus) >= max_pdus:
                        break
    elif os.path.isdir(seed_path):
        import glob
        for f in sorted(glob.glob(os.path.join(seed_path, "*.bin")))[:max_pdus]:
            with open(f, 'rb') as fh:
                seed_pdus.append(fh.read())
    else:
        with open(seed_path, 'rb') as f:
            seed_pdus.append(f.read())

    return seed_pdus


def save_generated(pdus, output_dir, prefix="generated"):
    """Save generated PDUs as binary files."""
    os.makedirs(output_dir, exist_ok=True)

    for i, pdu_bytes in enumerate(pdus):
        out_path = os.path.join(output_dir, f"{prefix}_{i:06d}.bin")
        with open(out_path, 'wb') as f:
            f.write(pdu_bytes)

    logger.info(f"Saved {len(pdus)} PDUs to {output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate fuzzing PDUs using trained byte-level Transformer"
    )
    parser.add_argument("--model", type=str, required=True,
                        help="Path to trained model checkpoint")
    parser.add_argument("--count", type=int, default=100,
                        help="Number of PDUs to generate")
    parser.add_argument("--strategy", type=str, default="temperature",
                        choices=["temperature", "topk-error", "prefix", "gradient"],
                        help="Generation strategy")
    parser.add_argument("--output-dir", type=str, default="fuzzer/data/pcap_output/ml_generated",
                        help="Output directory for generated PDUs")

    # Temperature strategy
    parser.add_argument("--temp", type=float, default=1.5,
                        help="Sampling temperature (default: 1.5)")

    # Top-k strategy
    parser.add_argument("--k", type=int, default=10,
                        help="Top-k for sampling (default: 10)")
    parser.add_argument("--error-rate", type=float, default=0.05,
                        help="Random error rate for topk-error (default: 0.05)")

    # Prefix strategy
    parser.add_argument("--prefix-hex", type=str, default=None,
                        help="Hex string of prefix bytes (e.g. 0100000000)")

    # Gradient strategy
    parser.add_argument("--seed-pcap", type=str, default=None,
                        help="Seed PCAP for gradient-guided generation")
    parser.add_argument("--seed-dir", type=str, default=None,
                        help="Directory of seed .bin files")
    parser.add_argument("--top-n", type=int, default=10,
                        help="Top-N positions to mutate (gradient)")

    # PCAP output
    parser.add_argument("--to-pcap", action="store_true",
                        help="Also generate PCAP files from PDUs")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("BYTE-LEVEL TRANSFORMER GENERATION")
    print("=" * 70)
    print(f"Model: {args.model}")
    print(f"Strategy: {args.strategy}")
    print(f"Count: {args.count}")
    print("=" * 70 + "\n")

    # Load model
    model, config = load_model(args.model)
    max_length = config["max_seq_len"]
    logger.info(f"Model loaded: {model.count_parameters():,} parameters")

    # Generate based on strategy
    if args.strategy == "temperature":
        pdus = generate_temperature(model, args.count, args.temp, max_length)

    elif args.strategy == "topk-error":
        pdus = generate_topk_error(model, args.count, args.k, args.error_rate, max_length)

    elif args.strategy == "prefix":
        if not args.prefix_hex:
            # Default: valid A-ASSOCIATE-RQ header (type=0x01, reserved=0x00)
            prefix = bytes([0x01, 0x00, 0x00, 0x00, 0x00])
        else:
            prefix = bytes.fromhex(args.prefix_hex)
        pdus = generate_prefix_constrained(model, args.count, prefix, max_length)

    elif args.strategy == "gradient":
        seed_source = args.seed_pcap or args.seed_dir
        if not seed_source:
            logger.error("Gradient strategy requires --seed-pcap or --seed-dir")
            sys.exit(1)
        seed_pdus = load_seed_pdus(seed_source)
        if not seed_pdus:
            logger.error(f"No seed PDUs found in {seed_source}")
            sys.exit(1)
        logger.info(f"Loaded {len(seed_pdus)} seed PDUs")
        pdus = generate_gradient_guided(model, seed_pdus, args.count, args.top_n, max_length)

    # Save generated PDUs
    save_generated(pdus, args.output_dir, prefix=f"gen_{args.strategy}")

    # Optionally convert to PCAP
    if args.to_pcap:
        try:
            from fuzzer.models.byte_model.to_pcap import pdus_to_pcap
            pcap_dir = os.path.join(args.output_dir, "pcap")
            pdus_to_pcap(pdus, pcap_dir)
        except ImportError as e:
            logger.error(f"Cannot import to_pcap module: {e}")

    print(f"\nDone: {len(pdus)} PDUs generated")
    print(f"Output: {args.output_dir}\n")


if __name__ == "__main__":
    main()
