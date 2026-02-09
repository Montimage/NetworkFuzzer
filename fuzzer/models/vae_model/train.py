#!/usr/bin/env python3
"""
Training loop for the Convolutional VAE on DICOM PDU byte sequences.

Uses beta-annealing to prevent posterior collapse: slowly increases KL
weight from 0 to target beta over the first half of training.

Usage:
    python -m fuzzer.models.vae_model.train --data-dir fuzzer/data/training_data/pdus/assoc_rq --epochs 100 --model-out fuzzer/data/models/assoc_rq_vae.pt
    python -m fuzzer.models.vae_model.train --data-dir fuzzer/data/training_data/pdus/pdata --epochs 50 --max-length 512
"""

import os
import sys
import argparse
import logging
import time
import json
import glob

import numpy as np
import torch
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from fuzzer.models.vae_model.vae import ConvVAE, vae_loss

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("vae_training.log"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)

PAD_VALUE = 256  # Padding token (outside 0-255 byte range)


class PDUByteDataset(Dataset):
    """Dataset that loads PDU bytes and pads/truncates to fixed length."""

    def __init__(self, data_dir, max_length=1024):
        self.max_length = max_length
        self.sequences = []

        bytes_path = os.path.join(data_dir, "bytes.npy")
        offsets_path = os.path.join(data_dir, "offsets.npy")

        if os.path.exists(bytes_path) and os.path.exists(offsets_path):
            all_bytes = np.load(bytes_path)
            offsets = np.load(offsets_path)
            for i in range(len(offsets) - 1):
                seq = all_bytes[offsets[i]:offsets[i + 1]].tolist()
                if seq:
                    self.sequences.append(seq)
        else:
            for f in sorted(glob.glob(os.path.join(data_dir, "*.bin"))):
                with open(f, 'rb') as fh:
                    seq = list(fh.read())
                if seq:
                    self.sequences.append(seq)

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        seq = self.sequences[idx]

        # Truncate
        if len(seq) > self.max_length:
            seq = seq[:self.max_length]

        # Pad
        actual_len = len(seq)
        padded = seq + [PAD_VALUE] * (self.max_length - actual_len)

        return torch.tensor(padded, dtype=torch.long), actual_len


def train(args):
    device = torch.device("cpu")

    # Load data
    dataset = PDUByteDataset(args.data_dir, max_length=args.max_length)
    if len(dataset) == 0:
        logger.error(f"No data found in {args.data_dir}")
        return

    n_val = max(1, int(len(dataset) * 0.1))
    n_train = len(dataset) - n_val
    train_set, val_set = torch.utils.data.random_split(
        dataset, [n_train, n_val],
        generator=torch.Generator().manual_seed(42),
    )

    train_loader = DataLoader(train_set, batch_size=args.batch_size, shuffle=True, drop_last=True)
    val_loader = DataLoader(val_set, batch_size=args.batch_size, shuffle=False)

    logger.info(f"Dataset: {len(dataset)} PDUs (train={n_train}, val={n_val})")

    # Build model
    model = ConvVAE(max_length=args.max_length, latent_dim=args.latent_dim).to(device)
    logger.info(f"Model parameters: {model.count_parameters():,}")

    optimizer = optim.Adam(model.parameters(), lr=args.lr)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=args.epochs, eta_min=args.lr * 0.01,
    )

    best_val_loss = float('inf')
    history = []
    os.makedirs(os.path.dirname(args.model_out) or '.', exist_ok=True)

    for epoch in range(1, args.epochs + 1):
        t0 = time.time()

        # Beta annealing: linearly increase from 0 to target over first half
        if epoch < args.epochs // 2:
            beta = args.beta * (epoch / (args.epochs // 2))
        else:
            beta = args.beta

        # Train
        model.train()
        train_total, train_recon, train_kl = 0, 0, 0
        n_batches = 0

        for batch_x, batch_lens in train_loader:
            batch_x = batch_x.to(device)
            logits, mu, log_var = model(batch_x)

            loss, recon, kl = vae_loss(logits, batch_x, mu, log_var, beta=beta)

            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            train_total += loss.item()
            train_recon += recon.item()
            train_kl += kl.item()
            n_batches += 1

        scheduler.step()

        train_total /= max(n_batches, 1)
        train_recon /= max(n_batches, 1)
        train_kl /= max(n_batches, 1)

        # Validate
        model.eval()
        val_total, val_recon, val_kl = 0, 0, 0
        vn = 0
        with torch.no_grad():
            for batch_x, batch_lens in val_loader:
                batch_x = batch_x.to(device)
                logits, mu, log_var = model(batch_x)
                loss, recon, kl = vae_loss(logits, batch_x, mu, log_var, beta=beta)
                val_total += loss.item()
                val_recon += recon.item()
                val_kl += kl.item()
                vn += 1

        val_total /= max(vn, 1)
        val_recon /= max(vn, 1)
        val_kl /= max(vn, 1)

        elapsed = time.time() - t0
        logger.info(
            f"Epoch {epoch}/{args.epochs} | "
            f"train={train_total:.4f} (recon={train_recon:.4f} kl={train_kl:.4f}) | "
            f"val={val_total:.4f} (recon={val_recon:.4f} kl={val_kl:.4f}) | "
            f"beta={beta:.4f} | {elapsed:.1f}s"
        )

        history.append({
            "epoch": epoch, "beta": beta,
            "train_loss": train_total, "train_recon": train_recon, "train_kl": train_kl,
            "val_loss": val_total, "val_recon": val_recon, "val_kl": val_kl,
        })

        if val_total < best_val_loss:
            best_val_loss = val_total
            checkpoint = {
                "model_state_dict": model.state_dict(),
                "epoch": epoch,
                "val_loss": val_total,
                "config": {
                    "max_length": args.max_length,
                    "latent_dim": args.latent_dim,
                },
            }
            torch.save(checkpoint, args.model_out)
            logger.info(f"  Saved best model (val={val_total:.4f})")

    history_path = args.model_out.replace('.pt', '_history.json')
    with open(history_path, 'w') as f:
        json.dump(history, f, indent=2)

    logger.info(f"Training complete. Best val_loss={best_val_loss:.4f}")


def main():
    parser = argparse.ArgumentParser(description="Train VAE on DICOM PDU bytes")
    parser.add_argument("--data-dir", type=str, required=True)
    parser.add_argument("--model-out", type=str, default="fuzzer/data/models/vae.pt")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--max-length", type=int, default=1024)
    parser.add_argument("--latent-dim", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--beta", type=float, default=0.1,
                        help="KL weight (target after annealing)")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("VAE TRAINING")
    print("=" * 70)
    print(f"Data: {args.data_dir}")
    print(f"Model: {args.model_out}")
    print(f"Epochs: {args.epochs}, Batch: {args.batch_size}")
    print(f"Latent dim: {args.latent_dim}, Beta: {args.beta}")
    print("=" * 70 + "\n")

    train(args)


if __name__ == "__main__":
    main()
