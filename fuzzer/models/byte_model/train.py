#!/usr/bin/env python3
"""
Training loop for the byte-level Transformer model on DICOM PDU sequences.

Usage:
    python -m fuzzer.models.byte_model.train --data-dir fuzzer/data/training_data/pdus/assoc_rq --epochs 50 --model-out fuzzer/data/models/assoc_rq_transformer.pt
    python -m fuzzer.models.byte_model.train --data-dir fuzzer/data/training_data/pdus/pdata --epochs 30 --max-length 512
"""

import os
import sys
import argparse
import logging
import math
import time
import json

import torch
import torch.optim as optim

# Allow running as script or module
if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from fuzzer.models.byte_model.pdu_tokenizer import create_dataloaders
from fuzzer.models.byte_model.transformer_model import build_model

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("byte_model_training.log"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)


def train_one_epoch(model, dataloader, optimizer, scheduler, device, grad_accum=1):
    """Train for one epoch. Returns average loss."""
    model.train()
    total_loss = 0.0
    n_batches = 0

    optimizer.zero_grad()

    for batch_idx, (input_ids, target_ids, lengths) in enumerate(dataloader):
        input_ids = input_ids.to(device)
        target_ids = target_ids.to(device)

        logits, loss = model(input_ids, target_ids)
        loss = loss / grad_accum
        loss.backward()

        if (batch_idx + 1) % grad_accum == 0:
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            if scheduler is not None:
                scheduler.step()
            optimizer.zero_grad()

        total_loss += loss.item() * grad_accum
        n_batches += 1

    return total_loss / max(n_batches, 1)


@torch.no_grad()
def validate(model, dataloader, device):
    """Compute validation loss. Returns average loss."""
    model.eval()
    total_loss = 0.0
    n_batches = 0

    for input_ids, target_ids, lengths in dataloader:
        input_ids = input_ids.to(device)
        target_ids = target_ids.to(device)

        logits, loss = model(input_ids, target_ids)
        total_loss += loss.item()
        n_batches += 1

    return total_loss / max(n_batches, 1)


def train(args):
    """Main training function."""
    device = torch.device("cpu")

    # Create dataloaders
    logger.info(f"Loading data from {args.data_dir}")
    train_loader, val_loader, dataset_size = create_dataloaders(
        args.data_dir,
        max_length=args.max_length,
        batch_size=args.batch_size,
        val_split=args.val_split,
    )
    logger.info(f"Dataset: {dataset_size} PDUs")
    logger.info(f"Train batches: {len(train_loader)}, Val batches: {len(val_loader)}")

    # Build model
    model = build_model(
        d_model=args.d_model,
        n_heads=args.n_heads,
        n_layers=args.n_layers,
        d_ff=args.d_ff,
        max_seq_len=args.max_length,
        dropout=args.dropout,
    )
    model = model.to(device)
    n_params = model.count_parameters()
    logger.info(f"Model parameters: {n_params:,}")

    # Optimizer
    optimizer = optim.AdamW(
        model.parameters(), lr=args.lr, weight_decay=args.weight_decay,
    )

    # Cosine annealing scheduler
    total_steps = len(train_loader) * args.epochs // args.grad_accum
    scheduler = optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=total_steps, eta_min=args.lr * 0.01,
    )

    # Training loop
    best_val_loss = float('inf')
    history = []

    os.makedirs(os.path.dirname(args.model_out) or '.', exist_ok=True)

    for epoch in range(1, args.epochs + 1):
        t0 = time.time()

        train_loss = train_one_epoch(
            model, train_loader, optimizer, scheduler, device,
            grad_accum=args.grad_accum,
        )
        val_loss = validate(model, val_loader, device)

        elapsed = time.time() - t0
        lr = optimizer.param_groups[0]['lr']

        logger.info(
            f"Epoch {epoch}/{args.epochs} | "
            f"train_loss={train_loss:.4f} val_loss={val_loss:.4f} | "
            f"lr={lr:.2e} | {elapsed:.1f}s"
        )

        history.append({
            "epoch": epoch,
            "train_loss": train_loss,
            "val_loss": val_loss,
            "lr": lr,
        })

        # Save best model
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            checkpoint = {
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "epoch": epoch,
                "val_loss": val_loss,
                "config": {
                    "d_model": args.d_model,
                    "n_heads": args.n_heads,
                    "n_layers": args.n_layers,
                    "d_ff": args.d_ff,
                    "max_seq_len": args.max_length,
                    "dropout": args.dropout,
                },
            }
            torch.save(checkpoint, args.model_out)
            logger.info(f"  Saved best model (val_loss={val_loss:.4f})")

    # Save training history
    history_path = args.model_out.replace('.pt', '_history.json')
    with open(history_path, 'w') as f:
        json.dump(history, f, indent=2)

    logger.info(f"Training complete. Best val_loss={best_val_loss:.4f}")
    logger.info(f"Model saved to {args.model_out}")

    return best_val_loss


def main():
    parser = argparse.ArgumentParser(
        description="Train byte-level Transformer on DICOM PDU sequences"
    )
    parser.add_argument("--data-dir", type=str, required=True,
                        help="Directory with PDU data (from extract_pdus.py)")
    parser.add_argument("--model-out", type=str, default="fuzzer/data/models/transformer.pt",
                        help="Output path for trained model")
    parser.add_argument("--epochs", type=int, default=50,
                        help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=32,
                        help="Training batch size")
    parser.add_argument("--max-length", type=int, default=1024,
                        help="Maximum sequence length")
    parser.add_argument("--lr", type=float, default=1e-4,
                        help="Learning rate")
    parser.add_argument("--weight-decay", type=float, default=0.01,
                        help="Weight decay")
    parser.add_argument("--grad-accum", type=int, default=1,
                        help="Gradient accumulation steps")
    parser.add_argument("--val-split", type=float, default=0.1,
                        help="Validation split fraction")
    parser.add_argument("--d-model", type=int, default=128,
                        help="Embedding dimension")
    parser.add_argument("--n-heads", type=int, default=4,
                        help="Number of attention heads")
    parser.add_argument("--n-layers", type=int, default=2,
                        help="Number of Transformer layers")
    parser.add_argument("--d-ff", type=int, default=512,
                        help="Feedforward dimension")
    parser.add_argument("--dropout", type=float, default=0.1,
                        help="Dropout rate")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("BYTE-LEVEL TRANSFORMER TRAINING")
    print("=" * 70)
    print(f"Data: {args.data_dir}")
    print(f"Model: {args.model_out}")
    print(f"Epochs: {args.epochs}, Batch: {args.batch_size}, LR: {args.lr}")
    print(f"Architecture: d={args.d_model}, heads={args.n_heads}, "
          f"layers={args.n_layers}, ff={args.d_ff}")
    print("=" * 70 + "\n")

    train(args)


if __name__ == "__main__":
    main()
