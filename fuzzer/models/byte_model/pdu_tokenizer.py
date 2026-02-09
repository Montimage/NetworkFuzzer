#!/usr/bin/env python3
"""
PDU byte tokenizer for Transformer model training.

Loads raw PDU byte sequences extracted by extract_pdus.py, converts them to
integer token sequences (byte values 0-255 + special tokens), and provides
PyTorch Dataset/DataLoader for training.

Usage (as module):
    from pdu_tokenizer import PDUDataset, create_dataloaders
    train_dl, val_dl = create_dataloaders("fuzzer/data/training_data/pdus/assoc_rq", max_length=1024)
"""

import os
import glob
import numpy as np

import torch
from torch.utils.data import Dataset, DataLoader

# Special tokens
BOS_TOKEN = 256  # Beginning of sequence
EOS_TOKEN = 257  # End of sequence
PAD_TOKEN = 258  # Padding
VOCAB_SIZE = 259  # 256 byte values + 3 special tokens


class PDUDataset(Dataset):
    """
    PyTorch dataset for PDU byte sequences.

    Each item is a padded/truncated token sequence:
        [BOS, byte_0, byte_1, ..., byte_n, EOS, PAD, PAD, ...]
    """

    def __init__(self, data_dir, max_length=1024, file_ext=".bin"):
        """
        Args:
            data_dir: Directory containing raw PDU binary files or numpy arrays.
            max_length: Maximum sequence length (including BOS/EOS).
            file_ext: Extension of binary PDU files.
        """
        self.max_length = max_length
        self.sequences = []

        # Try loading from numpy format first (faster)
        bytes_path = os.path.join(data_dir, "bytes.npy")
        offsets_path = os.path.join(data_dir, "offsets.npy")

        if os.path.exists(bytes_path) and os.path.exists(offsets_path):
            self._load_numpy(bytes_path, offsets_path)
        else:
            self._load_binary_files(data_dir, file_ext)

    def _load_numpy(self, bytes_path, offsets_path):
        """Load PDUs from numpy arrays (created by extract_pdus.py)."""
        all_bytes = np.load(bytes_path)
        offsets = np.load(offsets_path)

        n_pdus = len(offsets) - 1
        for i in range(n_pdus):
            start = offsets[i]
            end = offsets[i + 1]
            pdu_bytes = all_bytes[start:end].tolist()
            self.sequences.append(pdu_bytes)

    def _load_binary_files(self, data_dir, file_ext):
        """Load PDUs from individual binary files."""
        pattern = os.path.join(data_dir, f"*{file_ext}")
        files = sorted(glob.glob(pattern))

        for fpath in files:
            with open(fpath, 'rb') as f:
                pdu_bytes = list(f.read())
            if pdu_bytes:
                self.sequences.append(pdu_bytes)

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        """
        Returns:
            input_ids: tensor of shape (max_length,) — [BOS, b0, b1, ..., PAD]
            target_ids: tensor of shape (max_length,) — [b0, b1, ..., EOS, PAD]
            length: actual sequence length (including BOS/EOS)
        """
        raw_bytes = self.sequences[idx]

        # Truncate if necessary (leave room for BOS and EOS)
        max_content = self.max_length - 2
        if len(raw_bytes) > max_content:
            raw_bytes = raw_bytes[:max_content]

        # Build input: [BOS, byte_0, ..., byte_n, PAD, ...]
        input_seq = [BOS_TOKEN] + raw_bytes
        # Build target: [byte_0, ..., byte_n, EOS, PAD, ...]
        target_seq = raw_bytes + [EOS_TOKEN]

        actual_len = len(input_seq)

        # Pad to max_length
        pad_len = self.max_length - actual_len
        input_seq = input_seq + [PAD_TOKEN] * pad_len
        target_seq = target_seq + [PAD_TOKEN] * pad_len

        return (
            torch.tensor(input_seq, dtype=torch.long),
            torch.tensor(target_seq, dtype=torch.long),
            actual_len,
        )


def create_dataloaders(data_dir, max_length=1024, batch_size=32,
                       val_split=0.1, num_workers=0):
    """
    Create training and validation DataLoaders from a PDU directory.

    Args:
        data_dir: Directory containing PDU data.
        max_length: Maximum token sequence length.
        batch_size: Batch size.
        val_split: Fraction of data for validation.
        num_workers: DataLoader worker count.

    Returns:
        (train_loader, val_loader, dataset_size)
    """
    dataset = PDUDataset(data_dir, max_length=max_length)

    if len(dataset) == 0:
        raise ValueError(f"No PDU data found in {data_dir}")

    # Train/val split
    n_val = max(1, int(len(dataset) * val_split))
    n_train = len(dataset) - n_val

    train_set, val_set = torch.utils.data.random_split(
        dataset, [n_train, n_val],
        generator=torch.Generator().manual_seed(42),
    )

    train_loader = DataLoader(
        train_set, batch_size=batch_size, shuffle=True,
        num_workers=num_workers, drop_last=True,
    )
    val_loader = DataLoader(
        val_set, batch_size=batch_size, shuffle=False,
        num_workers=num_workers,
    )

    return train_loader, val_loader, len(dataset)
