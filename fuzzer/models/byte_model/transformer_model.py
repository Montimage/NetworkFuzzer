#!/usr/bin/env python3
"""
Byte-level Transformer model for DICOM PDU generation.

A small causal (GPT-style) autoregressive model that predicts the next
byte given the preceding bytes. Designed for CPU training (~600K parameters).

Uses TransformerEncoder with causal mask (standard GPT approach — no
cross-attention overhead from TransformerDecoder).

Architecture:
    - Vocabulary: 259 tokens (256 byte values + BOS + EOS + PAD)
    - Embedding: 128 dimensions
    - Transformer: 2 layers, 4 heads, FFN dim 512
    - Max sequence: 512 tokens
    - Total params: ~600K
"""

import math

import torch
import torch.nn as nn

from .pdu_tokenizer import VOCAB_SIZE, PAD_TOKEN


class ByteTransformer(nn.Module):
    """
    Causal Transformer for next-byte prediction on DICOM PDU sequences.

    Uses nn.TransformerEncoder with a causal attention mask — this is the
    standard GPT approach and avoids the wasted cross-attention of
    TransformerDecoder.
    """

    def __init__(
        self,
        vocab_size=VOCAB_SIZE,
        d_model=128,
        n_heads=4,
        n_layers=2,
        d_ff=512,
        max_seq_len=512,
        dropout=0.1,
        pad_token=PAD_TOKEN,
    ):
        super().__init__()

        self.d_model = d_model
        self.max_seq_len = max_seq_len
        self.pad_token = pad_token

        self.token_embedding = nn.Embedding(vocab_size, d_model, padding_idx=pad_token)
        self.position_embedding = nn.Embedding(max_seq_len, d_model)
        self.dropout = nn.Dropout(dropout)

        # Use TransformerEncoder with causal mask (GPT-style)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=n_heads,
            dim_feedforward=d_ff,
            dropout=dropout,
            batch_first=True,
            norm_first=True,
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)

        self.ln_f = nn.LayerNorm(d_model)
        self.output_proj = nn.Linear(d_model, vocab_size)

        self._init_weights()

    def _init_weights(self):
        for p in self.parameters():
            if p.dim() > 1:
                nn.init.xavier_uniform_(p)

    def _make_causal_mask(self, seq_len, device):
        """Upper-triangular causal mask (True = blocked)."""
        return torch.triu(
            torch.ones(seq_len, seq_len, device=device, dtype=torch.bool),
            diagonal=1,
        )

    def forward(self, input_ids, targets=None):
        """
        Args:
            input_ids: (batch, seq_len) token IDs
            targets: (batch, seq_len) target IDs for loss computation

        Returns:
            logits: (batch, seq_len, vocab_size)
            loss: scalar if targets provided, else None
        """
        batch_size, seq_len = input_ids.shape
        device = input_ids.device

        positions = torch.arange(seq_len, device=device).unsqueeze(0)
        x = self.token_embedding(input_ids) + self.position_embedding(positions)
        x = self.dropout(x)

        causal_mask = self._make_causal_mask(seq_len, device)
        pad_mask = (input_ids == self.pad_token)

        x = self.transformer(x, mask=causal_mask, src_key_padding_mask=pad_mask)
        x = self.ln_f(x)
        logits = self.output_proj(x)

        loss = None
        if targets is not None:
            loss_fn = nn.CrossEntropyLoss(ignore_index=self.pad_token)
            loss = loss_fn(logits.view(-1, logits.size(-1)), targets.view(-1))

        return logits, loss

    def count_parameters(self):
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def build_model(
    d_model=128, n_heads=4, n_layers=2, d_ff=512,
    max_seq_len=512, dropout=0.1,
):
    """Build a ByteTransformer with the given hyperparameters."""
    return ByteTransformer(
        d_model=d_model,
        n_heads=n_heads,
        n_layers=n_layers,
        d_ff=d_ff,
        max_seq_len=max_seq_len,
        dropout=dropout,
    )
