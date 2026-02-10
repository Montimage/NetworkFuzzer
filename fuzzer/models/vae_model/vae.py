#!/usr/bin/env python3
"""
Convolutional Variational Autoencoder for DICOM PDU byte sequences.

Learns a compressed latent representation of valid PDUs. The latent space
gives explicit control: interpolate between "normal" and "malformed" to
generate PCAPs at any desired malformation degree.

Architecture (CPU-friendly, ~1-2M parameters):
    Encoder: 3x 1D Conv (stride=2) -> flatten -> Linear -> mu + log_var
    Decoder: Linear -> reshape -> 3x 1D ConvTranspose -> output logits
    Latent:  64 dimensions
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class ConvVAE(nn.Module):
    """
    Convolutional VAE for byte sequences.

    Input: (batch, max_length) byte values 0-255
    Latent: (batch, latent_dim) continuous vectors
    Output: (batch, max_length, 256) logits per byte position
    """

    def __init__(self, max_length=1024, latent_dim=64, n_byte_values=256):
        super().__init__()

        self.max_length = max_length
        self.latent_dim = latent_dim
        self.n_byte_values = n_byte_values

        # Embedding: byte value -> dense vector
        self.embedding = nn.Embedding(n_byte_values + 1, 32, padding_idx=n_byte_values)
        # +1 for padding token (index 256)

        # Encoder: (batch, 32, max_length) -> compressed
        self.encoder = nn.Sequential(
            nn.Conv1d(32, 64, kernel_size=5, stride=2, padding=2),
            nn.ReLU(),
            nn.Conv1d(64, 128, kernel_size=5, stride=2, padding=2),
            nn.ReLU(),
            nn.Conv1d(128, 256, kernel_size=5, stride=2, padding=2),
            nn.ReLU(),
        )

        # Compute encoder output size: max_length -> /2 -> /2 -> /2
        self._enc_len = max_length // 8
        self._enc_flat = 256 * self._enc_len

        # Latent projections
        self.fc_mu = nn.Linear(self._enc_flat, latent_dim)
        self.fc_logvar = nn.Linear(self._enc_flat, latent_dim)

        # Decoder
        self.fc_decode = nn.Linear(latent_dim, self._enc_flat)

        self.decoder = nn.Sequential(
            nn.ConvTranspose1d(256, 128, kernel_size=5, stride=2, padding=2, output_padding=1),
            nn.ReLU(),
            nn.ConvTranspose1d(128, 64, kernel_size=5, stride=2, padding=2, output_padding=1),
            nn.ReLU(),
            nn.ConvTranspose1d(64, 32, kernel_size=5, stride=2, padding=2, output_padding=1),
            nn.ReLU(),
        )

        # Output projection: 32 channels -> 256 byte logits
        self.output_proj = nn.Conv1d(32, n_byte_values, kernel_size=1)

    def encode(self, x):
        """
        Encode byte sequence to latent distribution parameters.

        Args:
            x: (batch, max_length) byte values (0-255, or 256 for padding)

        Returns:
            mu: (batch, latent_dim)
            log_var: (batch, latent_dim)
        """
        # Embed and transpose for conv: (batch, max_length) -> (batch, 32, max_length)
        h = self.embedding(x).transpose(1, 2)
        h = self.encoder(h)
        h = h.reshape(h.size(0), -1)

        mu = self.fc_mu(h)
        log_var = self.fc_logvar(h)
        return mu, log_var

    def reparameterize(self, mu, log_var):
        """Sample z from q(z|x) using the reparameterization trick."""
        std = torch.exp(0.5 * log_var)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z):
        """
        Decode latent vector to byte logits.

        Args:
            z: (batch, latent_dim)

        Returns:
            logits: (batch, max_length, 256)
        """
        h = self.fc_decode(z)
        h = h.reshape(-1, 256, self._enc_len)
        h = self.decoder(h)

        # Trim or pad to exact max_length (ConvTranspose may differ slightly)
        if h.size(2) > self.max_length:
            h = h[:, :, :self.max_length]
        elif h.size(2) < self.max_length:
            pad = self.max_length - h.size(2)
            h = F.pad(h, (0, pad))

        logits = self.output_proj(h)  # (batch, 256, max_length)
        logits = logits.transpose(1, 2)  # (batch, max_length, 256)
        return logits

    def forward(self, x):
        """
        Full forward pass: encode -> sample -> decode.

        Returns:
            logits: (batch, max_length, 256)
            mu: (batch, latent_dim)
            log_var: (batch, latent_dim)
        """
        mu, log_var = self.encode(x)
        z = self.reparameterize(mu, log_var)
        logits = self.decode(z)
        return logits, mu, log_var

    def count_parameters(self):
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def vae_loss(logits, targets, mu, log_var, beta=1.0, pad_value=256):
    """
    VAE loss = reconstruction + beta * KL divergence.

    Args:
        logits: (batch, max_length, 256) predicted byte logits
        targets: (batch, max_length) actual byte values
        mu, log_var: latent distribution parameters
        beta: KL weight (beta-VAE)
        pad_value: padding token value to ignore
    """
    # Reconstruction: cross-entropy per byte, ignoring padding
    batch_size, seq_len, _ = logits.shape
    recon_loss = F.cross_entropy(
        logits.reshape(-1, 256),
        targets.clamp(0, 255).reshape(-1).long(),
        reduction='none',
    ).reshape(batch_size, seq_len)

    # Mask out padding positions
    mask = (targets != pad_value).float()
    recon_loss = (recon_loss * mask).sum() / mask.sum().clamp(min=1)

    # KL divergence: -0.5 * sum(1 + log_var - mu^2 - exp(log_var))
    kl_loss = -0.5 * torch.mean(1 + log_var - mu.pow(2) - log_var.exp())

    total = recon_loss + beta * kl_loss
    return total, recon_loss, kl_loss


def build_vae(max_length=1024, latent_dim=64):
    """Build a ConvVAE with the given hyperparameters."""
    return ConvVAE(max_length=max_length, latent_dim=latent_dim)
