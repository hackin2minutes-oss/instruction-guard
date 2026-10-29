"""Offline Ed25519 signing and verification for the lockfile.

Design goals:
- Fully offline. No network, no Fulcio/Rekor, no OIDC. Works air-gapped.
- Asymmetric: the private key signs; a committed public key verifies in CI.
- Optional: this module imports `cryptography` lazily, so the core scanner
  stays dependency-free. Install with:  pip install "instruction-guard[sign]"

Files produced:
- a private key   (keep secret, e.g. a GitHub Actions secret) -- never committed
- <lockfile>.pub  (public key, hex) -- committed to the repo
- <lockfile>.sig  (detached signature over the exact lockfile bytes) -- committed

The signature is over the raw bytes of the lockfile, so it covers every pinned
hash. Any change to an instruction file changes a hash, changes the lockfile,
and invalidates the signature until a holder of the private key re-signs.
"""

# Copyright (c) 2026 Sawan Bhan. All rights reserved.
# Licensed under the MIT License.

from __future__ import annotations

from pathlib import Path


class SigningUnavailable(RuntimeError):
    """Raised when the optional 'cryptography' dependency is not installed."""


def _load_backend():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives import serialization
        return Ed25519PrivateKey, Ed25519PublicKey, serialization
    except ImportError as exc:  # pragma: no cover - exercised via message only
        raise SigningUnavailable(
            "Signing requires the 'cryptography' package. "
            'Install it with: pip install "instruction-guard[sign]"'
        ) from exc


def keygen(private_path: Path, public_path: Path) -> None:
    """Generate an Ed25519 keypair. Private key is raw hex; public key is raw hex."""
    Ed25519PrivateKey, _, serialization = _load_backend()
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    private_path.write_text(priv_raw.hex() + "\n", encoding="utf-8")
    public_path.write_text(pub_raw.hex() + "\n", encoding="utf-8")


def sign_file(target: Path, private_path: Path, sig_path: Path) -> None:
    """Sign the raw bytes of `target` with the private key; write detached sig as hex."""
    Ed25519PrivateKey, _, _ = _load_backend()
    priv_hex = private_path.read_text(encoding="utf-8").strip()
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    signature = priv.sign(target.read_bytes())
    sig_path.write_text(signature.hex() + "\n", encoding="utf-8")


def verify_file(target: Path, public_path: Path, sig_path: Path) -> bool:
    """Return True iff `sig_path` is a valid signature over `target` for `public_path`."""
    _, Ed25519PublicKey, _ = _load_backend()
    pub_hex = public_path.read_text(encoding="utf-8").strip()
    sig_hex = sig_path.read_text(encoding="utf-8").strip()
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    try:
        pub.verify(bytes.fromhex(sig_hex), target.read_bytes())
        return True
    except Exception:
        return False
