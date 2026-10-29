"""Tests for offline Ed25519 lockfile signing. Skips if cryptography is absent."""

# Copyright (c) 2026 Sawan Bhan. All rights reserved.
# Licensed under the MIT License.

from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from instruction_guard.signing import keygen, sign_file, verify_file


def _setup(tmp_path: Path):
    lock = tmp_path / "instruction-guard.lock.json"
    lock.write_text('{"files": {"AGENTS.md": {"sha256": "abc", "bytes": 3}}}', encoding="utf-8")
    priv = tmp_path / "ig.key"
    pub = tmp_path / "instruction-guard.lock.json.pub"
    sig = tmp_path / "instruction-guard.lock.json.sig"
    keygen(priv, pub)
    sign_file(lock, priv, sig)
    return lock, pub, sig


def test_valid_signature_verifies(tmp_path: Path):
    lock, pub, sig = _setup(tmp_path)
    assert verify_file(lock, pub, sig) is True


def test_tampered_lockfile_fails(tmp_path: Path):
    lock, pub, sig = _setup(tmp_path)
    lock.write_text('{"files": {"AGENTS.md": {"sha256": "EVIL", "bytes": 4}}}', encoding="utf-8")
    assert verify_file(lock, pub, sig) is False


def test_wrong_key_fails(tmp_path: Path):
    lock, pub, sig = _setup(tmp_path)
    # Generate a different keypair; its public key must not validate the sig.
    other_priv = tmp_path / "other.key"
    other_pub = tmp_path / "other.pub"
    keygen(other_priv, other_pub)
    assert verify_file(lock, other_pub, sig) is False
