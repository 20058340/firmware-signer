import os
import pytest
from signer.keys import generate_keypair, save_private_key, save_public_key


def test_keypair_generation():
    """Test that we can generate a keypair"""
    private_key, public_key = generate_keypair()

    # Check they are not None
    assert private_key is not None
    assert public_key is not None


def test_save_private_key(tmp_path):
    """Test private key saves to file"""
    private_key, _ = generate_keypair()
    filepath = tmp_path / "private.pem"

    save_private_key(private_key, str(filepath))

    # Check file exists and has content
    assert filepath.exists()
    assert filepath.stat().st_size > 0


def test_save_public_key(tmp_path):
    """Test public key saves to file"""
    _, public_key = generate_keypair()
    filepath = tmp_path / "public.pem"

    save_public_key(public_key, str(filepath))

    assert filepath.exists()
    assert filepath.stat().st_size > 0