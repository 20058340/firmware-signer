import os
import pytest
from signer.keys import generate_keypair, save_private_key
from signer.sign import load_private_key, sign_firmware, save_signature


@pytest.fixture
def keypair_files(tmp_path):
    """
    Generate a keypair and save to temp files.
    This runs before each test automatically.
    """
    private_key, public_key = generate_keypair()
    private_path = str(tmp_path / "private.pem")
    save_private_key(private_key, private_path)
    return private_path, public_key


def test_load_private_key(keypair_files):
    """Test that we can load a private key from file"""
    private_path, _ = keypair_files
    private_key = load_private_key(private_path)
    assert private_key is not None


def test_sign_firmware(keypair_files, tmp_path):
    """Test that signing produces a signature"""
    private_path, _ = keypair_files
    private_key = load_private_key(private_path)

    # Create a fake firmware file
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"fake firmware data for testing")

    signature = sign_firmware(firmware_path, private_key)

    # Signature should exist and have content
    assert signature is not None
    assert len(signature) > 0


def test_save_signature(keypair_files, tmp_path):
    """Test that signature saves to file"""
    private_path, _ = keypair_files
    private_key = load_private_key(private_path)

    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"fake firmware data for testing")

    signature = sign_firmware(firmware_path, private_key)
    sig_path = str(tmp_path / "firmware.sig")
    save_signature(signature, sig_path)

    # Check signature file exists
    assert os.path.exists(sig_path)
    assert os.path.getsize(sig_path) > 0