import pytest
from signer.encrypt import (
    generate_aes_key,
    save_aes_key,
    load_aes_key,
    encrypt_firmware,
    save_encrypted_firmware,
    decrypt_firmware
)


@pytest.fixture
def firmware_file(tmp_path):
    """Create a fake firmware file for testing"""
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"This is genuine Qualcomm firmware v1.0")
    return firmware_path


def test_generate_aes_key():
    """Test AES key generation"""
    key = generate_aes_key()
    assert key is not None
    # AES-256 key should be exactly 32 bytes
    assert len(key) == 32


def test_save_and_load_aes_key(tmp_path):
    """Test saving and loading AES key"""
    key = generate_aes_key()
    key_path = str(tmp_path / "aes.key")

    save_aes_key(key, key_path)
    loaded_key = load_aes_key(key_path)

    # Loaded key must match original
    assert key == loaded_key


def test_encrypt_firmware(firmware_file):
    """Test firmware encryption produces ciphertext"""
    key = generate_aes_key()
    ciphertext, nonce = encrypt_firmware(firmware_file, key)

    assert ciphertext is not None
    assert nonce is not None
    # Nonce must always be 12 bytes
    assert len(nonce) == 12


def test_decrypt_firmware(firmware_file, tmp_path):
    """Test full encrypt → decrypt cycle"""
    key = generate_aes_key()

    # Encrypt
    ciphertext, nonce = encrypt_firmware(firmware_file, key)
    encrypted_path = str(tmp_path / "firmware.enc")
    save_encrypted_firmware(ciphertext, nonce, encrypted_path)

    # Decrypt
    decrypted_data = decrypt_firmware(encrypted_path, key)

    # Must match original
    assert decrypted_data == b"This is genuine Qualcomm firmware v1.0"


def test_wrong_key_fails(firmware_file, tmp_path):
    """
    Decrypting with wrong key must fail.
    This is the security guarantee of AES-GCM!
    """
    key = generate_aes_key()
    wrong_key = generate_aes_key()  # Different key!

    # Encrypt with correct key
    ciphertext, nonce = encrypt_firmware(firmware_file, key)
    encrypted_path = str(tmp_path / "firmware.enc")
    save_encrypted_firmware(ciphertext, nonce, encrypted_path)

    # Try to decrypt with WRONG key — must raise an error
    with pytest.raises(Exception):
        decrypt_firmware(encrypted_path, wrong_key)