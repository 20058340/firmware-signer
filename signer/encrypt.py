import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key():
    """
    Generate a random 256-bit AES key.
    Returns key as bytes.
    """
    key = AESGCM.generate_key(bit_length=256)
    return key


def save_aes_key(key, filepath):
    """
    Save AES key to a file.
    """
    with open(filepath, "wb") as f:
        f.write(key)
    print(f"AES key saved to {filepath}")


def load_aes_key(filepath):
    """
    Load AES key from a file.
    """
    with open(filepath, "rb") as f:
        key = f.read()
    return key


def encrypt_firmware(firmware_path, key):
    """
    Encrypt a firmware file using AES-GCM.
    Returns (ciphertext, nonce)
    """
    # Read the firmware
    with open(firmware_path, "rb") as f:
        firmware_data = f.read()

    # Generate a random nonce (number used once)
    nonce = os.urandom(12)

    # Encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, firmware_data, None)

    return ciphertext, nonce


def save_encrypted_firmware(ciphertext, nonce, filepath):
    """
    Save encrypted firmware to a file.
    We store nonce + ciphertext together.
    """
    with open(filepath, "wb") as f:
        # Save nonce first (always 12 bytes)
        # Then save the ciphertext
        f.write(nonce + ciphertext)

    print(f"Encrypted firmware saved to {filepath}")


def decrypt_firmware(encrypted_path, key):
    """
    Decrypt an encrypted firmware file.
    Returns original firmware as bytes.
    """
    with open(encrypted_path, "rb") as f:
        data = f.read()

    # First 12 bytes = nonce
    # Rest = ciphertext
    nonce = data[:12]
    ciphertext = data[12:]

    # Decrypt
    aesgcm = AESGCM(key)
    firmware_data = aesgcm.decrypt(nonce, ciphertext, None)

    return firmware_data