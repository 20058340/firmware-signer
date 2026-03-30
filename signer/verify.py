from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def load_public_key(filepath):
    """
    Load a public key from a .pem file
    """
    with open(filepath, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return public_key


def verify_firmware(firmware_path, signature_path, public_key):
    """
    Verify a firmware file against its signature.
    Returns True if valid, False if tampered.
    """
    # Read the firmware
    with open(firmware_path, "rb") as f:
        firmware_data = f.read()

    # Read the signature
    with open(signature_path, "rb") as f:
        signature = f.read()

    # Verify
    try:
        public_key.verify(
            signature,
            firmware_data,
            ec.ECDSA(hashes.SHA256())
        )
        print(" Signature is VALID - firmware is genuine")
        return True

    except InvalidSignature:
        print(" Signature is INVALID - firmware was tampered!")
        return False