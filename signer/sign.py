from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization


def load_private_key(filepath):
    """
    Load a private key from a .pem file
    """
    with open(filepath, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return private_key


def sign_firmware(firmware_path, private_key):
    """
    Sign a firmware file using the private key.
    Returns the signature as bytes.
    """
    # Read the firmware file as raw bytes
    with open(firmware_path, "rb") as f:
        firmware_data = f.read()

    # Sign the firmware data
    signature = private_key.sign(
        firmware_data,
        ec.ECDSA(hashes.SHA256())
    )

    return signature


def save_signature(signature, filepath):
    """
    Save the signature to a file
    """
    with open(filepath, "wb") as f:
        f.write(signature)

    print(f"Signature saved to {filepath}")