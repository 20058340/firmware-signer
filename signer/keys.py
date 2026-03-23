from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_keypair():
    """
    Generate an ECDSA private/public keypair.
    Returns (private_key, public_key)
    """
    # Generate private key using P-256 curve
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Derive the public key from the private key
    public_key = private_key.public_key()

    return private_key, public_key


def save_private_key(private_key, filepath):
    """
    Save private key to a .pem file.
    No password protection for now — we'll add later.
    """
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(filepath, "wb") as f:
        f.write(pem_data)

    print(f"Private key saved to {filepath}")


def save_public_key(public_key, filepath):
    """
    Save public key to a .pem file.
    """
    pem_data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(filepath, "wb") as f:
        f.write(pem_data)

    print(f"Public key saved to {filepath}")