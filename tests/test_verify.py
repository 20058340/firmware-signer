import pytest
from signer.keys import generate_keypair, save_private_key, save_public_key
from signer.sign import sign_firmware, save_signature
from signer.verify import load_public_key, verify_firmware


@pytest.fixture
def signed_firmware(tmp_path):
    """
    Full setup — generate keys, sign firmware.
    Ready for verification tests.
    """
    # Generate keypair
    private_key, public_key = generate_keypair()

    # Save keys
    private_path = str(tmp_path / "private.pem")
    public_path = str(tmp_path / "public.pem")
    save_private_key(private_key, private_path)
    save_public_key(public_key, public_path)

    # Create fake firmware
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"This is genuine Qualcomm firmware v1.0")

    # Sign it
    signature = sign_firmware(firmware_path, private_key)
    sig_path = str(tmp_path / "firmware.sig")
    save_signature(signature, sig_path)

    return firmware_path, sig_path, public_path


def test_load_public_key(signed_firmware, tmp_path):
    """Test we can load a public key from file"""
    _, _, public_path = signed_firmware
    public_key = load_public_key(public_path)
    assert public_key is not None


def test_valid_firmware_passes(signed_firmware):
    """
    Genuine firmware should pass verification
    """
    firmware_path, sig_path, public_path = signed_firmware
    public_key = load_public_key(public_path)

    result = verify_firmware(firmware_path, sig_path, public_key)

    assert result == True


def test_tampered_firmware_fails(signed_firmware, tmp_path):
    """
    Tampered firmware should FAIL verification
    This is the most important security test!
    """
    firmware_path, sig_path, public_path = signed_firmware
    public_key = load_public_key(public_path)

    # Tamper with the firmware - change just 1 byte!
    with open(firmware_path, "wb") as f:
        f.write(b"This is HACKED Qualcomm firmware v1.0")

    result = verify_firmware(firmware_path, sig_path, public_key)

    # Must be rejected
    assert result == False