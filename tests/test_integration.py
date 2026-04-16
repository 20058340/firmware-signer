import os
import pytest
from click.testing import CliRunner
from signer.cli import cli
from signer.keys import generate_keypair, save_private_key, save_public_key
from signer.sign import sign_firmware, save_signature
from signer.verify import load_public_key, verify_firmware
from signer.encrypt import (
    generate_aes_key,
    save_aes_key,
    encrypt_firmware,
    save_encrypted_firmware,
    decrypt_firmware
)


# ─────────────────────────────────────────
# WORKFLOW TESTS
# ─────────────────────────────────────────

def test_full_sign_and_verify_workflow(tmp_path):
    """
    Complete workflow test:
    generate keys → sign → verify → PASS
    """
    # Step 1 — Generate keys
    private_key, public_key = generate_keypair()
    private_path = str(tmp_path / "private.pem")
    public_path = str(tmp_path / "public.pem")
    save_private_key(private_key, private_path)
    save_public_key(public_key, public_path)

    # Step 2 — Create firmware
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"Qualcomm firmware v2.0 genuine")

    # Step 3 — Sign it
    from signer.sign import load_private_key
    private = load_private_key(private_path)
    signature = sign_firmware(firmware_path, private)
    sig_path = str(tmp_path / "firmware.sig")
    save_signature(signature, sig_path)

    # Step 4 — Verify it
    public = load_public_key(public_path)
    result = verify_firmware(firmware_path, sig_path, public)

    assert result == True


def test_full_tamper_detection_workflow(tmp_path):
    """
    Tamper detection workflow:
    sign → tamper with firmware → verify → FAIL
    This is the most critical security test!
    """
    # Generate keys
    private_key, public_key = generate_keypair()
    private_path = str(tmp_path / "private.pem")
    public_path = str(tmp_path / "public.pem")
    save_private_key(private_key, private_path)
    save_public_key(public_key, public_path)

    # Create and sign firmware
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"Qualcomm firmware v2.0 genuine")

    from signer.sign import load_private_key
    private = load_private_key(private_path)
    signature = sign_firmware(firmware_path, private)
    sig_path = str(tmp_path / "firmware.sig")
    save_signature(signature, sig_path)

    # Tamper with firmware after signing
    with open(firmware_path, "wb") as f:
        f.write(b"HACKED firmware v2.0 malicious")

    # Verify — must FAIL
    public = load_public_key(public_path)
    result = verify_firmware(firmware_path, sig_path, public)

    assert result == False


def test_full_encrypt_decrypt_workflow(tmp_path):
    """
    Complete encryption workflow:
    encrypt → decrypt → matches original
    """
    # Create firmware
    firmware_path = str(tmp_path / "firmware.bin")
    original_data = b"Qualcomm firmware v2.0 secret data"
    with open(firmware_path, "wb") as f:
        f.write(original_data)

    # Encrypt
    key = generate_aes_key()
    key_path = str(tmp_path / "aes.key")
    save_aes_key(key, key_path)
    ciphertext, nonce = encrypt_firmware(firmware_path, key)
    enc_path = str(tmp_path / "firmware.enc")
    save_encrypted_firmware(ciphertext, nonce, enc_path)

    # Decrypt
    loaded_key = generate_aes_key()  
    from signer.encrypt import load_aes_key
    loaded_key = load_aes_key(key_path)
    decrypted = decrypt_firmware(enc_path, loaded_key)

    # Must match original exactly
    assert decrypted == original_data


# ─────────────────────────────────────────
# CLI TESTS
# ─────────────────────────────────────────

@pytest.fixture
def runner():
    """Click test runner — simulates terminal commands"""
    return CliRunner()


def test_cli_generate_keys(runner, tmp_path):
    """Test generate-keys CLI command"""
    result = runner.invoke(cli, [
        "generate-keys",
        "--private-key", str(tmp_path / "private.pem"),
        "--public-key", str(tmp_path / "public.pem")
    ])

    # Check command ran successfully
    assert result.exit_code == 0
    assert "✅" in result.output

    # Check files were actually created
    assert (tmp_path / "private.pem").exists()
    assert (tmp_path / "public.pem").exists()


def test_cli_sign(runner, tmp_path):
    """Test sign CLI command"""
    # First generate keys
    runner.invoke(cli, [
        "generate-keys",
        "--private-key", str(tmp_path / "private.pem"),
        "--public-key", str(tmp_path / "public.pem")
    ])

    # Create firmware
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"test firmware data")

    # Sign it via CLI
    result = runner.invoke(cli, [
        "sign", firmware_path,
        "--private-key", str(tmp_path / "private.pem"),
        "--signature", str(tmp_path / "firmware.sig")
    ])

    assert result.exit_code == 0
    assert "✅" in result.output
    assert (tmp_path / "firmware.sig").exists()


def test_cli_verify_genuine(runner, tmp_path):
    """Test verify CLI command with genuine firmware"""
    # Generate keys
    runner.invoke(cli, [
        "generate-keys",
        "--private-key", str(tmp_path / "private.pem"),
        "--public-key", str(tmp_path / "public.pem")
    ])

    # Create and sign firmware
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"genuine firmware data")

    runner.invoke(cli, [
        "sign", firmware_path,
        "--private-key", str(tmp_path / "private.pem"),
        "--signature", str(tmp_path / "firmware.sig")
    ])

    # Verify via CLI
    result = runner.invoke(cli, [
        "verify", firmware_path,
        "--public-key", str(tmp_path / "public.pem"),
        "--signature", str(tmp_path / "firmware.sig")
    ])

    assert result.exit_code == 0
    assert "GENUINE" in result.output


def test_cli_verify_tampered(runner, tmp_path):
    """Test verify CLI command catches tampered firmware"""
    # Generate keys
    runner.invoke(cli, [
        "generate-keys",
        "--private-key", str(tmp_path / "private.pem"),
        "--public-key", str(tmp_path / "public.pem")
    ])

    # Create and sign firmware
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"genuine firmware data")

    runner.invoke(cli, [
        "sign", firmware_path,
        "--private-key", str(tmp_path / "private.pem"),
        "--signature", str(tmp_path / "firmware.sig")
    ])

    # Tamper with firmware
    with open(firmware_path, "wb") as f:
        f.write(b"HACKED firmware data")

    # Verify via CLI — should catch tampering
    result = runner.invoke(cli, [
        "verify", firmware_path,
        "--public-key", str(tmp_path / "public.pem"),
        "--signature", str(tmp_path / "firmware.sig")
    ])

    assert "TAMPERED" in result.output


def test_cli_encrypt_and_decrypt(runner, tmp_path):
    """Test encrypt and decrypt CLI commands"""
    # Create firmware
    firmware_path = str(tmp_path / "firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(b"secret firmware data")

    # Encrypt via CLI
    enc_path = str(tmp_path / "firmware.enc")
    key_path = str(tmp_path / "aes.key")
    result = runner.invoke(cli, [
        "encrypt", firmware_path,
        "--aes-key", key_path,
        "--output", enc_path
    ])

    assert result.exit_code == 0
    assert "✅" in result.output
    assert (tmp_path / "firmware.enc").exists()

    # Decrypt via CLI
    dec_path = str(tmp_path / "firmware_decrypted.bin")
    result = runner.invoke(cli, [
        "decrypt", enc_path,
        "--aes-key", key_path,
        "--output", dec_path
    ])

    assert result.exit_code == 0
    assert "✅" in result.output

    # Check decrypted matches original
    with open(dec_path, "rb") as f:
        decrypted = f.read()
    assert decrypted == b"secret firmware data"