import click
from signer.keys import (
    generate_keypair,
    save_private_key,
    save_public_key
)
from signer.sign import (
    load_private_key,
    sign_firmware,
    save_signature
)
from signer.verify import (
    load_public_key,
    verify_firmware
)
from signer.encrypt import (
    generate_aes_key,
    save_aes_key,
    load_aes_key,
    encrypt_firmware,
    save_encrypted_firmware,
    decrypt_firmware
)


# This is the main group of commands
@click.group()
def cli():
    """
    Firmware Signer Tool
    Qualcomm Security Tools — Learning Project
    """
    pass


@cli.command()
@click.option("--private-key", default="private.pem", help="Path to save private key")
@click.option("--public-key", default="public.pem", help="Path to save public key")
def generate_keys(private_key, public_key):
    """Generate a new ECDSA keypair"""
    click.echo("Generating ECDSA keypair...")
    private, public = generate_keypair()
    save_private_key(private, private_key)
    save_public_key(public, public_key)
    click.echo("✅ Keypair generated successfully!")


@cli.command()
@click.argument("firmware")
@click.option("--private-key", default="private.pem", help="Path to private key")
@click.option("--signature", default="firmware.sig", help="Path to save signature")
def sign(firmware, private_key, signature):
    """Sign a firmware file"""
    click.echo(f"Signing {firmware}...")
    private = load_private_key(private_key)
    sig = sign_firmware(firmware, private)
    save_signature(sig, signature)
    click.echo("✅ Firmware signed successfully!")


@cli.command()
@click.argument("firmware")
@click.option("--public-key", default="public.pem", help="Path to public key")
@click.option("--signature", default="firmware.sig", help="Path to signature file")
def verify(firmware, public_key, signature):
    """Verify a firmware file"""
    click.echo(f"Verifying {firmware}...")
    public = load_public_key(public_key)
    result = verify_firmware(firmware, signature, public)
    if result:
        click.echo("✅ Firmware is GENUINE - safe to install!")
    else:
        click.echo("❌ Firmware is TAMPERED - rejected!")


@cli.command()
@click.argument("firmware")
@click.option("--aes-key", default="aes.key", help="Path to save AES key")
@click.option("--output", default="firmware.enc", help="Path to save encrypted firmware")
def encrypt(firmware, aes_key, output):
    """Encrypt a firmware file"""
    click.echo(f"Encrypting {firmware}...")
    key = generate_aes_key()
    save_aes_key(key, aes_key)
    ciphertext, nonce = encrypt_firmware(firmware, key)
    save_encrypted_firmware(ciphertext, nonce, output)
    click.echo("✅ Firmware encrypted successfully!")


@cli.command()
@click.argument("encrypted_firmware")
@click.option("--aes-key", default="aes.key", help="Path to AES key")
@click.option("--output", default="firmware_decrypted.bin", help="Path to save decrypted firmware")
def decrypt(encrypted_firmware, aes_key, output):
    """Decrypt a firmware file"""
    click.echo(f"Decrypting {encrypted_firmware}...")
    key = load_aes_key(aes_key)
    firmware_data = decrypt_firmware(encrypted_firmware, key)
    with open(output, "wb") as f:
        f.write(firmware_data)
    click.echo(f"✅ Firmware decrypted and saved to {output}!")


if __name__ == "__main__":
    cli()