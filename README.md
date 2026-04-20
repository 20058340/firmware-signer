# Firmware Signer

![CI](https://github.com/20058340/firmware-signer/actions/workflows/ci.yml/badge.svg)

A command line tool for signing, verifying and encrypting firmware files using 
ECDSA and AES-256-GCM cryptography.

---

## Background

When firmware is distributed to devices, the device needs to confirm two things
before installing it. First, that the firmware actually came from the expected
source. Second, that nobody modified it in transit.

This tool handles both. It uses ECDSA to sign and verify firmware, and AES-256-GCM
to encrypt it so the contents stay confidential.

---

## Cryptography

Signing uses ECDSA with the P-256 curve. Before signing, the firmware is hashed
with SHA-256 so the signature covers a fixed size digest rather than the raw file.

Encryption uses AES-256-GCM. GCM mode gives you both confidentiality and
authenticated encryption, meaning it will detect if the ciphertext was tampered
with after encryption.

---

## Installation

Clone the repo and set up a virtual environment:
```bash
git clone https://github.com/20058340/firmware-signer.git
cd firmware-signer
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

## Usage

Generate a keypair first. This gives you a private key for signing and a
public key for verification:
```bash
python -m signer.cli generate-keys
```

Sign a firmware file using your private key:
```bash
python -m signer.cli sign firmware.bin --private-key private.pem
```

Verify the firmware before installing. If the file was modified after signing
it will be rejected:
```bash
python -m signer.cli verify firmware.bin --public-key public.pem
```

Encrypt a firmware file:
```bash
python -m signer.cli encrypt firmware.bin
```

Decrypt it:
```bash
python -m signer.cli decrypt firmware.enc
```

---

## Running Tests
```bash
pytest tests/ -v
```

The test suite covers keypair generation, signing, verification, encryption,
tamper detection and full end to end CLI workflows. 22 tests total.

---

## Project Structure
```
firmware-signer/
├── signer/
│   ├── keys.py       # ECDSA keypair generation
│   ├── sign.py       # Firmware signing
│   ├── verify.py     # Signature verification
│   ├── encrypt.py    # AES-GCM encryption
│   └── cli.py        # Command line interface
├── tests/
│   ├── test_keys.py
│   ├── test_sign.py
│   ├── test_verify.py
│   ├── test_encrypt.py
│   └── test_integration.py
├── .github/
│   └── workflows/
│       └── ci.yml
├── requirements.txt
└── README.md
```

---

## Notes

The private key should never be shared or committed to version control.
In a real production environment it would be stored in an HSM
(Hardware Security Module) rather than a flat file.

