"""
Ed25519 key pair generator.

Run this script ONCE to generate your cryptographic keys:
    python generate_keys.py

The private key is saved to keys/private_key.pem (gitignored, never commit).
The public key is saved to keys/public_key.pem (safe to commit).

WARNING: Running this again overwrites existing keys. Any credentials
signed with the old private key will fail verification after regeneration.
"""

import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_ed25519_keypair() -> None:
    """
    Generate an Ed25519 key pair and save both keys to the keys/ directory.

    The private key is stored in PKCS8 PEM format without encryption.
    The public key is stored in SubjectPublicKeyInfo PEM format.
    """

    # Generate the private key using the OS cryptographically secure RNG
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Derive the public key (always computed from the private key, never separately)
    public_key = private_key.public_key()

    # Serialize private key to PEM (PKCS8 container, no password protection)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM (SubjectPublicKeyInfo container)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Ensure keys/ directory exists
    os.makedirs('keys', exist_ok=True)

    private_key_path = 'keys/private_key.pem'
    public_key_path = 'keys/public_key.pem'

    with open(private_key_path, 'wb') as f:
        f.write(private_pem)

    with open(public_key_path, 'wb') as f:
        f.write(public_pem)

    print("Keys generated successfully!")
    print(f"  Private key: {private_key_path}  (KEEP SECRET - never commit)")
    print(f"  Public key:  {public_key_path}  (safe to commit)")
    print()
    print("IMPORTANT: Run this script only ONCE.")
    print("Regenerating keys will invalidate all previously issued credentials.")


if __name__ == '__main__':
    generate_ed25519_keypair()
