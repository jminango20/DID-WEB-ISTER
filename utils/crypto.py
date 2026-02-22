"""
Ed25519 cryptography utilities.

Handles loading keys from PEM files, signing data, and verifying signatures.
All credentials in this system are signed with Ed25519 using JWS (detached payload).

JWS format used: header..signature
- header: base64url-encoded JSON {"alg":"EdDSA","b64":false,"crit":["b64"]}
- payload is detached (not included in the JWS string)
- signature: base64url-encoded Ed25519 signature over the canonical credential JSON
"""

import base64
import json
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def load_private_key(path: str) -> Ed25519PrivateKey:
    """
    Load an Ed25519 private key from a PEM file.

    Args:
        path: Path to the PKCS8 PEM private key file.

    Returns:
        Ed25519PrivateKey instance.

    Raises:
        FileNotFoundError: If the key file does not exist.
                           Run generate_keys.py first.
    """
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str) -> Ed25519PublicKey:
    """
    Load an Ed25519 public key from a PEM file.

    Args:
        path: Path to the SubjectPublicKeyInfo PEM public key file.

    Returns:
        Ed25519PublicKey instance.
    """
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def sign_credential(credential_without_proof: Dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """
    Sign a credential dict and return a JWS string (detached payload format).

    The credential is canonicalized (sorted keys, no spaces) before signing
    to ensure deterministic byte representation.

    Args:
        credential_without_proof: The credential dict with NO 'proof' field.
        private_key: Ed25519PrivateKey to sign with.

    Returns:
        JWS string in format: base64url(header)..base64url(signature)
    """
    # Canonical JSON: sorted keys, no spaces — deterministic byte representation
    canonical = json.dumps(credential_without_proof, sort_keys=True, separators=(',', ':'))

    # Sign the canonical bytes
    signature_bytes = private_key.sign(canonical.encode('utf-8'))

    # JWS header for EdDSA with detached payload
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"]}
    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    signature_b64 = _b64url_encode(signature_bytes)

    # Detached JWS: header..signature (payload position is empty)
    return f"{header_b64}..{signature_b64}"


def verify_credential_signature(credential: Dict[str, Any], public_key_multibase: str) -> bool:
    """
    Verify the Ed25519 signature on a W3C Verifiable Credential.

    Extracts the JWS from credential['proof']['jws'], removes the proof field,
    canonicalizes the remaining credential, and verifies the signature against
    the provided public key.

    Args:
        credential: Full credential dict including 'proof'.
        public_key_multibase: Base64-encoded public key from the DID Document.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        proof = credential.get('proof', {})
        jws = proof.get('jws', '')

        if not jws:
            return False

        # Reconstruct the credential without the proof (what was originally signed)
        credential_copy = {k: v for k, v in credential.items() if k != 'proof'}
        canonical = json.dumps(credential_copy, sort_keys=True, separators=(',', ':'))

        # Parse the JWS: header..signature
        parts = jws.split('.')
        if len(parts) != 3:
            return False

        signature_bytes = _b64url_decode(parts[2])

        # Decode the public key from base64 (as stored in the DID Document)
        padding = (4 - len(public_key_multibase) % 4) % 4
        public_key_bytes = base64.b64decode(public_key_multibase + '=' * padding)

        # Load the raw public key bytes into a cryptography key object
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        # Verify — raises InvalidSignature if verification fails
        public_key.verify(signature_bytes, canonical.encode('utf-8'))
        return True

    except (InvalidSignature, Exception):
        return False


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string (with or without padding)."""
    padding = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + '=' * padding)
