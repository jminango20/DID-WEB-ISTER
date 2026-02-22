"""
DID Document utilities.

Handles creating, saving, and fetching W3C DID Documents for the did:web method.

The DID Document is a JSON file that describes an identity and its public keys.
For did:web, the document is hosted at /.well-known/did.json on the issuer's domain.

Note on publicKeyMultibase encoding: The W3C Ed25519VerificationKey2020 spec prefers
base58btc encoding with a 'z' multibase prefix. This implementation uses plain base64
for consistency with the JavaScript verification code (crypto-verify.js) in this project.
"""

import json
import os
import base64
from typing import Dict, Any

import requests
from cryptography.hazmat.primitives import serialization


def create_did_document(domain: str, public_key_path: str) -> Dict[str, Any]:
    """
    Create a W3C DID Document for a did:web identity.

    Args:
        domain: The domain name, e.g. 'credenciales-emisor-ISTER.replit.app'
        public_key_path: Path to the Ed25519 public key PEM file.

    Returns:
        A dictionary representing the W3C DID Document.

    Raises:
        FileNotFoundError: If the public key file does not exist.
                           Run generate_keys.py first.
    """

    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Extract raw 32-byte Ed25519 public key (no PEM headers or wrappers)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Encode as base64 for the DID Document
    public_key_multibase = base64.b64encode(public_key_bytes).decode('utf-8')

    did = f"did:web:{domain}"

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": public_key_multibase
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"]
    }


def save_did_document(did_document: Dict[str, Any]) -> str:
    """
    Save a DID Document to static/.well-known/did.json.

    Flask serves files in static/ automatically, but we use a custom route
    (routes/did_routes.py) to serve this file at /.well-known/did.json
    instead of the default /static/.well-known/did.json.

    Args:
        did_document: The DID Document dictionary to save.

    Returns:
        The file path where the document was saved.
    """

    output_dir = os.path.join('static', '.well-known')
    output_path = os.path.join(output_dir, 'did.json')

    os.makedirs(output_dir, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(did_document, f, indent=2)

    return output_path


def fetch_did_document(did: str) -> Dict[str, Any]:
    """
    Fetch a DID Document from a did:web identifier.

    Converts the DID to a URL and makes an HTTP GET request.
    Used during credential verification to retrieve the issuer's public key.

    Conversion rule:
        did:web:<domain>        -> https://<domain>/.well-known/did.json
        did:web:<domain>:<path> -> https://<domain>/<path>/did.json

    Args:
        did: A did:web identifier, e.g. 'did:web:example.com'

    Returns:
        The parsed DID Document as a dictionary.

    Raises:
        ValueError: If the DID is not a valid did:web identifier.
        requests.HTTPError: If the HTTP request fails.
    """

    if not did.startswith('did:web:'):
        raise ValueError(f"Not a did:web identifier: {did}")

    remainder = did[len('did:web:'):]
    parts = remainder.split(':')
    domain = parts[0]

    if len(parts) == 1:
        url = f"https://{domain}/.well-known/did.json"
    else:
        path = '/'.join(parts[1:])
        url = f"https://{domain}/{path}/did.json"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    return response.json()
