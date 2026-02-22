"""
Tests for DID Document generation.

Run with:
    pytest tests/test_did.py -v
"""

import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from utils.did import create_did_document, save_did_document


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def temp_key_dir(tmp_path):
    """
    Create a temporary Ed25519 key pair for testing.

    Uses pytest's tmp_path to ensure tests are isolated
    and never touch the real keys/ directory.
    """

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_key_path = tmp_path / 'public_key.pem'
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_path.write_bytes(public_pem)

    return {
        'public_key': public_key,
        'public_key_path': str(public_key_path),
        'tmp_path': tmp_path
    }


@pytest.fixture
def sample_did_document(temp_key_dir):
    """Create a DID Document using the temp key."""
    return create_did_document(
        'credenciales-emisor-ISTER.replit.app',
        temp_key_dir['public_key_path']
    )


# ─── Structure Tests ─────────────────────────────────────────────────────────

class TestDIDDocumentStructure:

    def test_has_context(self, sample_did_document):
        assert '@context' in sample_did_document
        assert 'https://www.w3.org/ns/did/v1' in sample_did_document['@context']

    def test_has_id(self, sample_did_document):
        assert 'id' in sample_did_document

    def test_id_format(self, sample_did_document):
        assert sample_did_document['id'] == 'did:web:credenciales-emisor-ISTER.replit.app'

    def test_has_verification_method(self, sample_did_document):
        assert 'verificationMethod' in sample_did_document
        assert isinstance(sample_did_document['verificationMethod'], list)
        assert len(sample_did_document['verificationMethod']) > 0

    def test_has_authentication(self, sample_did_document):
        assert 'authentication' in sample_did_document
        assert len(sample_did_document['authentication']) > 0

    def test_has_assertion_method(self, sample_did_document):
        assert 'assertionMethod' in sample_did_document
        assert len(sample_did_document['assertionMethod']) > 0


# ─── Verification Method Tests ────────────────────────────────────────────────

class TestVerificationMethod:

    def test_has_required_fields(self, sample_did_document):
        vm = sample_did_document['verificationMethod'][0]
        for field in ('id', 'type', 'controller', 'publicKeyMultibase'):
            assert field in vm

    def test_type_is_ed25519(self, sample_did_document):
        vm = sample_did_document['verificationMethod'][0]
        assert vm['type'] == 'Ed25519VerificationKey2020'

    def test_id_format(self, sample_did_document):
        vm = sample_did_document['verificationMethod'][0]
        assert vm['id'] == 'did:web:credenciales-emisor-ISTER.replit.app#key-1'

    def test_controller_is_did(self, sample_did_document):
        vm = sample_did_document['verificationMethod'][0]
        assert vm['controller'] == sample_did_document['id']

    def test_authentication_references_key(self, sample_did_document):
        key_id = sample_did_document['verificationMethod'][0]['id']
        assert key_id in sample_did_document['authentication']

    def test_assertion_method_references_key(self, sample_did_document):
        key_id = sample_did_document['verificationMethod'][0]['id']
        assert key_id in sample_did_document['assertionMethod']


# ─── Public Key Encoding Tests ────────────────────────────────────────────────

class TestPublicKeyEncoding:

    def test_public_key_multibase_is_string(self, sample_did_document):
        vm = sample_did_document['verificationMethod'][0]
        assert isinstance(vm['publicKeyMultibase'], str)
        assert len(vm['publicKeyMultibase']) > 0

    def test_public_key_is_valid_base64(self, sample_did_document):
        vm = sample_did_document['verificationMethod'][0]
        encoded = vm['publicKeyMultibase']
        # Add padding if needed
        padding = (4 - len(encoded) % 4) % 4
        decoded = base64.b64decode(encoded + '=' * padding)
        assert len(decoded) == 32, f"Ed25519 public key must be 32 bytes, got {len(decoded)}"

    def test_public_key_matches_actual_key(self, temp_key_dir, sample_did_document):
        actual_bytes = temp_key_dir['public_key'].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        vm = sample_did_document['verificationMethod'][0]
        encoded = vm['publicKeyMultibase']
        padding = (4 - len(encoded) % 4) % 4
        decoded_bytes = base64.b64decode(encoded + '=' * padding)

        assert decoded_bytes == actual_bytes


# ─── Save Tests ───────────────────────────────────────────────────────────────

class TestSaveDidDocument:

    def test_save_creates_file(self, sample_did_document, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        saved_path = save_did_document(sample_did_document)
        assert os.path.exists(saved_path)

    def test_saved_file_is_valid_json(self, sample_did_document, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        saved_path = save_did_document(sample_did_document)
        with open(saved_path, 'r') as f:
            loaded = json.load(f)
        assert loaded == sample_did_document

    def test_save_path_is_well_known(self, sample_did_document, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        saved_path = save_did_document(sample_did_document)
        assert saved_path == os.path.join('static', '.well-known', 'did.json')
