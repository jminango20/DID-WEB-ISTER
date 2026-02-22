"""
Tests for Ed25519 cryptography utilities.

Run with:
    pytest tests/test_crypto.py -v
"""

import json
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from utils.crypto import sign_credential, verify_credential_signature, load_private_key, load_public_key


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def key_pair(tmp_path):
    """Generate a fresh Ed25519 key pair in a temp directory."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_path = tmp_path / 'private_key.pem'
    public_path = tmp_path / 'public_key.pem'

    private_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    public_path.write_bytes(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    return {
        'private_key': private_key,
        'public_key': public_key,
        'private_path': str(private_path),
        'public_path': str(public_path),
    }


@pytest.fixture
def sample_credential():
    """A minimal credential dict without a proof field."""
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": "did:web:example.com/credentials/TEST0000000000001",
        "type": ["VerifiableCredential", "EducationalCredential"],
        "issuer": "did:web:example.com",
        "issuanceDate": "2025-01-01T00:00:00+00:00",
        "credentialSubject": {
            "id": "did:email:student@example.com",
            "name": "Juan Pérez",
            "studentId": "20240001",
            "hasCredential": {
                "type": "CourseCompletionCredential",
                "courseName": "Blockchain Fundamentals",
                "completionDate": "2025-01-01",
                "grade": "95"
            }
        }
    }


# ─── Key Loading Tests ────────────────────────────────────────────────────────

class TestKeyLoading:

    def test_load_private_key(self, key_pair):
        key = load_private_key(key_pair['private_path'])
        assert key is not None

    def test_load_public_key(self, key_pair):
        key = load_public_key(key_pair['public_path'])
        assert key is not None

    def test_load_private_key_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_private_key('/nonexistent/path/private_key.pem')


# ─── Signing Tests ────────────────────────────────────────────────────────────

class TestSignCredential:

    def test_sign_returns_jws_string(self, key_pair, sample_credential):
        jws = sign_credential(sample_credential, key_pair['private_key'])
        assert isinstance(jws, str)
        assert len(jws) > 0

    def test_jws_has_detached_format(self, key_pair, sample_credential):
        """JWS must be header..signature (two dots, empty payload section)."""
        jws = sign_credential(sample_credential, key_pair['private_key'])
        parts = jws.split('.')
        assert len(parts) == 3
        assert parts[1] == '', "Payload section must be empty (detached)"

    def test_sign_is_deterministic_for_same_input(self, key_pair, sample_credential):
        """Same credential + same key must produce the same JWS."""
        jws1 = sign_credential(sample_credential, key_pair['private_key'])
        jws2 = sign_credential(sample_credential, key_pair['private_key'])
        assert jws1 == jws2

    def test_different_credentials_produce_different_signatures(self, key_pair, sample_credential):
        credential2 = dict(sample_credential)
        credential2['issuanceDate'] = '2025-06-01T00:00:00+00:00'
        jws1 = sign_credential(sample_credential, key_pair['private_key'])
        jws2 = sign_credential(credential2, key_pair['private_key'])
        assert jws1 != jws2


# ─── Verification Tests ───────────────────────────────────────────────────────

class TestVerifyCredentialSignature:

    def _public_key_multibase(self, public_key) -> str:
        import base64
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw_bytes).decode('utf-8')

    def _make_signed_credential(self, credential, private_key):
        """Return a credential dict with a proof attached."""
        import copy
        cred = copy.deepcopy(credential)
        jws = sign_credential(cred, private_key)
        cred['proof'] = {
            "type": "Ed25519Signature2020",
            "created": "2025-01-01T00:00:00+00:00",
            "verificationMethod": "did:web:example.com#key-1",
            "proofPurpose": "assertionMethod",
            "jws": jws
        }
        return cred

    def test_valid_signature_returns_true(self, key_pair, sample_credential):
        signed = self._make_signed_credential(sample_credential, key_pair['private_key'])
        pub_multibase = self._public_key_multibase(key_pair['public_key'])
        assert verify_credential_signature(signed, pub_multibase) is True

    def test_tampered_credential_returns_false(self, key_pair, sample_credential):
        signed = self._make_signed_credential(sample_credential, key_pair['private_key'])
        pub_multibase = self._public_key_multibase(key_pair['public_key'])

        # Tamper with the credential after signing
        signed['credentialSubject']['name'] = 'Hacker McHackface'

        assert verify_credential_signature(signed, pub_multibase) is False

    def test_wrong_key_returns_false(self, key_pair, sample_credential):
        signed = self._make_signed_credential(sample_credential, key_pair['private_key'])

        # Use a different key for verification
        wrong_key = ed25519.Ed25519PrivateKey.generate().public_key()
        wrong_multibase = self._public_key_multibase(wrong_key)

        assert verify_credential_signature(signed, wrong_multibase) is False

    def test_missing_proof_returns_false(self, key_pair, sample_credential):
        assert verify_credential_signature(sample_credential, 'anykey') is False

    def test_missing_jws_returns_false(self, key_pair, sample_credential):
        cred = dict(sample_credential)
        cred['proof'] = {"type": "Ed25519Signature2020"}
        pub_multibase = self._public_key_multibase(key_pair['public_key'])
        assert verify_credential_signature(cred, pub_multibase) is False
