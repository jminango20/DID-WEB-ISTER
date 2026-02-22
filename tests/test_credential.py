"""
Tests for W3C Verifiable Credential creation and validation.

Run with:
    pytest tests/test_credential.py -v
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from utils.credential import create_verifiable_credential, generate_claim_id, validate_credential_structure
from utils.crypto import verify_credential_signature

import base64
from cryptography.hazmat.primitives import serialization


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def private_key():
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture
def public_key_multibase(private_key):
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode('utf-8')


@pytest.fixture
def issuer_did():
    return 'did:web:credenciales-emisor-ISTER.replit.app'


@pytest.fixture
def signed_credential(private_key, issuer_did):
    credential, claim_id = create_verifiable_credential(
        student_name='Juan Pérez',
        student_email='juan@example.com',
        student_id='20240001',
        course_name='Blockchain Fundamentals',
        completion_date='2025-02-20',
        grade='95',
        issuer_did=issuer_did,
        private_key=private_key,
    )
    return credential, claim_id


# ─── Claim ID Tests ───────────────────────────────────────────────────────────

class TestGenerateClaimId:

    def test_claim_id_is_16_chars(self):
        assert len(generate_claim_id()) == 16

    def test_claim_id_is_uppercase(self):
        claim_id = generate_claim_id()
        assert claim_id == claim_id.upper()

    def test_claim_id_is_alphanumeric(self):
        claim_id = generate_claim_id()
        assert claim_id.isalnum()

    def test_claim_ids_are_unique(self):
        ids = {generate_claim_id() for _ in range(100)}
        assert len(ids) == 100


# ─── Credential Structure Tests ───────────────────────────────────────────────

class TestCreateVerifiableCredential:

    def test_returns_credential_and_claim_id(self, signed_credential):
        credential, claim_id = signed_credential
        assert isinstance(credential, dict)
        assert isinstance(claim_id, str)
        assert len(claim_id) == 16

    def test_credential_has_context(self, signed_credential):
        credential, _ = signed_credential
        assert '@context' in credential
        assert 'https://www.w3.org/2018/credentials/v1' in credential['@context']

    def test_credential_type(self, signed_credential):
        credential, _ = signed_credential
        assert 'VerifiableCredential' in credential['type']
        assert 'EducationalCredential' in credential['type']

    def test_credential_id_contains_claim_id(self, signed_credential, issuer_did):
        credential, claim_id = signed_credential
        assert claim_id in credential['id']
        assert issuer_did in credential['id']

    def test_credential_issuer(self, signed_credential, issuer_did):
        credential, _ = signed_credential
        assert credential['issuer'] == issuer_did

    def test_credential_subject_fields(self, signed_credential):
        credential, _ = signed_credential
        subject = credential['credentialSubject']
        assert subject['name'] == 'Juan Pérez'
        assert subject['studentId'] == '20240001'
        assert 'juan@example.com' in subject['id']

    def test_credential_has_course_info(self, signed_credential):
        credential, _ = signed_credential
        course = credential['credentialSubject']['hasCredential']
        assert course['courseName'] == 'Blockchain Fundamentals'
        assert course['completionDate'] == '2025-02-20'
        assert course['grade'] == '95'

    def test_credential_has_proof(self, signed_credential):
        credential, _ = signed_credential
        assert 'proof' in credential
        proof = credential['proof']
        assert proof['type'] == 'Ed25519Signature2020'
        assert proof['proofPurpose'] == 'assertionMethod'
        assert 'jws' in proof

    def test_signature_is_valid(self, signed_credential, public_key_multibase):
        credential, _ = signed_credential
        assert verify_credential_signature(credential, public_key_multibase) is True


# ─── Validation Tests ─────────────────────────────────────────────────────────

class TestValidateCredentialStructure:

    def test_valid_credential_passes(self, signed_credential):
        credential, _ = signed_credential
        assert validate_credential_structure(credential) is True

    def test_missing_context_fails(self, signed_credential):
        credential, _ = signed_credential
        del credential['@context']
        assert validate_credential_structure(credential) is False

    def test_missing_proof_fails(self, signed_credential):
        credential, _ = signed_credential
        del credential['proof']
        assert validate_credential_structure(credential) is False

    def test_missing_verifiable_credential_type_fails(self, signed_credential):
        credential, _ = signed_credential
        credential['type'] = ['EducationalCredential']  # missing VerifiableCredential
        assert validate_credential_structure(credential) is False
