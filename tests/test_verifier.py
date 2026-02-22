"""
Tests for verifier routes - /verify/check endpoint.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from app import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


SAMPLE_CREDENTIAL = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "did:web:example.com/credentials/ABCD1234EFGH5678",
    "type": ["VerifiableCredential", "EducationalCredential"],
    "issuer": "did:web:example.com",
    "issuanceDate": "2025-01-01T00:00:00+00:00",
    "credentialSubject": {
        "id": "did:email:student@example.com",
        "name": "Ana Torres",
        "studentId": "20240001",
        "hasCredential": {
            "type": "CourseCompletionCredential",
            "courseName": "Blockchain Fundamentals",
            "completionDate": "2025-01-01",
            "grade": "95"
        }
    },
    "proof": {
        "type": "Ed25519Signature2020",
        "created": "2025-01-01T00:00:00+00:00",
        "verificationMethod": "did:web:example.com#key-1",
        "proofPurpose": "assertionMethod",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..fakesignature"
    }
}

SAMPLE_DID_DOC = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:web:example.com",
    "verificationMethod": [{
        "id": "did:web:example.com#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:web:example.com",
        "publicKeyMultibase": "dGVzdHB1YmxpY2tleWJ5dGVzMTIzNDU2Nzg="
    }],
    "authentication": ["did:web:example.com#key-1"],
    "assertionMethod": ["did:web:example.com#key-1"]
}


class TestVerifierIndex:
    def test_index_returns_200(self, client):
        response = client.get('/verify/')
        assert response.status_code == 200

    def test_index_contains_html(self, client):
        response = client.get('/verify/')
        assert b'Verificador' in response.data


class TestVerifierCheck:
    def test_missing_body_returns_400(self, client):
        response = client.post('/verify/check', content_type='application/json')
        assert response.status_code == 400

    def test_missing_credential_returns_400(self, client):
        response = client.post(
            '/verify/check',
            data=json.dumps({}),
            content_type='application/json'
        )
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_missing_issuer_returns_400(self, client):
        cred = {**SAMPLE_CREDENTIAL}
        del cred['issuer']
        response = client.post(
            '/verify/check',
            data=json.dumps({'credential': cred}),
            content_type='application/json'
        )
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_valid_credential_returns_valid_true(self, client):
        with patch('routes.verifier_routes.fetch_did_document', return_value=SAMPLE_DID_DOC), \
             patch('routes.verifier_routes.verify_credential_signature', return_value=True):
            response = client.post(
                '/verify/check',
                data=json.dumps({'credential': SAMPLE_CREDENTIAL}),
                content_type='application/json'
            )
        assert response.status_code == 200
        data = response.get_json()
        assert data['valid'] is True
        assert 'válida' in data['message']

    def test_invalid_signature_returns_valid_false(self, client):
        with patch('routes.verifier_routes.fetch_did_document', return_value=SAMPLE_DID_DOC), \
             patch('routes.verifier_routes.verify_credential_signature', return_value=False):
            response = client.post(
                '/verify/check',
                data=json.dumps({'credential': SAMPLE_CREDENTIAL}),
                content_type='application/json'
            )
        assert response.status_code == 200
        data = response.get_json()
        assert data['valid'] is False
        assert 'inválida' in data['message']

    def test_did_resolution_failure_returns_200_with_valid_false(self, client):
        with patch('routes.verifier_routes.fetch_did_document', side_effect=Exception('DID not found')):
            response = client.post(
                '/verify/check',
                data=json.dumps({'credential': SAMPLE_CREDENTIAL}),
                content_type='application/json'
            )
        assert response.status_code == 200
        data = response.get_json()
        assert data['valid'] is False

    def test_response_includes_credential_details(self, client):
        with patch('routes.verifier_routes.fetch_did_document', return_value=SAMPLE_DID_DOC), \
             patch('routes.verifier_routes.verify_credential_signature', return_value=True):
            response = client.post(
                '/verify/check',
                data=json.dumps({'credential': SAMPLE_CREDENTIAL}),
                content_type='application/json'
            )
        data = response.get_json()
        assert data['credential']['credentialSubject']['name'] == 'Ana Torres'
        assert data['credential']['credentialSubject']['hasCredential']['courseName'] == 'Blockchain Fundamentals'
        assert data['credential']['issuer'] == 'did:web:example.com'

    def test_did_doc_without_verification_method_returns_valid_false(self, client):
        bad_did_doc = {**SAMPLE_DID_DOC, 'verificationMethod': []}
        with patch('routes.verifier_routes.fetch_did_document', return_value=bad_did_doc):
            response = client.post(
                '/verify/check',
                data=json.dumps({'credential': SAMPLE_CREDENTIAL}),
                content_type='application/json'
            )
        assert response.status_code == 200
        data = response.get_json()
        assert data['valid'] is False
