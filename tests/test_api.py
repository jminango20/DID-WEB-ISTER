"""
Tests for API endpoints.

Run with:
    pytest tests/test_api.py -v

These tests use Flask's test client and mock the database to avoid
making real network requests during testing.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from app import create_app


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Flask test client with testing config."""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret'
    with app.test_client() as client:
        yield client


@pytest.fixture
def admin_client(client):
    """Test client with an active admin session."""
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
    return client


# ─── Health Check ─────────────────────────────────────────────────────────────

class TestHealth:

    def test_health_returns_200(self, client):
        response = client.get('/health')
        assert response.status_code == 200

    def test_health_returns_json(self, client):
        response = client.get('/health')
        data = response.get_json()
        assert data['status'] == 'ok'
        assert 'did' in data


# ─── DID Document ─────────────────────────────────────────────────────────────

class TestDIDDocument:

    def test_did_document_returns_200(self, client):
        response = client.get('/.well-known/did.json')
        assert response.status_code == 200

    def test_did_document_has_correct_id(self, client):
        response = client.get('/.well-known/did.json')
        data = response.get_json()
        assert data['id'] == 'did:web:credenciales-emisor-ISTER.replit.app'


# ─── Issue Credential API ─────────────────────────────────────────────────────

class TestIssueCredentialAPI:

    def test_missing_fields_returns_400(self, client):
        response = client.post('/api/credentials/issue',
                               json={'student_name': 'Juan'},
                               content_type='application/json')
        assert response.status_code == 400
        assert 'error' in response.get_json()

    def test_issue_credential_success(self, client):
        mock_supabase = MagicMock()
        mock_supabase.table.return_value.insert.return_value.execute.return_value = MagicMock()

        with patch('utils.database.get_supabase_client', return_value=mock_supabase):
            response = client.post('/api/credentials/issue', json={
                'student_name': 'Juan Pérez',
                'student_email': 'juan@example.com',
                'student_id': '20240001',
                'course_name': 'Blockchain Fundamentals',
                'completion_date': '2025-02-20',
                'grade': '95'
            })

        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert 'claim_id' in data['data']
        assert 'credential' in data['data']
        assert 'claim_url' in data['data']


# ─── Get Credential API ───────────────────────────────────────────────────────

class TestGetCredentialAPI:

    def test_not_found_returns_404(self, client):
        mock_supabase = MagicMock()
        mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value \
            = MagicMock(data=[])

        with patch('utils.database.get_supabase_client', return_value=mock_supabase):
            response = client.get('/api/credentials/NONEXISTENT000001')

        assert response.status_code == 404

    def test_found_credential_returns_200(self, client):
        fake_credential = {'id': 'did:web:test/credentials/TEST', 'type': ['VerifiableCredential']}
        mock_supabase = MagicMock()
        mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value \
            = MagicMock(data=[{'credential_data': fake_credential}])

        with patch('utils.database.get_supabase_client', return_value=mock_supabase):
            response = client.get('/api/credentials/TEST0000000000001')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True


# ─── Claim Credential API ─────────────────────────────────────────────────────

class TestClaimCredentialAPI:

    def test_claim_already_claimed_returns_409(self, client):
        mock_supabase = MagicMock()
        mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value \
            = MagicMock(data=[{'claimed': True}])

        with patch('utils.database.get_supabase_client', return_value=mock_supabase):
            response = client.post('/api/credentials/CLAIMED00000001/claim')

        assert response.status_code == 409

    def test_claim_not_found_returns_404(self, client):
        mock_supabase = MagicMock()
        mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value \
            = MagicMock(data=[])

        with patch('utils.database.get_supabase_client', return_value=mock_supabase):
            response = client.post('/api/credentials/NOTFOUND000001/claim')

        assert response.status_code == 404


# ─── Recover API ──────────────────────────────────────────────────────────────

class TestRecoverAPI:

    def test_missing_email_returns_400(self, client):
        response = client.post('/api/recover', json={})
        assert response.status_code == 400

    def test_recover_returns_credentials(self, client):
        fake_cred = {'id': 'test', 'type': ['VerifiableCredential']}
        mock_supabase = MagicMock()
        mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value \
            = MagicMock(data=[{'credential_data': fake_cred}])

        with patch('utils.database.get_supabase_client', return_value=mock_supabase):
            response = client.post('/api/recover', json={'email': 'juan@example.com'})

        assert response.status_code == 200
        data = response.get_json()
        assert len(data['data']['credentials']) == 1
