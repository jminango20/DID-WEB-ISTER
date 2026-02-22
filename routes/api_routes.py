"""
Public API endpoints.

All responses are JSON. No authentication required unless noted.

Endpoints:
    POST /api/credentials/issue       - Issue credential (admin key required in future)
    GET  /api/credentials/list        - List all credentials (admin)
    GET  /api/credentials/<claim_id>  - Get credential by claim ID
    POST /api/credentials/<claim_id>/claim - Mark as claimed
    POST /api/credentials/verify      - Verify credential signature
    POST /api/recover                 - Recover credentials by email
"""

from functools import wraps
from flask import Blueprint, request, jsonify, session, url_for

from config import config

api_bp = Blueprint('api', __name__, url_prefix='/api')


# ─── Custom Exceptions ────────────────────────────────────────────────────────

class ClaimNotFoundError(Exception):
    pass


class AlreadyClaimedError(Exception):
    pass


# ─── Error Handler Decorator ──────────────────────────────────────────────────

def handle_errors(f):
    """Catch known exceptions and return appropriate JSON error responses."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ClaimNotFoundError:
            return jsonify({"error": "Credential not found"}), 404
        except AlreadyClaimedError:
            return jsonify({"error": "Credential already claimed"}), 409
        except Exception as e:
            print(f"API error: {e}")
            return jsonify({"error": "Internal server error"}), 500
    return decorated


# ─── Endpoints ────────────────────────────────────────────────────────────────

@api_bp.route('/credentials/issue', methods=['POST'])
@handle_errors
def issue_credential():
    """
    Issue a new verifiable credential.

    Body (JSON):
        student_name, student_email, student_id,
        course_name, completion_date, grade

    Returns:
        201 with claim_id, claim_url, and the full credential JSON.
    """
    data = request.get_json(silent=True) or {}

    required = ['student_name', 'student_email', 'student_id', 'course_name', 'completion_date']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    from utils.crypto import load_private_key
    from utils.credential import create_verifiable_credential
    from utils.database import get_supabase_client

    private_key = load_private_key(config.PRIVATE_KEY_PATH)

    credential, claim_id = create_verifiable_credential(
        student_name=data['student_name'],
        student_email=data['student_email'],
        student_id=data['student_id'],
        course_name=data['course_name'],
        completion_date=data['completion_date'],
        grade=data.get('grade', ''),
        issuer_did=config.DID_METHOD,
        private_key=private_key,
    )

    supabase = get_supabase_client()
    supabase.table('credentials').insert({
        'claim_id': claim_id,
        'credential_type': 'EducationalCredential',
        'student_name': data['student_name'],
        'student_email': data['student_email'],
        'student_id': data['student_id'],
        'course_name': data['course_name'],
        'completion_date': data['completion_date'],
        'grade': data.get('grade', ''),
        'credential_data': credential,
    }).execute()

    claim_url = request.host_url.rstrip('/') + f'/wallet/claim/{claim_id}'

    return jsonify({
        "success": True,
        "data": {
            "claim_id": claim_id,
            "claim_url": claim_url,
            "credential": credential,
        }
    }), 201


@api_bp.route('/credentials/list', methods=['GET'])
@handle_errors
def list_credentials():
    """List all credentials (requires admin session)."""
    if not session.get('admin_logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    from utils.database import get_supabase_client
    supabase = get_supabase_client()
    result = supabase.table('credentials') \
        .select('claim_id, student_name, student_email, course_name, issued_at, claimed') \
        .order('issued_at', desc=True) \
        .execute()

    return jsonify({"success": True, "data": result.data or []})


@api_bp.route('/credentials/<claim_id>', methods=['GET'])
@handle_errors
def get_credential(claim_id: str):
    """Get a credential by claim ID."""
    from utils.database import get_supabase_client
    supabase = get_supabase_client()
    result = supabase.table('credentials') \
        .select('*') \
        .eq('claim_id', claim_id) \
        .execute()

    if not result.data:
        raise ClaimNotFoundError()

    row = result.data[0]
    return jsonify({"success": True, "data": row['credential_data']})


@api_bp.route('/credentials/<claim_id>/claim', methods=['POST'])
@handle_errors
def claim_credential(claim_id: str):
    """Mark a credential as claimed by the student."""
    from utils.database import get_supabase_client
    from datetime import datetime, timezone

    supabase = get_supabase_client()
    result = supabase.table('credentials') \
        .select('claimed') \
        .eq('claim_id', claim_id) \
        .execute()

    if not result.data:
        raise ClaimNotFoundError()

    # Idempotent: update claimed status even if already claimed
    if not result.data[0]['claimed']:
        supabase.table('credentials').update({
            'claimed': True,
            'claimed_at': datetime.now(timezone.utc).isoformat(),
        }).eq('claim_id', claim_id).execute()

    return jsonify({"success": True, "data": {"message": "Credential claimed successfully"}})


@api_bp.route('/credentials/verify', methods=['POST'])
@handle_errors
def verify_credential():
    """
    Verify a credential's signature.

    Body (JSON): { "credential": {...} }

    Returns:
        { "valid": true/false, "message": "..." }
    """
    data = request.get_json(silent=True) or {}
    credential = data.get('credential')

    if not credential:
        return jsonify({"error": "No credential provided"}), 400

    issuer_did = credential.get('issuer')
    if not issuer_did:
        return jsonify({"error": "Invalid credential: missing issuer"}), 400

    from utils.did import fetch_did_document
    from utils.crypto import verify_credential_signature

    did_doc = fetch_did_document(issuer_did)
    public_key = did_doc['verificationMethod'][0]['publicKeyMultibase']
    is_valid = verify_credential_signature(credential, public_key)

    return jsonify({
        "valid": is_valid,
        "message": "Valid credential" if is_valid else "Invalid signature"
    })


@api_bp.route('/recover', methods=['POST'])
@handle_errors
def recover_credentials():
    """
    Recover all credentials issued to an email address.

    Body (JSON): { "email": "student@example.com" }
    """
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    from utils.database import get_supabase_client
    supabase = get_supabase_client()
    result = supabase.table('credentials') \
        .select('credential_data, claim_id, issued_at') \
        .eq('student_email', email) \
        .execute()

    credentials = [row['credential_data'] for row in (result.data or [])]

    return jsonify({"success": True, "data": {"credentials": credentials}})
