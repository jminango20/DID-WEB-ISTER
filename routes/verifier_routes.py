"""
Verifier routes - public interface for third-party credential verification.
"""

import json
import os

from flask import Blueprint, render_template, request, jsonify

from config import config
from utils.crypto import verify_credential_signature
from utils.did import fetch_did_document, create_did_document

verifier_bp = Blueprint('verifier', __name__, url_prefix='/verify')


@verifier_bp.route('/debug/<claim_id>', methods=['GET'])
def debug_verification(claim_id: str):
    """Temporary debug endpoint — shows exactly what is being signed vs verified."""
    import base64
    import json as _json
    from utils.database import get_supabase_client
    from utils.crypto import _b64url_decode

    supabase = get_supabase_client()
    result = supabase.table('credentials').select('credential_data').eq('claim_id', claim_id).execute()
    if not result.data:
        return jsonify({'error': 'Credential not found'}), 404

    credential = result.data[0]['credential_data']
    proof = credential.get('proof', {})
    jws = proof.get('jws', '')
    issuer_did = credential.get('issuer', '')

    # Canonical JSON (what was signed / what is verified)
    credential_copy = {k: v for k, v in credential.items() if k != 'proof'}
    canonical = _json.dumps(credential_copy, sort_keys=True, separators=(',', ':'))

    # Public key from DID doc
    try:
        local_did_path = os.path.join('static', '.well-known', 'did.json')
        if os.path.exists(local_did_path):
            with open(local_did_path, 'r') as f:
                did_doc = _json.load(f)
            key_source = 'local_file'
        else:
            did_doc = create_did_document(config.DID_WEB_DOMAIN, config.PUBLIC_KEY_PATH)
            key_source = 'generated_from_pem'
        public_key_multibase = did_doc['verificationMethod'][0]['publicKeyMultibase']
    except Exception as e:
        return jsonify({'error': f'DID doc error: {str(e)}'}), 500

    # JWS parts
    jws_parts = jws.split('.')
    sig_b64 = jws_parts[2] if len(jws_parts) == 3 else ''

    # Actual verify
    is_valid = verify_credential_signature(credential, public_key_multibase)

    return jsonify({
        'claim_id': claim_id,
        'issuer_in_credential': issuer_did,
        'config_did_method': config.DID_METHOD,
        'issuer_matches_config': issuer_did == config.DID_METHOD,
        'key_source': key_source,
        'public_key_multibase': public_key_multibase,
        'jws': jws,
        'canonical_json': canonical,
        'canonical_length': len(canonical),
        'signature_b64url': sig_b64,
        'verification_result': is_valid,
    })


@verifier_bp.route('/', methods=['GET'])
def index():
    """Verifier landing page."""
    return render_template('verifier/index.html')


@verifier_bp.route('/check', methods=['POST'])
def check_credential():
    """
    Verify a credential's signature.

    Accepts JSON body: { "credential": { ...W3C VC... } }
    Returns verification result with credential details.
    """
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Se requiere JSON en el cuerpo de la solicitud'}), 400

        credential = data.get('credential')
        if not credential:
            return jsonify({'error': 'No se proporcionó ninguna credencial'}), 400

        issuer_did = credential.get('issuer')
        if not issuer_did:
            return jsonify({'error': 'Credencial inválida: falta el emisor (issuer)'}), 400

        # Fetch DID document to get the public key.
        # If the issuer is ourselves, load from local file to avoid an external HTTP call
        # (critical when running locally or when the domain isn't publicly reachable yet).
        try:
            if issuer_did == config.DID_METHOD:
                local_did_path = os.path.join('static', '.well-known', 'did.json')
                if os.path.exists(local_did_path):
                    with open(local_did_path, 'r') as f:
                        did_doc = json.load(f)
                else:
                    did_doc = create_did_document(config.DID_WEB_DOMAIN, config.PUBLIC_KEY_PATH)
            else:
                did_doc = fetch_did_document(issuer_did)
        except Exception as e:
            return jsonify({
                'valid': False,
                'error': f'No se pudo resolver el DID del emisor: {str(e)}',
                'message': 'No se pudo obtener la clave pública del emisor'
            }), 200

        verification_methods = did_doc.get('verificationMethod', [])
        if not verification_methods:
            return jsonify({
                'valid': False,
                'error': 'El documento DID no contiene métodos de verificación',
                'message': 'Documento DID inválido'
            }), 200

        public_key_multibase = verification_methods[0].get('publicKeyMultibase')
        if not public_key_multibase:
            return jsonify({
                'valid': False,
                'error': 'No se encontró la clave pública en el documento DID',
                'message': 'Clave pública no encontrada'
            }), 200

        # Verify the signature
        try:
            is_valid = verify_credential_signature(credential, public_key_multibase)
        except Exception as e:
            return jsonify({
                'valid': False,
                'error': f'Error al verificar la firma: {str(e)}',
                'message': 'Error de verificación'
            }), 200

        subject = credential.get('credentialSubject', {})
        has_credential = subject.get('hasCredential', {})

        result = {
            'valid': is_valid,
            'message': 'Firma válida' if is_valid else 'Firma inválida',
            'credential': {
                'id': credential.get('id'),
                'type': credential.get('type', []),
                'issuer': issuer_did,
                'issuanceDate': credential.get('issuanceDate'),
                'credentialSubject': {
                    'name': subject.get('name'),
                    'studentId': subject.get('studentId'),
                    'hasCredential': {
                        'courseName': has_credential.get('courseName'),
                        'completionDate': has_credential.get('completionDate'),
                        'grade': has_credential.get('grade'),
                    }
                }
            }
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Error interno: {str(e)}'}), 500
