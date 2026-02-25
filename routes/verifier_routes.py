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
                # Always build from the current key file — never trust the cached did.json
                # on disk, which may have been written with a different key (e.g. after
                # env-var-only restarts on Render that preserve the filesystem).
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
