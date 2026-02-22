"""
DID Document routes.

Serves the W3C DID Document at the standard well-known URL:
    GET /.well-known/did.json

This endpoint is public and requires no authentication.
Anyone verifying a credential from this issuer will fetch this URL to get the public key.
"""

import json
import os
from flask import Blueprint, jsonify

from config import config
from utils.did import create_did_document, save_did_document

did_bp = Blueprint('did', __name__)


@did_bp.route('/.well-known/did.json', methods=['GET'])
def get_did_document():
    """
    Serve the DID Document at the well-known URL.

    Serves the pre-generated file if it exists, otherwise generates it on the fly.

    Returns:
        JSON response with Content-Type application/did+json.
    """

    did_json_path = os.path.join('static', '.well-known', 'did.json')

    if os.path.exists(did_json_path):
        with open(did_json_path, 'r', encoding='utf-8') as f:
            did_document = json.load(f)
    else:
        try:
            did_document = create_did_document(
                domain=config.DID_WEB_DOMAIN,
                public_key_path=config.PUBLIC_KEY_PATH
            )
            save_did_document(did_document)
        except FileNotFoundError:
            return jsonify({
                "error": "DID Document not available",
                "details": "Public key not found. Run: python generate_keys.py"
            }), 503

    response = jsonify(did_document)
    response.headers['Content-Type'] = 'application/did+json'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response
