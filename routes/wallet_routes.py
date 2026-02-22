"""
Wallet routes (student-facing pages).

The wallet is a PWA that stores credentials in the browser's localStorage.
The server only serves the HTML pages — all credential storage happens client-side.

Routes:
    GET /wallet/              - Wallet home (list of saved credentials)
    GET /wallet/claim/<id>    - Claim a credential by claim ID
    GET /wallet/view          - View a single credential (data passed via JS)
    GET /wallet/recover       - Recover credentials by email
"""

from flask import Blueprint, render_template, jsonify, request
from config import config

wallet_bp = Blueprint('wallet', __name__, url_prefix='/wallet')


@wallet_bp.route('/')
def index():
    """Wallet home — shows credentials stored in localStorage."""
    return render_template('wallet/index.html')


@wallet_bp.route('/claim/<claim_id>')
def claim(claim_id: str):
    """
    Claim page for a specific credential.

    Fetches the credential from the API and presents it to the student.
    The student clicks 'Guardar' to store it in localStorage.
    """
    return render_template('wallet/claim.html', claim_id=claim_id)


@wallet_bp.route('/view')
def view_credential():
    """View a single credential detail page (credential loaded via JS from localStorage)."""
    return render_template('wallet/view_credential.html')


@wallet_bp.route('/recover')
def recover():
    """Recovery page — student enters email to retrieve their credentials."""
    return render_template('wallet/recover.html')
