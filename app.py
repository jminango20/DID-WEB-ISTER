"""
Main Flask application entry point.

Usage:
    python app.py
"""

import os
from flask import Flask, jsonify
from flask_cors import CORS

from config import config


def create_app() -> Flask:
    """
    Application factory function.

    Creates a configured Flask application with all blueprints registered.
    Using a factory function makes it easy to create fresh app instances for testing.

    Returns:
        A configured Flask application instance.
    """

    app = Flask(__name__)

    app.secret_key = config.SECRET_KEY
    app.config['ENV'] = config.ENV
    app.config['DEBUG'] = config.DEBUG

    # Enable CORS for API, DID, and verifier routes
    CORS(app, resources={
        r"/api/*": {"origins": "*"},
        r"/.well-known/*": {"origins": "*"},
        r"/verify/*": {"origins": "*"}
    })

    # Phase 1: DID routes
    from routes.did_routes import did_bp
    app.register_blueprint(did_bp)

    # Phase 3: Admin and API routes
    from routes.admin_routes import admin_bp
    from routes.api_routes import api_bp
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    # Phase 4: Wallet routes
    from routes.wallet_routes import wallet_bp
    app.register_blueprint(wallet_bp)

    # Phase 5: Verifier routes
    from routes.verifier_routes import verifier_bp
    app.register_blueprint(verifier_bp)

    @app.route('/health')
    def health():
        """Health check endpoint."""
        return jsonify({"status": "ok", "did": config.DID_METHOD})

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error"}), 500

    return app


def ensure_keys_exist() -> None:
    """Restore keys from PRIVATE_KEY_B64 env var (Render/prod) or generate fresh (local dev)."""
    private_key_b64 = os.getenv('PRIVATE_KEY_B64')

    if private_key_b64:
        import base64 as _b64
        from cryptography.hazmat.primitives import serialization as _ser
        os.makedirs('keys', exist_ok=True)
        private_pem = _b64.b64decode(private_key_b64)
        with open(config.PRIVATE_KEY_PATH, 'wb') as f:
            f.write(private_pem)
        private_key = _ser.load_pem_private_key(private_pem, password=None)
        public_pem = private_key.public_key().public_bytes(
            encoding=_ser.Encoding.PEM,
            format=_ser.PublicFormat.SubjectPublicKeyInfo
        )
        with open(config.PUBLIC_KEY_PATH, 'wb') as f:
            f.write(public_pem)
        print("Keys restored from PRIVATE_KEY_B64 environment variable.")

    elif not os.path.exists(config.PRIVATE_KEY_PATH):
        from generate_keys import generate_ed25519_keypair
        print("Keys not found — generating on first startup...")
        generate_ed25519_keypair()


ensure_keys_exist()
app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=config.DEBUG)
