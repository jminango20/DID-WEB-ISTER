"""
Application configuration.

Loads environment variables from .env file using python-dotenv.
All other modules should import configuration values from here
rather than calling os.getenv() directly.
"""

import os
from dotenv import load_dotenv

# Load .env file into os.environ.
# On Replit, secrets are already in os.environ, so this is a no-op there.
load_dotenv()


class Config:
    """Central configuration object for the application."""

    # Flask
    SECRET_KEY: str = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    ENV: str = os.getenv('FLASK_ENV', 'development')
    DEBUG: bool = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'

    # DID
    DID_WEB_DOMAIN: str = os.getenv('DID_WEB_DOMAIN', 'credenciales-emisor-ISTER.replit.app')
    DID_METHOD: str = os.getenv('DID_METHOD', 'did:web:credenciales-emisor-ISTER.replit.app')

    # Key file paths
    PRIVATE_KEY_PATH: str = os.getenv('PRIVATE_KEY_PATH', 'keys/private_key.pem')
    PUBLIC_KEY_PATH: str = os.getenv('PUBLIC_KEY_PATH', 'keys/public_key.pem')

    # Admin credentials (POC only)
    ADMIN_USERNAME: str = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD: str = os.getenv('ADMIN_PASSWORD', 'admin123')

    # Supabase (configured in Phase 2)
    SUPABASE_URL: str = os.getenv('SUPABASE_URL', '')
    SUPABASE_KEY: str = os.getenv('SUPABASE_KEY', '')


# Single instance imported by all other modules
config = Config()
