# Educational Verifiable Credentials POC with DID:Web

## Project Context

**See @PLAN.md for complete implementation plan, architecture, and current phase.**

This is a proof-of-concept for issuing educational verifiable credentials using the DID:Web standard with three components:
- **Issuer Backend**: Flask API for credential issuance
- **Student Wallet**: PWA for claiming and storing credentials
- **Verifier**: Public interface for third-party verification

---

## Quick Start Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Generate Ed25519 keys (run once)
python generate_keys.py

# Start development server
python app.py

# Run tests
pytest tests/ -v

# Run specific test file
pytest tests/test_crypto.py -v
```

---

## Development Workflow

1. **Check current phase** in PLAN.md 
2. **Create feature branch**: `git checkout -b feat/feature-name`
3. **Implement** following PLAN.md specifications
4. **Test**: Run `pytest tests/` before committing
5. **Commit**: Use `/commit` skill with conventional commits
6. **Update PLAN.md**: Mark completed items as done

---

## Code Style & Conventions

### Python Style
- Follow PEP 8
- Use type hints for all function signatures
- Write docstrings for all public functions
- Maximum line length: 100 characters
- Use `black` for formatting (if available)

### Cryptography
- **ALWAYS use Ed25519** for signing (never RSA)
- Private key stored in `keys/private_key.pem` (gitignored)
- Public key in `keys/public_key.pem`
- All credentials use Ed25519Signature2020 proof type

### API Conventions
- All responses return JSON
- Include CORS headers for cross-origin requests
- Error responses format: `{"error": "message", "details": {...}}`
- Success responses format: `{"success": true, "data": {...}}`
- Use HTTP status codes correctly (200, 201, 400, 404, 500)

### Database
- Use Supabase client from `utils/database.py`
- Never write raw SQL queries
- Use parameterized queries for all user input
- Always validate input before database operations

### W3C Verifiable Credentials
- Follow W3C VC Data Model 1.1
- DID format: `did:web:credenciales-emisor-ISTER.replit.app`
- DID Document served at `/.well-known/did.json`
- Credential ID format: `{issuer_did}/credentials/{claim_id}`
- Claim ID format: 16 uppercase alphanumeric characters

---

## Testing Requirements

### Before Every Commit
- Run full test suite: `pytest tests/`
- All tests must pass
- No skipped tests without good reason

### Test Coverage
- Write tests for all new API endpoints
- Test both success and error cases
- Test edge cases (empty inputs, invalid formats, etc.)
- Maintain >80% code coverage where practical

### Test Files
- `tests/test_crypto.py` - Cryptography operations
- `tests/test_did.py` - DID document generation
- `tests/test_credential.py` - VC creation and verification
- `tests/test_api.py` - API endpoints

---

## Important Security Rules

### Private Key Management
- **NEVER** commit private keys to git
- Private key only in `keys/private_key.pem` (gitignored)
- Use environment variable for private key path
- For Replit: Store in Replit Secrets

### Environment Variables
- Load from `.env` file (local development)
- Use Replit Secrets for deployment
- Never hardcode credentials in source code
- Admin password stored in environment, not code

### Input Validation
- Validate all user inputs before processing
- Sanitize inputs to prevent injection attacks
- Check email format before database queries
- Validate claim ID format (16 chars, alphanumeric)

### CORS Configuration
- Configure Flask-CORS for specific origins
- Don't use `origins: "*"` in production
- Allow wallet origin for API access

---

## Environment Variables Required

```env
# Flask
FLASK_SECRET_KEY=<random-secret-key>
FLASK_ENV=development
FLASK_DEBUG=True

# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key

# DID
DID_WEB_DOMAIN=credenciales-emisor-ISTER.replit.app
DID_METHOD=did:web:credenciales-emisor-ISTER.replit.app

# Admin
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

# Keys
PRIVATE_KEY_PATH=keys/private_key.pem
PUBLIC_KEY_PATH=keys/public_key.pem
```

---

## File Structure Patterns

### Route Organization
- `routes/admin_routes.py` - Admin panel (login, dashboard, issue credentials)
- `routes/api_routes.py` - API endpoints (issue, claim, verify, recover)
- `routes/wallet_routes.py` - Wallet pages (claim, view, recover)
- `routes/verifier_routes.py` - Verifier pages (verify, results)
- `routes/did_routes.py` - DID document serving

### Utilities Organization
- `utils/crypto.py` - Ed25519 signing and verification
- `utils/did.py` - DID document generation
- `utils/credential.py` - W3C VC creation and validation
- `utils/database.py` - Supabase client wrapper

### Template Organization
- `templates/admin/` - Admin panel templates
- `templates/wallet/` - Student wallet templates
- `templates/verifier/` - Verifier interface templates

---

## Common Patterns

### Error Handling
```python
from functools import wraps
from flask import jsonify

def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except SpecificError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            return jsonify({"error": "Internal server error"}), 500
    return decorated_function
```

### Database Queries
```python
# Use Supabase client, not raw SQL
from utils.database import get_supabase_client

supabase = get_supabase_client()
result = supabase.table('credentials').select('*').eq('claim_id', claim_id).execute()
```

### Credential Verification
```python
# Always verify both signature AND issuer
from utils.crypto import verify_credential_signature
from utils.did import fetch_did_document

did_doc = fetch_did_document(credential['issuer'])
public_key = did_doc['verificationMethod'][0]['publicKeyMultibase']
is_valid = verify_credential_signature(credential, public_key)
```

---

## Deployment (Replit)

### Configuration
- Use `.replit` file for run configuration
- Store secrets in Replit Secrets (not .env)
- Serve on port 5000 (Flask default)
- HTTPS automatic on Replit

### Pre-Deployment Checklist
- [ ] All tests passing
- [ ] Environment variables in Replit Secrets
- [ ] Private key generated and stored securely
- [ ] Supabase database schema created
- [ ] DID document accessible at `/.well-known/did.json`
- [ ] CORS configured correctly
- [ ] Error handling in place

---

## Troubleshooting

### Common Issues

**Issue: DID document not found**
- Check `static/.well-known/did.json` exists
- Ensure Flask serves static files correctly
- Verify route is registered

**Issue: Signature verification fails**
- Ensure canonical JSON (sorted keys, no spaces)
- Check public key encoding (base64 vs base64url)
- Verify JWS format: `header..signature`

**Issue: Supabase connection fails**
- Check `SUPABASE_URL` and `SUPABASE_KEY` are correct
- Verify network connectivity
- Check Supabase project is not paused

**Issue: Private key not found**
- Run `python generate_keys.py`
- Check `keys/` directory exists
- Verify `.gitignore` includes `keys/private_key.pem`

---

## Phase Progress Tracking

When completing tasks:
1. Update PLAN.md with ✅ for completed items
2. Add entry to session notes if significant progress
3. Document any decisions or deviations from plan
4. Run tests to verify functionality

---

## External Resources

- W3C VC Spec: https://www.w3.org/TR/vc-data-model/
- DID Web Spec: https://w3c-ccg.github.io/did-method-web/
- Ed25519 Signature Suite: https://w3c-ccg.github.io/lds-ed25519-2020/
- Supabase Docs: https://supabase.com/docs
- Flask Docs: https://flask.palletsprojects.com/

---

## Skills Available

- `/commit` - Create conventional git commits with validation
