# Educational Verifiable Credentials POC - Implementation Plan

## Project Overview

**Goal**: Build a complete Verifiable Credentials system using DID:Web standard for issuing educational certificates with a PWA wallet for students.

**Configuration**:
- Domain: `credenciales-emisor-ISTER.replit.app`
- DID: `did:web:credenciales-emisor-ISTER.replit.app`
- Cryptography: Ed25519
- Admin: `admin / admin123`
- Stack: Flask + Supabase + PWA

---

## Complete File Structure

```
/home/juan/CPqD/DID-WEB/DID-WEB-ISTER/
├── .env                              # Environment variables
├── .replit                           # Replit configuration
├── .gitignore                        # Git ignore
├── requirements.txt                  # Python dependencies
├── README.md                         # Documentation
├── app.py                            # Main Flask app ⭐
├── config.py                         # Configuration
├── generate_keys.py                  # Key generation utility
│
├── keys/
│   ├── .gitkeep
│   ├── private_key.pem              # Ed25519 private key (gitignored)
│   └── public_key.pem               # Ed25519 public key
│
├── utils/
│   ├── __init__.py
│   ├── crypto.py                    # Cryptography utilities ⭐
│   ├── did.py                       # DID document generation
│   ├── credential.py                # W3C VC creation ⭐
│   └── database.py                  # Supabase client
│
├── routes/
│   ├── __init__.py
│   ├── admin_routes.py              # Admin panel routes
│   ├── api_routes.py                # API endpoints ⭐
│   ├── wallet_routes.py             # Wallet routes
│   ├── verifier_routes.py           # Verifier routes
│   └── did_routes.py                # DID document serving
│
├── static/
│   ├── .well-known/
│   │   └── did.json                 # DID Document (generated)
│   ├── css/
│   │   ├── admin.css
│   │   ├── wallet.css
│   │   └── verifier.css
│   ├── js/
│   │   ├── wallet.js                # Wallet functionality ⭐
│   │   ├── verifier.js              # Verifier functionality
│   │   ├── qr-scanner.js
│   │   └── crypto-verify.js         # Client-side verification
│   ├── manifest.json                # PWA manifest
│   ├── service-worker.js            # Service worker
│   └── icons/
│       ├── icon-192.png
│       └── icon-512.png
│
├── templates/
│   ├── admin/
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── issue_credential.html
│   │   └── credential_list.html
│   ├── wallet/
│   │   ├── index.html
│   │   ├── claim.html
│   │   ├── view_credential.html
│   │   └── recover.html
│   └── verifier/
│       ├── index.html              # Public verifier page
│       └── result.html             # Verification result page
│
└── tests/
    ├── __init__.py
    ├── test_crypto.py
    ├── test_did.py
    ├── test_credential.py
    └── test_api.py
```

**⭐ = Critical files**

---

## Implementation Phases

### Phase 1: Foundation & DID Setup
**Files**: Project structure, keys, DID document

1. Create project structure and `.gitignore`
2. Install dependencies (`requirements.txt`)
3. Generate Ed25519 key pair (`generate_keys.py`)
4. Implement DID document generation (`utils/did.py`)
5. Serve DID at `/.well-known/did.json`
6. Test DID resolution

### Phase 2: Database Setup
**Files**: Supabase configuration, `utils/database.py`

1. Create Supabase project
2. Run SQL schema (see Database Schema section)
3. Get API credentials (SUPABASE_URL, SUPABASE_KEY)
4. Create database client wrapper
5. Test connection

### Phase 3: Credential Issuance System
**Files**: `utils/credential.py`, `utils/crypto.py`, admin routes

1. Implement Ed25519 signing utilities
2. Create W3C VC generator with JWS proofs
3. Build admin login and dashboard
4. Create credential issuance form
5. Store credentials in Supabase
6. Generate claim URLs and QR codes

### Phase 4: PWA Wallet - Core
**Files**: Wallet templates, `static/js/wallet.js`

1. Build wallet UI (list credentials)
2. Implement localStorage management
3. Create claim flow (URL-based)
4. Display credentials beautifully
5. Test claim and storage

### Phase 5: Verification System
**Files**: `static/js/crypto-verify.js`, API routes

1. Add @noble/ed25519 library (CDN)
2. Implement client-side signature verification
3. Create verification UI
4. Add API verification endpoint
5. Test signature validation

### Phase 6: PWA Features
**Files**: `manifest.json`, `service-worker.js`

1. Create PWA manifest
2. Implement service worker for offline
3. Add app icons
4. Test installation on mobile

### Phase 7: Recovery & QR
**Files**: Recovery routes, QR components

1. Implement email-based recovery API
2. Create recovery UI
3. Add QR code generation
4. Add QR scanner
5. Test recovery flow

### Phase 8: Verifier Interface
**Files**: Verifier templates, `routes/verifier_routes.py`, `static/js/verifier.js`

1. Create public verifier landing page
2. Implement credential input (paste JSON or scan QR)
3. Add verification display logic
4. Fetch DID document automatically
5. Show verification results (signature status, issuer info, credential details)
6. Add credential detail view with all fields
7. Test with valid and invalid credentials

### Phase 9: Testing & Deployment
**Files**: All test files, `.replit`

1. Run all unit tests
2. Test end-to-end flows
3. Configure Replit deployment
4. Deploy and verify
5. Document usage

---

## Dependencies (requirements.txt)

```txt
Flask==3.0.0
flask-cors==4.0.0
python-dotenv==1.0.0
cryptography==41.0.7
supabase==2.3.0
postgrest==0.13.0
PyJWT==2.8.0
qrcode[pil]==7.4.2
python-dateutil==2.8.2
```

---

## Environment Variables (.env)

```env
# Flask
FLASK_SECRET_KEY=your-secret-key-change-in-production
FLASK_ENV=development
FLASK_DEBUG=True

# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key

# DID
DID_WEB_DOMAIN=credenciales-emisor-ISTER.replit.app
DID_METHOD=did:web:credenciales-emisor-ISTER.replit.app

# Admin (POC only)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

# Keys
PRIVATE_KEY_PATH=keys/private_key.pem
PUBLIC_KEY_PATH=keys/public_key.pem
```

---

## Supabase Setup

### Step 1: Create Project
1. Go to https://supabase.com
2. Sign in and create new project
3. Name: `ister-credentials`
4. Choose region and generate password
5. Wait ~2 minutes for provisioning

### Step 2: Get Credentials
1. Settings → API
2. Copy **Project URL** → `SUPABASE_URL`
3. Copy **anon/public key** → `SUPABASE_KEY`

### Step 3: Run SQL Schema

```sql
-- Credentials table
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    claim_id VARCHAR(255) UNIQUE NOT NULL,
    credential_type VARCHAR(100) NOT NULL,
    student_name VARCHAR(255) NOT NULL,
    student_email VARCHAR(255) NOT NULL,
    student_id VARCHAR(100) NOT NULL,
    course_name VARCHAR(255) NOT NULL,
    completion_date DATE NOT NULL,
    grade VARCHAR(50),
    credential_data JSONB NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    claimed BOOLEAN DEFAULT FALSE,
    claimed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_credentials_claim_id ON credentials(claim_id);
CREATE INDEX idx_credentials_student_email ON credentials(student_email);
CREATE INDEX idx_credentials_claimed ON credentials(claimed);

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_credentials_updated_at
    BEFORE UPDATE ON credentials
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
```

---

## Critical Implementation: Ed25519 Key Generation

**File**: `generate_keys.py`

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os

def generate_ed25519_keypair():
    """Generate Ed25519 key pair and save to files"""

    # Generate private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Ensure directory exists
    os.makedirs('keys', exist_ok=True)

    # Write keys
    with open('keys/private_key.pem', 'wb') as f:
        f.write(private_pem)

    with open('keys/public_key.pem', 'wb') as f:
        f.write(public_pem)

    print("✅ Keys generated successfully!")
    print("   Private: keys/private_key.pem")
    print("   Public:  keys/public_key.pem")

if __name__ == '__main__':
    generate_ed25519_keypair()
```

**Run once**: `python generate_keys.py`

---

## Critical Implementation: W3C VC Creation

**File**: `utils/credential.py`

```python
import json
import uuid
from datetime import datetime, timezone
import base64

def create_verifiable_credential(
    student_name, student_email, student_id,
    course_name, completion_date, grade,
    issuer_did, private_key
):
    """Create W3C Verifiable Credential with Ed25519 signature"""

    claim_id = generate_claim_id()
    credential_id = f"{issuer_did}/credentials/{claim_id}"

    # W3C VC structure
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": credential_id,
        "type": ["VerifiableCredential", "EducationalCredential"],
        "issuer": issuer_did,
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        "credentialSubject": {
            "id": f"did:email:{student_email}",
            "name": student_name,
            "studentId": student_id,
            "hasCredential": {
                "type": "CourseCompletionCredential",
                "courseName": course_name,
                "completionDate": completion_date,
                "grade": grade
            }
        }
    }

    # Generate proof
    proof = create_ed25519_proof(credential, private_key, issuer_did)
    credential["proof"] = proof

    return credential, claim_id

def create_ed25519_proof(credential, private_key, issuer_did):
    """Create Ed25519Signature2020 proof with JWS"""

    # Canonical form (sorted keys, no spaces)
    canonical = json.dumps(credential, sort_keys=True, separators=(',', ':'))

    # Sign
    signature = private_key.sign(canonical.encode('utf-8'))

    # Create JWS header
    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"]}
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header).encode('utf-8')
    ).decode('utf-8').rstrip('=')

    signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

    # JWS format: header..signature (detached payload)
    jws = f"{header_b64}..{signature_b64}"

    proof = {
        "type": "Ed25519Signature2020",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": f"{issuer_did}#key-1",
        "proofPurpose": "assertionMethod",
        "jws": jws
    }

    return proof

def generate_claim_id():
    """Generate unique 16-char claim ID"""
    return str(uuid.uuid4()).replace('-', '')[:16].upper()
```

---

## Critical Implementation: DID Document

**File**: `utils/did.py`

```python
import json
import base64
from cryptography.hazmat.primitives import serialization

def create_did_document(domain, public_key_path):
    """Create W3C DID Document for did:web"""

    # Read public key
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Extract public key bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Base64 encode (multibase format)
    public_key_multibase = base64.b64encode(public_key_bytes).decode('utf-8')

    did = f"did:web:{domain}"

    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": [{
            "id": f"{did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"]
    }

    return did_document
```

---

## API Endpoints

Base: `https://credenciales-emisor-ISTER.replit.app`

### 1. GET /.well-known/did.json
**Public** - Returns DID Document

### 2. POST /api/credentials/issue
**Admin only** - Issue new credential
```json
Body: {
  "student_name": "Juan Pérez",
  "student_email": "juan@example.com",
  "student_id": "20240001",
  "course_name": "Blockchain Fundamentals",
  "completion_date": "2025-02-20",
  "grade": "95"
}
Response: {
  "success": true,
  "claim_id": "A7B3C9D1E5F7G2H4",
  "claim_url": "https://.../claim/A7B3C9D1E5F7G2H4",
  "credential": {...}
}
```

### 3. GET /api/credentials/list
**Admin only** - List all credentials

### 4. GET /api/credentials/<claim_id>
**Public** - Get credential by claim ID

### 5. POST /api/credentials/<claim_id>/claim
**Public** - Mark credential as claimed

### 6. POST /api/credentials/verify
**Public** - Verify credential signature
```json
Body: { "credential": {...} }
Response: { "valid": true, "message": "..." }
```

### 7. POST /api/recover
**Public** - Recover credentials by email
```json
Body: { "email": "student@example.com" }
Response: { "credentials": [...] }
```

---

## Verifier Routes (Page Routes)

Base: `https://credenciales-emisor-ISTER.replit.app`

### GET /verify
**Public** - Verifier landing page
- Input field for pasting credential JSON
- QR code scanner button
- Instructions for use
- Example credential link

### POST /verify/check
**Public** - Process verification request
- Accepts credential JSON in request body
- Calls verification API
- Displays results on result page

### GET /verify/result
**Public** - Display verification results
- Shows credential details (student name, course, grade, etc.)
- Signature validation status (✓ Valid / ✗ Invalid)
- Issuer information from DID document
- Issuance date and credential ID
- Option to verify another credential

---

## Client-Side Verification

**File**: `static/js/crypto-verify.js`

Uses **@noble/ed25519** library (CDN):
```html
<script src="https://cdn.jsdelivr.net/npm/@noble/ed25519@2.0.0/index.min.js"></script>
```

```javascript
async function verifyCredential(credential, publicKeyMultibase) {
    try {
        const proof = credential.proof;

        // Remove proof for verification
        const credentialCopy = { ...credential };
        delete credentialCopy.proof;

        // Canonical form
        const canonical = JSON.stringify(credentialCopy, Object.keys(credentialCopy).sort());

        // Parse JWS
        const jwsParts = proof.jws.split('.');
        const signature = base64UrlDecode(jwsParts[2]);

        // Decode public key
        const publicKeyBytes = base64Decode(publicKeyMultibase);

        // Verify with noble/ed25519
        const messageBytes = new TextEncoder().encode(canonical);
        const isValid = await nobleEd25519.verify(signature, messageBytes, publicKeyBytes);

        return { valid: isValid };
    } catch (error) {
        return { valid: false, message: error.message };
    }
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
```

---

## Verifier Implementation

The Verifier component provides a public interface for third parties (employers, universities, etc.) to independently verify credentials without requiring login or special access.

### Verifier Routes

**File**: `routes/verifier_routes.py`

```python
from flask import Blueprint, render_template, request, jsonify
import requests
from utils.crypto import verify_credential_signature
from utils.did import fetch_did_document

verifier_bp = Blueprint('verifier', __name__, url_prefix='/verify')

@verifier_bp.route('/', methods=['GET'])
def index():
    """Verifier landing page"""
    return render_template('verifier/index.html')

@verifier_bp.route('/check', methods=['POST'])
def check_credential():
    """Verify a credential"""
    try:
        data = request.get_json()
        credential = data.get('credential')

        if not credential:
            return jsonify({'error': 'No credential provided'}), 400

        # Extract issuer DID
        issuer_did = credential.get('issuer')
        if not issuer_did:
            return jsonify({'error': 'Invalid credential: missing issuer'}), 400

        # Fetch DID document to get public key
        did_doc = fetch_did_document(issuer_did)
        public_key = did_doc['verificationMethod'][0]['publicKeyMultibase']

        # Verify signature
        is_valid = verify_credential_signature(credential, public_key)

        # Extract credential details
        result = {
            'valid': is_valid,
            'credential': {
                'id': credential.get('id'),
                'type': credential.get('type'),
                'issuer': issuer_did,
                'issuanceDate': credential.get('issuanceDate'),
                'credentialSubject': credential.get('credentialSubject')
            },
            'message': 'Valid credential' if is_valid else 'Invalid signature'
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

### Verifier Frontend

**File**: `templates/verifier/index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ISTER Credential Verifier</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/verifier.css') }}">
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Credential Verifier</h1>
            <p>Independently verify educational credentials</p>
        </header>

        <main>
            <div class="input-section">
                <h2>Verify a Credential</h2>
                <p>Paste the credential JSON below or scan a QR code</p>

                <textarea id="credentialInput" placeholder='Paste credential JSON here...'></textarea>

                <div class="button-group">
                    <button id="verifyBtn" class="btn-primary">Verify Credential</button>
                    <button id="scanQrBtn" class="btn-secondary">Scan QR Code</button>
                </div>
            </div>

            <div id="results" class="results-section" style="display: none;">
                <!-- Results populated by JavaScript -->
            </div>
        </main>

        <footer>
            <p>Powered by DID:Web and W3C Verifiable Credentials</p>
        </footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/@noble/ed25519@2.0.0/index.min.js"></script>
    <script src="{{ url_for('static', filename='js/verifier.js') }}"></script>
</body>
</html>
```

**File**: `static/js/verifier.js`

```javascript
document.getElementById('verifyBtn').addEventListener('click', async () => {
    const credentialJson = document.getElementById('credentialInput').value.trim();

    if (!credentialJson) {
        showError('Please paste a credential');
        return;
    }

    try {
        const credential = JSON.parse(credentialJson);
        await verifyCredential(credential);
    } catch (e) {
        showError('Invalid JSON: ' + e.message);
    }
});

async function verifyCredential(credential) {
    try {
        const response = await fetch('/verify/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credential })
        });

        const result = await response.json();
        displayResults(result);

    } catch (error) {
        showError('Verification failed: ' + error.message);
    }
}

function displayResults(result) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.style.display = 'block';

    const statusClass = result.valid ? 'valid' : 'invalid';
    const statusIcon = result.valid ? '✓' : '✗';

    resultsDiv.innerHTML = `
        <div class="status ${statusClass}">
            <h2>${statusIcon} ${result.message}</h2>
        </div>

        <div class="credential-details">
            <h3>Credential Details</h3>

            <div class="detail-row">
                <span class="label">Student Name:</span>
                <span class="value">${result.credential.credentialSubject.name}</span>
            </div>

            <div class="detail-row">
                <span class="label">Course:</span>
                <span class="value">${result.credential.credentialSubject.hasCredential.courseName}</span>
            </div>

            <div class="detail-row">
                <span class="label">Grade:</span>
                <span class="value">${result.credential.credentialSubject.hasCredential.grade}</span>
            </div>

            <div class="detail-row">
                <span class="label">Completion Date:</span>
                <span class="value">${result.credential.credentialSubject.hasCredential.completionDate}</span>
            </div>

            <div class="detail-row">
                <span class="label">Issued By:</span>
                <span class="value">${result.credential.issuer}</span>
            </div>

            <div class="detail-row">
                <span class="label">Issuance Date:</span>
                <span class="value">${new Date(result.credential.issuanceDate).toLocaleString()}</span>
            </div>

            <div class="detail-row">
                <span class="label">Credential ID:</span>
                <span class="value">${result.credential.id}</span>
            </div>
        </div>

        <button class="btn-secondary" onclick="resetVerifier()">Verify Another</button>
    `;
}

function showError(message) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = `
        <div class="status invalid">
            <h2>✗ Error</h2>
            <p>${message}</p>
        </div>
        <button class="btn-secondary" onclick="resetVerifier()">Try Again</button>
    `;
}

function resetVerifier() {
    document.getElementById('credentialInput').value = '';
    document.getElementById('results').style.display = 'none';
}
```

### Verifier Styling

**File**: `static/css/verifier.css`

```css
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 800px;
    margin: 0 auto;
    background: white;
    border-radius: 16px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    overflow: hidden;
}

header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 40px;
    text-align: center;
}

header h1 {
    font-size: 2.5em;
    margin-bottom: 10px;
}

main {
    padding: 40px;
}

.input-section h2 {
    margin-bottom: 10px;
}

.input-section p {
    color: #666;
    margin-bottom: 20px;
}

#credentialInput {
    width: 100%;
    min-height: 200px;
    padding: 15px;
    border: 2px solid #e0e0e0;
    border-radius: 8px;
    font-family: 'Courier New', monospace;
    font-size: 14px;
    resize: vertical;
    margin-bottom: 20px;
}

.button-group {
    display: flex;
    gap: 10px;
}

.btn-primary, .btn-secondary {
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    cursor: pointer;
    transition: all 0.3s;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    flex: 1;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
}

.btn-secondary {
    background: #f5f5f5;
    color: #333;
}

.results-section {
    margin-top: 40px;
    padding-top: 40px;
    border-top: 2px solid #e0e0e0;
}

.status {
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 30px;
    text-align: center;
}

.status.valid {
    background: #d4edda;
    border: 2px solid #28a745;
    color: #155724;
}

.status.invalid {
    background: #f8d7da;
    border: 2px solid #dc3545;
    color: #721c24;
}

.status h2 {
    font-size: 2em;
}

.credential-details {
    background: #f9f9f9;
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 20px;
}

.credential-details h3 {
    margin-bottom: 20px;
    color: #333;
}

.detail-row {
    display: flex;
    padding: 12px 0;
    border-bottom: 1px solid #e0e0e0;
}

.detail-row:last-child {
    border-bottom: none;
}

.detail-row .label {
    font-weight: 600;
    color: #666;
    width: 180px;
}

.detail-row .value {
    flex: 1;
    color: #333;
}

footer {
    background: #f5f5f5;
    padding: 20px;
    text-align: center;
    color: #666;
}
```

### Key Features

1. **Public Access**: No authentication required
2. **Simple Interface**: Paste JSON or scan QR
3. **Real-time Verification**: Instant signature validation
4. **Detailed Display**: Shows all credential information
5. **Visual Feedback**: Clear valid/invalid indicators
6. **DID Resolution**: Automatically fetches issuer public key
7. **Error Handling**: User-friendly error messages

---

## Replit Configuration

**File**: `.replit`

```toml
run = "python app.py"
entrypoint = "app.py"
modules = ["python-3.11"]

[nix]
channel = "stable-23_05"

[deployment]
run = ["sh", "-c", "python app.py"]
deploymentTarget = "cloudrun"

[[ports]]
localPort = 5000
externalPort = 80
```

**Replit Secrets** (instead of .env):
- Add all env vars from `.env` as Replit Secrets
- Access via `os.getenv()` in code

---

## Error Handling Pattern

**File**: `routes/api_routes.py`

```python
from functools import wraps
from flask import jsonify

# Custom exceptions
class ClaimNotFoundError(Exception):
    pass

class AlreadyClaimedError(Exception):
    pass

# Error handler decorator
def handle_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ClaimNotFoundError:
            return jsonify({"error": "Credential not found"}), 404
        except AlreadyClaimedError:
            return jsonify({"error": "Already claimed"}), 409
        except Exception as e:
            print(f"Error: {e}")
            return jsonify({"error": "Internal server error"}), 500
    return decorated_function

# Usage
@app.route('/api/credentials/<claim_id>/claim', methods=['POST'])
@handle_errors
def claim_credential(claim_id):
    # Implementation
    pass
```

---

## Security Checklist

- [ ] Private key in `.gitignore` and Replit Secrets
- [ ] HTTPS enforced (automatic on Replit)
- [ ] Admin session management with Flask sessions
- [ ] Input validation on all forms
- [ ] SQL injection prevention (Supabase parameterized queries)
- [ ] CORS configured for specific origins
- [ ] Error messages don't leak sensitive info
- [ ] Claim IDs are cryptographically random

---

## Testing Checklist

### Unit Tests
- [ ] Key generation works
- [ ] Signing produces valid JWS
- [ ] Verification succeeds for valid signatures
- [ ] DID document structure is correct
- [ ] Credential format is W3C compliant

### Integration Tests
- [ ] Issue credential via API
- [ ] Claim credential via URL
- [ ] Verify signature via API
- [ ] Recovery by email returns credentials
- [ ] Admin authentication works

### Manual Tests
- [ ] DID resolves: `curl https://.../well-known/did.json`
- [ ] Admin login at `/admin`
- [ ] Issue credential from form
- [ ] Copy claim URL and open in wallet
- [ ] Credential saves in localStorage
- [ ] Signature verifies in wallet
- [ ] QR code generates
- [ ] Email recovery works
- [ ] **Verifier page accessible at `/verify`**
- [ ] **Paste credential JSON into verifier**
- [ ] **Verifier shows valid signature for real credentials**
- [ ] **Verifier shows invalid for tampered credentials**
- [ ] **Verifier displays all credential details correctly**
- [ ] PWA installs on mobile
- [ ] Offline access works

---

## Success Criteria

✅ **Ready for demo when**:

1. DID document resolves publicly
2. Admin can issue credentials via web form
3. System generates W3C-compliant VCs with Ed25519 signatures
4. Students can claim via URL in wallet
5. Credentials persist in localStorage
6. Signature verification works in wallet
7. Email recovery retrieves all credentials
8. **Verifier interface allows third parties to verify credentials**
9. **Verifier displays credential details and signature status**
10. PWA installs on mobile devices
11. Wallet works offline
12. All API endpoints functional
13. No security vulnerabilities
14. Deployed on Replit

---

## Implementation Order Summary

```
1. Project setup → dependencies → keys
2. Supabase → database connection
3. DID document → serve at /.well-known/did.json
4. Credential creation → signing → storage
5. Admin panel → issue form
6. API endpoints → error handling
7. Wallet UI → localStorage → claim flow
8. Verification → client-side crypto
9. PWA features → manifest → service worker
10. Recovery system → QR codes
11. Verifier interface → public verification
12. Testing → fixes → deployment
```

---

## Key Files to Modify During Implementation

**Critical files** (implement first):
1. `/utils/credential.py` - VC creation logic
2. `/utils/crypto.py` - Ed25519 signing
3. `/app.py` - Flask app structure
4. `/routes/api_routes.py` - API endpoints
5. `/static/js/wallet.js` - Wallet functionality

**Supporting files** (implement second):
6. `/utils/did.py` - DID document
7. `/utils/database.py` - Supabase client
8. `/routes/admin_routes.py` - Admin panel
9. `/routes/verifier_routes.py` - Verifier pages
10. `/templates/` - All HTML templates
11. `/static/js/crypto-verify.js` - Verification
12. `/static/js/verifier.js` - Verifier UI logic

---

## Notes

- Start with **Phase 1** (Foundation & DID) and progress sequentially
- Test each phase before moving to next
- Keep private key secure (never commit!)
- Use Supabase dashboard for debugging database issues
- Test PWA on real mobile device, not just desktop
- QR codes require HTTPS (Replit provides this)
- Recovery feature can be simple: just query by email

---

## Questions Resolved

✅ **Crypto algorithm**: Ed25519
✅ **Admin credentials**: admin / admin123
✅ **Domain**: credenciales-emisor-ISTER.replit.app
✅ **Supabase**: Need to set up (instructions included)
✅ **Key storage**: Environment variables + PEM files
✅ **Claim ID format**: 16-char UUID-based
✅ **Error handling**: Custom exceptions with decorators
✅ **Recovery**: Email-based query (simple for POC)

---

**Ready to implement!** Start with Phase 1: Foundation & DID Setup.
