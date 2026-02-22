"""
W3C Verifiable Credential creation and validation.

Creates credentials following the W3C VC Data Model 1.1 with Ed25519Signature2020 proofs.

Credential ID format:  {issuer_did}/credentials/{claim_id}
Claim ID format:       16 uppercase alphanumeric characters (UUID-based)
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from utils.crypto import sign_credential


def generate_claim_id() -> str:
    """
    Generate a unique 16-character claim ID.

    Uses UUID4 (random) as the source of entropy, strips hyphens,
    and takes the first 16 characters uppercased.

    Returns:
        16-character uppercase alphanumeric string, e.g. 'A7B3C9D1E5F7G2H4'
    """
    return str(uuid.uuid4()).replace('-', '')[:16].upper()


def create_verifiable_credential(
    student_name: str,
    student_email: str,
    student_id: str,
    course_name: str,
    completion_date: str,
    grade: str,
    issuer_did: str,
    private_key: Ed25519PrivateKey,
) -> Tuple[Dict[str, Any], str]:
    """
    Create a signed W3C Verifiable Credential for a course completion.

    Builds the credential structure, signs it with Ed25519, and attaches
    the proof. The credential is ready to be stored in the database and
    shared with the student.

    Args:
        student_name: Full name of the student.
        student_email: Student's email address (used as DID subject).
        student_id: Institutional student ID number.
        course_name: Name of the completed course.
        completion_date: ISO date string, e.g. '2025-02-20'.
        grade: Grade achieved, e.g. '95' or 'A'.
        issuer_did: DID of the issuing institution.
        private_key: Ed25519 private key for signing.

    Returns:
        Tuple of (signed_credential_dict, claim_id)
    """
    claim_id = generate_claim_id()
    credential_id = f"{issuer_did}/credentials/{claim_id}"
    now = datetime.now(timezone.utc).isoformat()

    # Build the W3C VC structure (without proof)
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": credential_id,
        "type": ["VerifiableCredential", "EducationalCredential"],
        "issuer": issuer_did,
        "issuanceDate": now,
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

    # Sign and attach proof
    jws = sign_credential(credential, private_key)
    credential["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now,
        "verificationMethod": f"{issuer_did}#key-1",
        "proofPurpose": "assertionMethod",
        "jws": jws
    }

    return credential, claim_id


def validate_credential_structure(credential: Dict[str, Any]) -> bool:
    """
    Check that a credential dict has the minimum required W3C VC fields.

    Does NOT verify the cryptographic signature — use verify_credential_signature
    from utils/crypto.py for that.

    Args:
        credential: Credential dict to validate.

    Returns:
        True if all required fields are present and correctly typed.
    """
    required_fields = ['@context', 'id', 'type', 'issuer', 'issuanceDate', 'credentialSubject']
    for field in required_fields:
        if field not in credential:
            return False

    if 'VerifiableCredential' not in credential.get('type', []):
        return False

    if 'proof' not in credential:
        return False

    return True
