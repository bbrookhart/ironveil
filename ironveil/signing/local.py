"""Explicitly local, test-only Ed25519 signing for the offline research mode."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ironveil.models import ReleaseBundle, SignatureBundle
from ironveil.util import canonical_json, digest_object, sha256_bytes


def generate_test_key(private_path: Path, public_path: Path) -> None:
    """Generate a local research key; callers must keep the private path outside git."""
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    private_path.chmod(0o600)


def evidence_envelope(bundle: ReleaseBundle) -> dict[str, object]:
    return {
        "artifact": bundle.artifact.model_dump(mode="json"),
        "source_digest": digest_object(bundle.source),
        "provenance_digest": digest_object(bundle.provenance),
        "sbom_digest": digest_object(bundle.sbom) if bundle.sbom else None,
        "security_digest": digest_object(bundle.security),
        "authorization_digest": digest_object(bundle.authorization),
        "update_digest": digest_object(bundle.update),
    }


def sign_release(
    bundle: ReleaseBundle,
    private_path: Path,
    public_path: Path,
    *,
    identity: str,
    issuer: str,
) -> SignatureBundle:
    private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("local research signer requires an Ed25519 private key")
    public_bytes = public_path.read_bytes()
    envelope_digest = digest_object(evidence_envelope(bundle))
    payload = canonical_json(
        {"artifact_digest": bundle.artifact.digest, "evidence_digest": envelope_digest}
    )
    signature = private_key.sign(payload)
    return SignatureBundle(
        evidence_id="EV-SIGN-001",
        artifact_digest=bundle.artifact.digest,
        evidence_digest=envelope_digest,
        signer_identity=identity,
        issuer=issuer,
        public_key_hint=sha256_bytes(public_bytes),
        public_key_pem=public_bytes.decode("ascii"),
        signature=base64.b64encode(signature).decode("ascii"),
        signed_at=datetime.now(UTC),
    )


def verify_release_signature(
    bundle: ReleaseBundle,
    trusted_public_key: Path,
) -> tuple[bool, str]:
    signature = bundle.signature
    if signature is None:
        return False, "signature evidence is missing"
    public_bytes = trusted_public_key.read_bytes()
    if signature.public_key_hint != sha256_bytes(public_bytes):
        return False, "signer key is not the configured trust root"
    expected_evidence_digest = digest_object(evidence_envelope(bundle))
    if signature.evidence_digest != expected_evidence_digest:
        return False, "signed evidence envelope does not match current evidence"
    if signature.artifact_digest != bundle.artifact.digest:
        return False, "signature subject does not match artifact digest"
    payload = canonical_json(
        {
            "artifact_digest": signature.artifact_digest,
            "evidence_digest": signature.evidence_digest,
        }
    )
    public_key = serialization.load_pem_public_key(public_bytes)
    if not isinstance(public_key, Ed25519PublicKey):
        return False, "configured trust root is not an Ed25519 public key"
    try:
        public_key.verify(base64.b64decode(signature.signature), payload)
    except (InvalidSignature, ValueError):
        return False, "cryptographic signature verification failed"
    return True, "cryptographic signature and evidence binding verified"


def verify_cryptographic_signature_only(bundle: ReleaseBundle) -> tuple[bool, str]:
    """Verify cryptography only, deliberately making no authorization decision."""
    signature = bundle.signature
    if signature is None:
        return False, "signature missing"
    if signature.artifact_digest != bundle.artifact.digest:
        return False, "artifact subject mismatch"
    payload = canonical_json(
        {
            "artifact_digest": signature.artifact_digest,
            "evidence_digest": signature.evidence_digest,
        }
    )
    try:
        public_key = serialization.load_pem_public_key(signature.public_key_pem.encode("ascii"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False, "unsupported signature key"
        public_key.verify(base64.b64decode(signature.signature), payload)
    except (InvalidSignature, ValueError):
        return False, "cryptographic signature invalid"
    return True, "signature is cryptographically valid; identity and policy not evaluated"
