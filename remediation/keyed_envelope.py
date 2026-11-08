#!/usr/bin/env python3
"""Remediation for F-01: key-identified signature envelopes.

Every signature is published inside an envelope that names the key
that produced it, and the verifier keeps a registry of CURRENT and
RETIRED public keys, selecting the key by the envelope's key_id.

  * key_id = first 16 hex chars of SHA-256(public key). It is a lookup
    key only, not a trust anchor: the signature itself is still
    verified against the registered public key.
  * The envelope binds the artifact digest (SHA-256) and the algorithm
    name, so a signature cannot be replayed onto a different artifact
    or a different algorithm.
  * Verification failures are DISTINCT:
      UNKNOWN_KEY_ID  — no registered key matches the envelope
      ARTIFACT_MISMATCH — the artifact digest differs from the envelope
      INVALID_SIGNATURE — the signature does not verify under the
        registered key (tampering / wrong key)
    A rotated key therefore produces a successful verification of old
    artifacts (the old key stays in the registry), while a tampered
    artifact still fails with a different, specific error.

The wrapper changes no cryptography: signatures are plain FIPS 204
ML-DSA-65 signatures and verify under liboqs 0.16.0 as well as
dilithium-py (verified by remediation/test_remediation.py).
"""
import hashlib
import json

from dilithium_py.ml_dsa import ML_DSA_65

ALG = "ML-DSA-65"


def key_id(pk: bytes) -> str:
    return hashlib.sha256(pk).hexdigest()[:16]


def sign_release(sk: bytes, pk: bytes, artifact: bytes) -> dict:
    """Sign an artifact and return the key-identified envelope."""
    sig = ML_DSA_65.sign(sk, artifact)
    return {
        "alg": ALG,
        "key_id": key_id(pk),
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "signature_hex": sig.hex(),
    }


def verify_release(registry: dict, envelope: dict, artifact: bytes) -> str:
    """Verify an envelope against a {key_id: public_key} registry.

    Returns 'VALID', or raises KeyError('UNKNOWN_KEY_ID') /
    ValueError('ARTIFACT_MISMATCH' | 'INVALID_SIGNATURE').
    """
    kid = envelope.get("key_id")
    if kid not in registry:
        raise KeyError(f"UNKNOWN_KEY_ID {kid}")
    if envelope.get("alg") != ALG:
        raise ValueError(f"UNSUPPORTED_ALG {envelope.get('alg')}")
    if envelope.get("artifact_sha256") != hashlib.sha256(artifact).hexdigest():
        raise ValueError("ARTIFACT_MISMATCH")
    pk = registry[kid]
    sig = bytes.fromhex(envelope["signature_hex"])
    if not ML_DSA_65.verify(pk, artifact, sig):
        raise ValueError("INVALID_SIGNATURE")
    return "VALID"


def envelope_json(envelope: dict) -> str:
    return json.dumps(envelope, sort_keys=True)
