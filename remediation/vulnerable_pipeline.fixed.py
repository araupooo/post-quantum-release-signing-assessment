#!/usr/bin/env python3
"""Fixed release pipeline (the AFTER code for F-01).

Identical interface to vulnerable_pipeline.py, but signatures are
published as key-identified envelopes (see remediation/keyed_envelope.py)
and verification looks the signing key up in a registry that retains
retired keys. Rotating the release key no longer invalidates previously
signed artifacts, and a tampered artifact still fails — with a distinct
error.
"""
import hashlib

import keyed_envelope as env


def keygen():
    from dilithium_py.ml_dsa import ML_DSA_65
    return ML_DSA_65.keygen()


def sign_artifact(sk, pk, artifact: bytes) -> dict:
    """Sign an artifact. Returns the key-identified envelope."""
    return env.sign_release(sk, pk, artifact)


def verify_artifact(registry: dict, envelope: dict, artifact: bytes) -> str:
    """Verify an envelope against a {key_id: public_key} registry."""
    return env.verify_release(registry, envelope, artifact)


def artifact_sha256(artifact: bytes) -> str:
    return hashlib.sha256(artifact).hexdigest()


def main():
    artifact_v1 = b"release-1.0 tarball bytes (simulated)"
    artifact_v1_tampered = b"release-1.0 tarball bytes (simulated!)"
    pk_a, sk_a = keygen()
    envelope_v1 = sign_artifact(sk_a, pk_a, artifact_v1)
    # Rotate the release key, keeping the old public key in the registry.
    pk_b, sk_b = keygen()
    registry = {env.key_id(pk_a): pk_a, env.key_id(pk_b): pk_b}
    print(f"old artifact verifies after rotation: {verify_artifact(registry, envelope_v1, artifact_v1)}")
    try:
        verify_artifact(registry, envelope_v1, artifact_v1_tampered)
        print("tampered artifact verifies after rotation: VALID (UNEXPECTED)")
    except ValueError as e:
        print(f"tampered artifact verifies after rotation: refused ({e})")


if __name__ == "__main__":
    main()
