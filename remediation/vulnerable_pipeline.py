#!/usr/bin/env python3
"""Vulnerable release pipeline (the BEFORE code for F-01).

The pipeline signs release artifacts with the CURRENT release key and
verifies them with the CURRENT release key only. Signatures carry no
key identifier and no algorithm identifier: the verifier has no way to
know which key signed an artifact.

Consequence: after a key rotation, every artifact signed under the old
key fails verification — and the failure is byte-identical to the
failure of a tampered artifact, so an operator cannot tell "the key
rotated" from "the artifact was modified". See
remediation/reproduce_weakness.py.
"""
import hashlib

from dilithium_py.ml_dsa import ML_DSA_65


def keygen():
    return ML_DSA_65.keygen()


def sign_artifact(sk, artifact: bytes) -> bytes:
    """Sign an artifact. Returns the raw signature only — no key id."""
    return ML_DSA_65.sign(sk, artifact)


def verify_artifact(pk, artifact: bytes, sig: bytes) -> str:
    """Verify with the current key only. Returns 'VALID' or 'INVALID'."""
    return "VALID" if ML_DSA_65.verify(pk, artifact, sig) else "INVALID"


def artifact_sha256(artifact: bytes) -> str:
    return hashlib.sha256(artifact).hexdigest()
