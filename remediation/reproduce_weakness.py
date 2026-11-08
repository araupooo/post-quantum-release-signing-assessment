#!/usr/bin/env python3
"""Reproduce the failure mode (F-01): key rotation breaks verification
of previously signed release artifacts, and the failure is
indistinguishable from tampering.

Scenario (the vulnerable pipeline in remediation/vulnerable_pipeline.py):
  1. Release 1.0 is signed with key A; it verifies under key A.
  2. The release key is rotated to key B (compromise, scheduled
     rotation, personnel change). Release 2.0 is signed with key B.
  3. A user verifies the OLD Release 1.0 artifact with the CURRENT
     key B: INVALID.
  4. A TAMPERED Release 1.0 artifact verified with key B: INVALID —
     the exact same error string, no key identifier, no way to tell
     rotation from tampering.

Exit code 0 means the failure mode reproduced (old artifact INVALID
after rotation, and the tampered-artifact error is identical).
Exit code 1 means it did NOT reproduce.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vulnerable_pipeline as pipe

ARTIFACT_V1 = b"release-1.0 tarball bytes (simulated)"
ARTIFACT_V1_TAMPERED = b"release-1.0 tarball bytes (simulated!)"
ARTIFACT_V2 = b"release-2.0 tarball bytes (simulated)"


def main():
    print("=== F-01 reproduction: key rotation without key identifiers ===")
    pk_a, sk_a = pipe.keygen()
    print("key A generated (ML-DSA-65)")
    sig_v1 = pipe.sign_artifact(sk_a, ARTIFACT_V1)
    print(f"Release 1.0 signed with key A; verify under A: {pipe.verify_artifact(pk_a, ARTIFACT_V1, sig_v1)}")

    # Rotate the release key.
    pk_b, sk_b = pipe.keygen()
    print("key rotated: A -> B (old key discarded by the pipeline)")
    sig_v2 = pipe.sign_artifact(sk_b, ARTIFACT_V2)
    print(f"Release 2.0 signed with key B; verify under B: {pipe.verify_artifact(pk_b, ARTIFACT_V2, sig_v2)}")

    # The failure: the old artifact no longer verifies, and the error
    # is indistinguishable from tampering.
    old_after_rotation = pipe.verify_artifact(pk_b, ARTIFACT_V1, sig_v1)
    tampered_after_rotation = pipe.verify_artifact(pk_b, ARTIFACT_V1_TAMPERED, sig_v1)
    print(f"Release 1.0 (untouched) verified under current key B: {old_after_rotation}")
    print(f"Release 1.0 (TAMPERED) verified under current key B: {tampered_after_rotation}")
    print(f"artifact sha256 v1: {pipe.artifact_sha256(ARTIFACT_V1)[:16]}... (unchanged — the artifact is intact)")
    if old_after_rotation == "INVALID" and tampered_after_rotation == "INVALID":
        print()
        print("REPRODUCED: after rotation, an intact previously signed artifact")
        print("fails verification, and the failure is identical to a tampered")
        print("artifact's failure. The pipeline cannot tell rotation from")
        print("tampering because signatures carry no key identifier.")
        return 0
    print("NOT REPRODUCED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
