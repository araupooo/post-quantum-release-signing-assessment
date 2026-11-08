#!/usr/bin/env python3
"""Regression test for the F-01 remediation (key rotation).

Structure (mirrors the before/after discipline of the pack):
  BEFORE (the failure mode, expected): signing with key A, then
  verifying the old artifact with the rotated key B, fails — and a
  tampered artifact fails with the identical error. This section
  proves the test can detect the failure mode; it is not a vacuous
  pass.
  AFTER (the remediation, all must pass):
    1. The key-identified envelope verifies the old artifact after
       rotation (retired key kept in the registry).
    2. A tampered artifact is refused with the distinct
       ARTIFACT_MISMATCH error.
    3. An envelope naming an unknown key id is refused (UNKNOWN_KEY_ID).
    4. A signature under the wrong key for the named key id is refused
       (INVALID_SIGNATURE).
    5. The envelope signature also verifies under liboqs 0.16.0
       (cross-implementation).
    6. The remediation patch applies cleanly to a fresh copy of
       vulnerable_pipeline.py and the patched caller verifies the old
       artifact after rotation.

Trigger:
  python3 remediation/test_remediation.py [--driver src/pq_driver]

Exit code 0 only if the BEFORE section reproduces the failure mode
AND all AFTER checks pass.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}" + (f" — {detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"FAIL {name}" + (f" — {detail}" if detail else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", default="src/pq_driver")
    a = ap.parse_args()

    import keyed_envelope as env
    import vulnerable_pipeline as pipe

    artifact_v1 = b"release-1.0 tarball bytes (simulated)"
    artifact_v1_tampered = b"release-1.0 tarball bytes (simulated!)"
    artifact_v2 = b"release-2.0 tarball bytes (simulated)"

    print("=== BEFORE (failure mode): rotation without key identifiers ===")
    pk_a, sk_a = pipe.keygen()
    sig_v1 = pipe.sign_artifact(sk_a, artifact_v1)
    check("before_old_artifact_valid_under_signing_key",
          pipe.verify_artifact(pk_a, artifact_v1, sig_v1) == "VALID")
    pk_b, sk_b = pipe.keygen()
    old_after_rotation = pipe.verify_artifact(pk_b, artifact_v1, sig_v1)
    tampered_after_rotation = pipe.verify_artifact(pk_b, artifact_v1_tampered, sig_v1)
    check("before_old_artifact_invalid_after_rotation",
          old_after_rotation == "INVALID",
          "rotation breaks verification of a previously signed artifact")
    check("before_rotation_error_indistinguishable_from_tampering",
          tampered_after_rotation == old_after_rotation == "INVALID",
          "tampered artifact fails with the identical error string")
    before_reproduced = old_after_rotation == "INVALID" and tampered_after_rotation == "INVALID"

    print("=== AFTER (remediation): key-identified envelopes ===")
    envelope_v1 = env.sign_release(sk_a, pk_a, artifact_v1)
    registry = {env.key_id(pk_a): pk_a, env.key_id(pk_b): pk_b}
    try:
        r = env.verify_release(registry, envelope_v1, artifact_v1)
        check("after_old_artifact_verifies_after_rotation", r == "VALID")
    except Exception as e:  # noqa: BLE001
        check("after_old_artifact_verifies_after_rotation", False, repr(e))
    try:
        env.verify_release(registry, envelope_v1, artifact_v1_tampered)
        check("after_tampered_artifact_refused_distinctly", False, "no exception raised")
    except ValueError as e:
        check("after_tampered_artifact_refused_distinctly",
              "ARTIFACT_MISMATCH" in str(e), str(e))
    except Exception as e:  # noqa: BLE001
        check("after_tampered_artifact_refused_distinctly", False, f"wrong exception: {e!r}")
    unknown = dict(envelope_v1)
    unknown["key_id"] = "deadbeefdeadbeef"
    try:
        env.verify_release(registry, unknown, artifact_v1)
        check("after_unknown_key_id_refused", False, "no exception raised")
    except KeyError as e:
        check("after_unknown_key_id_refused", "UNKNOWN_KEY_ID" in str(e), str(e))
    except Exception as e:  # noqa: BLE001
        check("after_unknown_key_id_refused", False, f"wrong exception: {e!r}")
    wrong_key = dict(envelope_v1)
    wrong_key["signature_hex"] = env.sign_release(sk_b, pk_b, artifact_v2)["signature_hex"]
    try:
        env.verify_release(registry, wrong_key, artifact_v1)
        check("after_wrong_key_signature_refused", False, "no exception raised")
    except ValueError as e:
        check("after_wrong_key_signature_refused",
              "INVALID_SIGNATURE" in str(e), str(e))
    except Exception as e:  # noqa: BLE001
        check("after_wrong_key_signature_refused", False, f"wrong exception: {e!r}")
    r = subprocess.run([a.driver, "sig-verify", "ML-DSA-65", pk_a.hex(),
                        artifact_v1.hex(), envelope_v1["signature_hex"]],
                       capture_output=True, text=True)
    check("after_envelope_signature_verifies_under_liboqs", "VALID" in r.stdout)

    # The patch applies cleanly and the patched caller verifies the old
    # artifact after rotation.
    with tempfile.TemporaryDirectory() as td:
        here = os.path.dirname(os.path.abspath(__file__))
        shutil.copy(os.path.join(here, "vulnerable_pipeline.py"),
                    os.path.join(td, "vulnerable_pipeline.py"))
        shutil.copy(os.path.join(here, "keyed_envelope.py"),
                    os.path.join(td, "keyed_envelope.py"))
        patch = os.path.join(here, "remediation.patch")
        r = subprocess.run(["patch", "--dry-run", "-p1", "-i", patch],
                           cwd=td, capture_output=True, text=True)
        check("after_patch_applies_cleanly", r.returncode == 0,
              r.stdout.strip() or r.stderr.strip())
        r = subprocess.run(["patch", "-p1", "-i", patch],
                           cwd=td, capture_output=True, text=True)
        check("after_patch_applied", r.returncode == 0)
        r = subprocess.run([sys.executable, os.path.join(td, "vulnerable_pipeline.py")],
                           cwd=td, capture_output=True, text=True)
        check("after_patched_caller_verifies_old_artifact_after_rotation",
              r.returncode == 0 and "old artifact verifies after rotation: VALID" in r.stdout,
              r.stdout.strip().splitlines()[0] if r.stdout.strip() else r.stderr.strip()[-200:])

    print(f"=== regression test: {PASS} passed, {FAIL} failed ===")
    return 0 if (before_reproduced and FAIL == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
