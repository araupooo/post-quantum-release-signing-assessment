# Claims — Post-Quantum Release-Signing Assessment

Each claim maps to the runnable script and unedited output that proves
it. Documentary claims (tool support) map to the cited primary source
plus the local runnable check where one exists. Timing medians and
peak-RSS values vary between runs by design and are reported, not
asserted equal (see README.md, comparison rule).

## Benchmark claims

- C-01: liboqs 0.16.0 reports the FIPS 204 Table 2 key/signature sizes
  for ML-DSA-44/65/87 and the FIPS 205 Table 2 sizes for all 12
  SLH-DSA parameter sets. Evidence: src/benchmark.py section 0,
  outputs/run1/benchmark-run.log (SIZE lines), outputs/run1/results.json
  (sizes_verified, all match=true).
- C-02: dilithium-py 1.5.1 produces the FIPS 204 Table 2 sizes for
  ML-DSA-44/65/87. Evidence: src/benchmark.py section 0,
  outputs/run1/benchmark-run.log (SIZE dilithium-py lines).
- C-03: slh-dsa 0.2.5 produces the FIPS 205 Table 2 sizes for all 12
  SLH-DSA parameter sets. Evidence: src/benchmark.py section 0,
  outputs/run1/benchmark-run.log (SIZE slh-dsa lines).
- C-04: Throughput medians per parameter set and implementation are as
  tabulated in docs/index.html and outputs/run1/results.json
  (throughput). Evidence: src/benchmark.py sections 1–2,
  outputs/run1/benchmark-run.log (TIMING lines).
- C-05: Peak RSS (VmHWM) per parameter set and implementation is as
  tabulated in outputs/run1/results.json (memory_kb). Evidence:
  src/benchmark.py sections 1–2, outputs/run1/benchmark-run.log
  (peak_rss_kb values).
- C-06: Cross-implementation agreement holds in both directions for
  all 15 signature parameter sets (ML-DSA dilithium-py <-> liboqs;
  SLH-DSA slh-dsa <-> liboqs). Evidence: src/benchmark.py section 5,
  outputs/run1/benchmark-run.log (XIMPL lines, all True),
  outputs/run1/results.json (cross_implementation).
- C-07: Adversarial inputs behave as documented for every parameter
  set and implementation (flipped/wrong-message signatures fail;
  truncated signatures refused or False; wrong-parameter-set keys
  refused; 300-byte ML-DSA context refused). Evidence:
  src/benchmark.py sections 3–4, outputs/run1/benchmark-run.log
  (ADV lines), outputs/run1/results.json (adversarial).
- C-08: SLH-DSA has no context parameter; FIPS 205 pure signing takes
  no ctx, while ML-DSA accepts a context of up to 255 bytes.
  Evidence: FIPS 204 section 3.4 / FIPS 205 section 8.2 (see
  citations.md); src/benchmark.py sections 3–4 (ML-DSA ctx cases;
  no ctx case exists for SLH-DSA because the interface has none).
- C-09: Signature-size overhead vs representative release artifacts
  is as tabulated in docs/index.html (e.g. SLH-DSA-256f is 49,856 B:
  4,869% of a 1 KiB manifest, 48.7% of a 100 KiB wheel, 0.95% of a
  5 MiB tarball). Evidence: src/benchmark.py section 7,
  outputs/run1/results.json (artifact_size_impact), computed from the
  verified FIPS 205 Table 2 sizes.

## Failure-mode claims

- C-10: The key-rotation failure mode (F-01) reproduces: after
  rotating the release key, an intact previously signed artifact
  fails verification, and a tampered artifact fails with the identical
  error. Evidence: remediation/reproduce_weakness.py,
  outputs/run1/remediation-before.log (ends REPRODUCED, exit 0).
- C-11: The keyed-envelope remediation fixes it: the old artifact
  verifies after rotation, a tampered artifact is refused with the
  distinct ARTIFACT_MISMATCH error, an unknown key id is refused
  (UNKNOWN_KEY_ID), and a wrong-key signature is refused
  (INVALID_SIGNATURE). Evidence: remediation/keyed_envelope.py,
  remediation/test_remediation.py,
  outputs/run1/remediation-after.log (regression test: all passed,
  0 failed).
- C-12: Envelope signatures verify under liboqs 0.16.0 as well as
  dilithium-py. Evidence: remediation/test_remediation.py
  (after_envelope_signature_verifies_under_liboqs),
  outputs/run1/remediation-after.log.

## Workflow claims

- C-13: Sigstore/cosign and GitHub artifact attestation have no
  post-quantum signing path today; Sigstore's ML-DSA plan targets a
  production public instance for mid-2027. Evidence:
  workflow/tool-support.md (Sigstore POLICY.md quote + Sigstore
  October 2026 PQC plan summary); citations.md.
- C-14: GnuPG 2.5.x supports ML-KEM encryption but no ML-DSA/SLH-DSA
  signing; minisign and signify are Ed25519-only. Evidence:
  workflow/tool-support.md (GnuPG 2.5.21 announcement; minisign
  package docs; signify(1)); citations.md.
- C-15: OpenSSL added native ML-DSA/SLH-DSA in 3.5 (8 April 2025);
  this machine runs OpenSSL 3.0.13, which lists neither algorithm.
  Evidence: src/benchmark.py section 8 (runnable local check),
  outputs/run1/benchmark-run.log (ENV lines),
  outputs/run1/results.json (environment); OpenSSL 3.5 release
  announcement (citations.md).
- C-16: A clean reproduction from a fresh copy matches run1 on every
  deterministic field. Evidence: scripts/clean_reproduce.sh,
  outputs/run-comparison.log (ends MATCH),
  outputs/run2-clean/benchmark-run.log.
- C-17: SHA-256 digests verify for all shippable files.
  Evidence: scripts/verify_digests.sh, SHA256SUMS
  (docs/index.html excluded as a generated page; see README.md).
