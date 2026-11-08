# Post-Quantum Release-Signing Assessment

Reproducible ML-DSA / SLH-DSA assessment for software release signing,
across pinned liboqs 0.16.0 (C), dilithium-py 1.5.1 and slh-dsa 0.2.5
(pure Python), with adversarial-input behaviour, a named-tool
release-workflow assessment, one reproduced release-signing failure
mode and a tested remediation.

- **Rendered findings page:** https://araupooo.github.io/post-quantum-release-signing-assessment/
- **Assessed revision:** `8eac20398dd9eb190790c19c5f256f7dbdf37d4e` (local pack git HEAD at final validation; the
  revision whose contents were benchmarked and verified — see below)

## What this pack is

- **Benchmarks**: ML-DSA-44/65/87 and all 12 FIPS 205 SLH-DSA
  parameter sets — keygen / sign / verify throughput (median per
  operation), peak RSS per operation, key and signature sizes
  verified against FIPS 204 Table 2 and FIPS 205 Table 2, and
  adversarial-input behaviour (flipped, truncated and
  wrong-parameter-set inputs; ML-DSA context cases), for every
  implementation that runs on this machine.
- **The one failure mode (F-01)**: key rotation without key
  identifiers breaks verification of previously signed release
  artifacts, and the failure is indistinguishable from tampering.
  Reproduced in `remediation/reproduce_weakness.py`; remediated by
  the key-identified signature envelope in
  `remediation/keyed_envelope.py` (registry of current + retired
  keys, distinct failure errors), with the patch in
  `remediation/remediation.patch` and a regression test in
  `remediation/test_remediation.py` that reproduces the failure
  before the fix and passes after it.
- **Release-workflow assessment**: `workflow/tool-support.md` names
  the current post-quantum status of cosign/Sigstore, GitHub artifact
  attestation, GnuPG, minisign, signify, OpenSSL, AWS KMS, Google
  Cloud KMS, and the Go standard library — each verified against its
  own documentation or announcement on 2026-11-09.
- **Claim-to-evidence index**: `claims.md` maps every claim to the
  script and output file that proves it. **Findings**: `findings.md`,
  severity ranked. **Sources**: `citations.md`.

This pack does **not** reuse the earlier dilithium-py hedged-signing
finding: that work concerned FIPS 204 deterministic signing inside
one library. The failure mode here is a release-workflow key
management failure (rotation without key identifiers), and the
benchmarks cover all 15 signature parameter sets including SLH-DSA,
which the earlier packs did not touch.

## How to run it

```sh
bash scripts/run_all.sh            # full rebuild + benchmark into outputs/run1/
bash scripts/clean_reproduce.sh    # fresh-copy re-run into outputs/run2-clean/ + comparison
bash scripts/verify_digests.sh     # SHA-256 check over all shippable files
```

Requirements: gcc, cmake, make, python3 (>= 3.10), OpenSSL dev headers
(`libssl-dev`) for `-lcrypto`, ~500 MB free disk for the liboqs build.
No network access is needed: all sources are bundled under `src/`
(liboqs tarball, both Python wheels, FIPS 203/204/205 PDFs) and their
SHA-256 digests are verified at the start of every run.

## Results (run1)

See `outputs/run1/results.json` for the full machine-readable results
and `docs/index.html` for the rendered findings page. Headline numbers
(medians, run1):

- **ML-DSA throughput (liboqs vs dilithium-py, median ms)**: 44 —
  keygen 0.032/7.17, sign 0.080/34.50, verify 0.035/8.58; 65 —
  0.056/11.64, 0.131/82.73, 0.057/13.39; 87 — 0.080/17.92,
  0.140/87.45, 0.081/20.71. Peak RSS: liboqs ~5.7–6.1 MB,
  dilithium-py ~20.0–20.8 MB.
- **SLH-DSA throughput (liboqs, median ms)**: signing is slow in the
  reference path on this machine — SHA2-128s 672 ms, SHA2-192s
  1,173 ms, SHA2-256s 1,048 ms, SHAKE-192s 2,008 ms per signature
  (n=20); the "f" variants are 32–182 ms; verification 0.7–4.8 ms.
  slh-dsa (pure Python, n=1 indicative) signs SHA2-128s in 5.07 s
  and SHA2-256s in 8.06 s. Peak RSS: liboqs ~5.7–6.1 MB,
  slh-dsa ~20.5–20.9 MB.
- **Sizes**: all verified against FIPS 204 Table 2 / FIPS 205 Table 2
  (ML-DSA signatures 2,420–4,627 B; SLH-DSA signatures 7,856–49,856 B).
- **Artifact-size impact**: SLH-DSA-256f (49,856 B) is 4,869% of a
  1 KiB release manifest, 48.7% of a 100 KiB wheel, 0.95% of a 5 MiB
  tarball.
- **Adversarial behaviour**: flipped signatures, wrong messages and
  wrong-parameter-set keys fail or are refused in every
  implementation and parameter set; truncated signatures are refused
  (liboqs driver length check) or return False (Python); a 300-byte
  ML-DSA context is refused by both implementations.
- **Cross-implementation agreement**: liboqs <-> dilithium-py
  (ML-DSA) and liboqs <-> slh-dsa (SLH-DSA) signatures verify in both
  directions for all 15 parameter sets.
- **Environment**: this machine runs OpenSSL 3.0.13, which lists
  neither ML-DSA nor SLH-DSA — PQC needs OpenSSL 3.5+.

## Comparison rule (why run1 and run2-clean logs differ)

`scripts/clean_reproduce.sh` re-runs everything from a fresh copy and
compares the deterministic fields of run1 and run2-clean with
`src/compare_runs.py`. Compared (must be equal): sizes, adversarial
outcomes, cross-implementation outcomes, determinism booleans,
artifact-size ratios, environment facts, and the remediation verdicts
(`REPRODUCED` in remediation-before.log, `0 failed` in
remediation-after.log). Timing medians and peak-RSS values are
reported in both runs but are NOT asserted equal — they vary between
runs by design. Test keys are generated fresh per run, so digests of
keys/signatures also differ and are excluded.

## Honest limitations

- **No Rust or Go implementations**: this machine has no cargo/rustc
  or Go toolchain, so the benchmark matrix covers C (liboqs) and
  Python only. The brief scoped the matrix to available
  implementations; the omission is recorded here and in
  evidence.json, not hidden.
- **slh-dsa throughput is n=1** (one timed sample per parameter set):
  the pure-Python signer takes seconds per signature, so a larger n
  would make the run take tens of minutes. The n=1 figures are
  indicative only; the correctness and cross-implementation results
  do not depend on n.
- **slh-dsa 0.2.5 is a small single-author package** (Colinxu2020).
  It is used here only as a second implementation, and only because
  its FIPS 205 pure-signing output verifies under liboqs and vice
  versa for all 12 parameter sets. It is not endorsed as a production
  signer.
- **Tool-support rows are documentary findings** verified against
  each tool's own documentation/announcement on 2026-11-09 (see
  citations.md). They are not produced by a runnable script; the one
  runnable tool-support check in this pack is the local OpenSSL
  version/algorithm check in `src/benchmark.py` section 8.
- **liboqs SLH-DSA runs its reference path on this machine**: signing
  medians (~0.7–1.0 s for the "s" sets) reflect the software SHA-256
  path, not an AVX2/SHA-NI accelerated build. Numbers from a machine
  with hardware SHA extensions will be lower.
- **No fault injection was performed** for the F-01 failure mode's
  remediation: the envelope pattern is a workflow fix, not a
  cryptographic one, and the regression test covers the workflow
  behaviour (rotation, tampering, unknown key id, wrong key).
- **The rendered page (`docs/index.html`) is generated** from
  `outputs/run1/results.json` plus findings.md, claims.md and
  workflow/tool-support.md, so it is excluded from SHA256SUMS (its own
  digest row would be self-referential). All other shippable files
  are covered by SHA256SUMS.
