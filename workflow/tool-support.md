# Release-workflow assessment — named tools, verified 2026-11-09

How a release engineer would actually sign with ML-DSA or SLH-DSA
today, tool by tool. Status is as observed on 2026-11-09; every row
names its source. "Not supported" is a finding, not a gap in the
research.

## Tool support

| Tool | Version checked | ML-DSA | SLH-DSA | Notes |
| --- | --- | --- | --- | --- |
| cosign / Sigstore (keyless) | cosign 3.1.4 (20 Oct 2026) | No | No | Signing algorithms: ECDSA P-224/256/384/521, Ed25519, RSA. PQ plan (Oct 2026 blog): separate ML-DSA infrastructure, production public instance targeted mid-2027, opt-in first. |
| GitHub artifact attestation | current | No | No | Built on Sigstore; verifies P-256, P-384, Ed25519. No PQC option. |
| GnuPG | 2.5.21 (2 Jul 2026) | No | No | 2.5 series adds ML-KEM (FIPS 203) encryption only. No ML-DSA/SLH-DSA signing in any released 2.5.x. 2.4 is end-of-life. |
| minisign | current | No | No | Ed25519 only (EdDSA / HashEdDSA identifiers, 64-byte signatures). No PQC mode. |
| signify (OpenBSD) | current (man page 2026-11-07) | No | No | Single fixed algorithm family (Ed25519); no algorithm selection, no PQC mode. |
| OpenSSL (library) | 3.5 (8 Apr 2025, LTS to 8 Apr 2030) | Yes | Yes | Native ML-KEM, ML-DSA, SLH-DSA in the default provider. This machine runs OpenSSL 3.0.13 — no PQC (verified locally, see environment section). |
| AWS KMS | GA 13 Jun 2025 | Yes | No (announced) | ML-DSA 44/65/87 GA for signing. (Secondary source.) |
| Google Cloud KMS | preview 20 Feb 2025 | Yes (preview) | Yes (preview, 128s) | ML-DSA-65 and SLH-DSA-SHA2-128s preview. (Secondary source.) |
| Go standard library | Go 1.27 (2026) | No (stdlib) | No | crypto/mlkem exists for KEM; no stdlib ML-DSA/SLH-DSA signing. Sigstore waits on Go crypto adoption. |
| Python `cryptography` | not installed on this machine | — | — | Not evaluated locally; check the installed version before relying on it. |

## Key generation and rotation

- ML-DSA key generation is fast (liboqs medians under 0.2 ms for all
  three sets); SLH-DSA key generation is also fast in C (~84–90 ms
  medians here, dominated by the hypertree root computation) but
  ~1.3 s per keypair in the pure-Python reference.
- Rotation is the weak point, not generation: see F-01. A release
  pipeline must record, with every signature, the algorithm, the
  parameter set, and the key identifier — and must retain retired
  public keys in its verification registry. The remediation in
  `remediation/` demonstrates the envelope and registry pattern.
- CNSA 2.0 mandates ML-DSA-87 for National Security Systems and
  excludes SLH-DSA and ML-DSA-44/65 there; the general default is
  ML-DSA-65. The parameter set must therefore be chosen per target
  regime and recorded with the signature (see F-09).

## Artifact-size impact

- Quantified in `outputs/run1/results.json` (artifact_size_impact)
  and on the findings page: SLH-DSA signatures run 7,856–49,856 B
  against ML-DSA's 2,420–4,627 B and Ed25519's 64 B.
- The binding constraint is small artifacts: a 1 KiB manifest signed
  with SLH-DSA-256f carries a signature 48.7x the artifact itself.
  For 5 MiB+ artifacts the overhead is under 1% for every parameter
  set. See F-03.

## Backward compatibility

- A verifier that does not understand ML-DSA/SLH-DSA cannot verify a
  PQC signature at all — there is no graceful downgrade. Dual signing
  (classical + PQC) is the only migration path that keeps old
  verifiers working, and it doubles the signature payload.
- SLH-DSA has no context parameter (FIPS 205 pure signing); ML-DSA
  workflows that bind releases with a context string must re-encode
  that binding when moving to SLH-DSA (see F-08).
- Key formats differ: ML-DSA/SLH-DSA public keys are raw byte strings
  of fixed length (FIPS 204 Table 2 / FIPS 205 Table 2); they are not
  interchangeable with PEM/DER Ed25519 keys, and tools that assume
  fixed 32-byte public keys or 64-byte signatures will reject them.

## Verifier support (summary)

- The primitive is available: OpenSSL 3.5+, liboqs 0.16.0, AWS KMS
  (ML-DSA), and the Python implementations benchmarked here.
- The release-signing *flow* is not: Sigstore/cosign, GitHub artifact
  attestation, GnuPG, minisign and signify all lack a PQC signing
  path today. The gap is in the tools, not the algorithms.
