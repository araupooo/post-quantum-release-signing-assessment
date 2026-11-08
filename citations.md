# Citations — Post-Quantum Release-Signing Assessment

Primary sources first. Every measured or spec-derived claim in this
pack cites one of the bundled standards or a named implementation
document; tool-support claims cite the tool's own documentation or
announcement. Secondary sources are flagged as such.

## Standards (bundled under src/)

- NIST FIPS 204, "Module-Lattice-Based Digital Signature Standard
  (ML-DSA)", August 2024. Bundled: src/FIPS.204.pdf (SHA-256
  57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b).
  Cited for: ML-DSA parameter sets and sizes (Table 2), hedged vs
  deterministic signing (section 3.4), context rules (section 3.4:
  ctx up to 255 bytes), verification length rules (section 3.6.2).
- NIST FIPS 205, "Stateless Hash-Based Digital Signature Standard
  (SLH-DSA)", August 2024. Bundled: src/FIPS.205.pdf (SHA-256
  8ef34228276f3386d23cb0da8c14592b8cfb0db3358016bba64df7a004f8d13d).
  Cited for: all 12 SLH-DSA parameter sets and sizes (Table 2),
  pure vs pre-hash signing (section 8), key sizes (section 7:
  secret key is 4n bytes), the 2^64 signature limit per key pair.
- NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
  Standard (ML-KEM)", August 2024. Bundled: src/FIPS.203.pdf
  (SHA-256 fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac).
  Cited for reference only (ML-KEM is not benchmarked in this pack).

## Implementations

- liboqs 0.16.0, Open Quantum Safe. Bundled tarball:
  src/liboqs-0.16.0.tar.gz (SHA-256
  162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae).
  SLH-DSA algorithm identifiers (SLH_DSA_PURE_SHA2_128S, ...) are
  from src/sig/sig.h in the bundled source; the FIPS 205 names used
  in this pack are translated in src/pq_driver.c.
- dilithium-py 1.5.1 (PyPI). Bundled wheel:
  src/dilithium_py-1.5.1-py3-none-any.whl (SHA-256
  21ab0cbd56e959d22b9dca59bd8af0e2a6f73703b14ad71d483ecf70438c73d7).
- slh-dsa 0.2.5 (PyPI, author Colinxu2020,
  https://github.com/colinxu2020/slhdsa). Bundled wheel:
  src/slh_dsa-0.2.5-py3-none-any.whl (SHA-256
  9d8292a4b606085089fedbe526d26c8036e9a57da43b67ac3e97f44545e6bd9d).
  The package's own documentation states that `sign_pure` /
  `verify_pure` "fully compl[y] with the final version of the FIPS 205
  specification" while `sign` / `verify` implement "the SLH-DSA
  Initial Draft"; this pack uses only the `_pure` API. Its
  correctness is verified empirically here by cross-implementation
  agreement with liboqs for all 12 parameter sets.

## Release tools (checked 2026-11-09)

- Sigstore, "Cryptographic Algorithms / KMS Policy" (POLICY.md):
  https://raw.githubusercontent.com/dnwe/sigstore/main/POLICY.md —
  supported signing algorithms (ECDSA P-224/256/384/521, Ed25519,
  RSA-PKCS#1v1.5/RSA-PSS) and the post-quantum section ("Sigstore
  does not yet have a stance on which PQ signing algorithms will be
  supported... once the Golang crypto package adopts these signing
  algorithms").
- Sigstore post-quantum plan (2 October 2026), as summarized in
  https://revisit.tech/blog/container-image-signing-in-2026-revisit-cosign-notation-and-in-toto-attestations-before-you-trust-another-image-tag/
  and https://www.ajayk.sh/blog/sigstore-artifact-signing-explained-2026/
  (secondary summaries): separate ML-DSA infrastructure with its own
  TUF root; production PQC public instance targeted mid-2027, opt-in
  at first; classical instance supported until a turndown tentatively
  set for 2029 or 2030. cosign 3.1.4 released 20 October 2026.
- OpenSSL 3.5 final release announcement (8 April 2025):
  https://openssl-library.org/post/2025-04-08-openssl-35-final-release/
  — "Support for PQC algorithms (ML-KEM, ML-DSA and SLH-DSA)";
  LTS supported until 8 April 2030.
- GnuPG 2.5.19 / 2.5.20 / 2.5.21 release announcements,
  https://lists.gnupg.org/pipermail/gnupg-announce/ — "the
  introduction of Kyber (aka ML-KEM or FIPS-203) as PQC encryption
  algorithm" as the main feature of the 2.5 series; no ML-DSA/SLH-DSA
  signing announced. 2.4 series end-of-life.
- minisign package documentation, https://pkg.go.dev/github.com/deviswar/slifork/server/cryptography/minisign
  (Go package docs for the minisign scheme): EdDSA / HashEdDSA
  algorithm identifiers, Ed25519 signatures.
- signify(1), OpenBSD manual pages, https://man.openbsd.org/signify
  (crawled 2026-11-07): the tool's interface; single fixed algorithm
  family, no algorithm selection.
- GitHub artifact attestation / Sigstore verification algorithms:
  Sigstore verification supports P-256, P-384, Ed25519 (see
  https://deepwiki.com/jdx/sigstore-verification/6.2-cryptographic-signature-verification,
  secondary summary of the verification library).
- CNSA 2.0 parameter mandate (ML-DSA-87 for National Security
  Systems; ML-DSA-44/65, HashML-DSA and SLH-DSA excluded): Red Hat,
  "2026 update: The road to quantum-safe cryptography in Red Hat
  OpenShift", https://www.RedHat.com/en/blog/road-to-quantum-safe-cryptography-red-hat-openshift
  (secondary source).
- AWS KMS ML-DSA general availability (13 June 2025) and Google
  Cloud KMS ML-DSA/SLH-DSA preview (20 February 2025): as reported
  in https://signmycode.com/blog/post-quantum-code-signing-what-developers-need-to-know-for-the-quantum-era/
  (secondary source).
- RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)",
  IETF, January 2017: Ed25519 fixed 64-byte signatures, 32-byte
  public keys (used for the size comparison baseline).
