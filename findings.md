# Findings — Post-Quantum Release-Signing Assessment

Severity-ranked findings from the benchmark and adversarial runs
(`outputs/run1/`, `outputs/run2-clean/`). Every finding is an actually
observed behaviour, with the trigger command and the evidence location
given. Where the implementations behave correctly, that is stated as a
verified-behaviour finding rather than a weakness. The ONE reproduced
release-signing failure mode is F-01; it is new and is not the
dilithium-py deterministic-signing finding from the earlier lattice
benchmark work (that work concerned FIPS 204 hedged signing inside one
library; this one concerns release-workflow key management).

## F-01 — Medium: key rotation without key identifiers breaks verification of previously signed release artifacts, and the failure is indistinguishable from tampering

**Observed.** The naive release pipeline (`remediation/vulnerable_pipeline.py`)
signs with the current key and verifies with the current key only;
signatures carry no key identifier. After rotating the release key from A
to B, the untouched Release 1.0 artifact fails verification under key B
(`INVALID`) — and a tampered Release 1.0 artifact fails with the byte-identical
`INVALID`. The artifact itself is intact (its SHA-256 is unchanged), but
the pipeline gives the operator no way to distinguish "the key rotated"
from "the artifact was modified". Reproduced by
`remediation/reproduce_weakness.py` (exit 0, "REPRODUCED").

**Why it matters.** Release keys rotate — compromise, scheduled rotation,
personnel change. Without a key identifier, every rotation silently
invalidates every previously signed artifact, and the only observable
signal is the same generic failure a tampered artifact produces. An
operator who "fixes" this by re-signing old artifacts under the new key
destroys the audit trail; one who ignores it trains users to distrust
verification failures.

**Remediation (tested).** `remediation/keyed_envelope.py` publishes each
signature inside an envelope `{alg, key_id, artifact_sha256,
signature_hex}` where `key_id` is the first 16 hex chars of
SHA-256(public key), and the verifier keeps a registry of current AND
retired public keys, selecting by `key_id`. Failures are distinct:
`UNKNOWN_KEY_ID`, `ARTIFACT_MISMATCH`, `INVALID_SIGNATURE`. The patch
(`remediation/remediation.patch`) converts the vulnerable pipeline to
the envelope form. The regression test
(`remediation/test_remediation.py`, `outputs/run1/remediation-after.log`)
reproduces the failure in its BEFORE section and passes all 11 checks
AFTER (11 passed, 0 failed): the old artifact verifies after rotation, a tampered artifact is
refused with `ARTIFACT_MISMATCH`, an unknown key id is refused, a
signature under the wrong key for the named key id is refused
(`INVALID_SIGNATURE`), and the envelope signature also verifies under
liboqs 0.16.0.

**Severity: Medium.** No key material is exposed and the signature
scheme itself is sound; but the failure mode silently breaks the
verification of all prior releases on every rotation, which is exactly
the event a release pipeline must survive.

## F-02 — Medium: Sigstore/cosign and GitHub artifact attestation have no post-quantum signing path today

**Observed.** Sigstore's supported signing algorithms are ECDSA
(P-224/256/384/521), Ed25519, and RSA-PKCS#1v1.5/RSA-PSS (Sigstore
POLICY.md: "Sigstore does not yet have a stance on which PQ signing
algorithms will be supported... We will add support for PQ signing
algorithms once the Golang crypto package adopts these signing
algorithms"). GitHub artifact attestation is built on Sigstore and
verifies the same algorithm set (P-256, P-384, Ed25519). Sigstore's
October 2026 post-quantum plan describes a separate ML-DSA-based
infrastructure with its own TUF root, targeting a production-ready
public instance for mid-2027, opt-in at first, with the classical
instance supported until a turndown tentatively set for 2029 or 2030.
cosign 3.1.4 (20 October 2026) ships no ML-DSA or SLH-DSA signing.

**Why it matters.** The standard keyless release-signing flow cannot
produce a post-quantum signature today. A release engineer who wants
ML-DSA-signed artifacts must step outside the attestation flow (own
keys, own verification) and loses the transparency-log and keyless
identity properties that make the flow valuable.

**Severity: Medium.** A dated plan exists (mid-2027) and the classical
flow remains supported, so this is a capability gap with a timeline,
not a dead end — but any PQC release-signing design shipped before
then must not assume Sigstore will carry it.

## F-03 — Medium: SLH-DSA signatures are large enough to dominate small release artifacts

**Observed.** Signature sizes (verified against FIPS 205 Table 2):
SLH-DSA-SHA2-128s 7,856 B; 128f 17,088 B; 192s 16,224 B; 192f 35,664 B;
256s 29,792 B; 256f 49,856 B (SHAKE variants identical). Against a
64-byte Ed25519 signature that is 123x (128s) to 779x (256f); against
ML-DSA-87 (4,627 B) it is 1.7x (128s) to 10.8x (256f). Against
representative release artifacts (`outputs/run1/results.json`,
artifact_size_impact): a 1 KiB release manifest carries 767% overhead
for 128s and 4,869% (48.7x the artifact) for 256f; a 100 KiB wheel
carries 7.7% (128s) to 48.7% (256f); a 5 MiB tarball 0.15% to 0.95%;
a 50 MiB binary 0.015% to 0.095%.

**Why it matters.** For the artifacts that most need signing — small
manifests, checksum lists, SBOMs — the SLH-DSA signature is the
artifact, not an annotation on it. Signature-size limits in
distribution channels (package indexes, registries, embedded
firmware slots) that were written for 64-byte signatures will reject
or truncate 49 KiB signatures. ML-DSA is the size-sane default for
release signing; SLH-DSA is justifiable only where its conservative
hash-based security is specifically required.

**Severity: Medium.** A sizing and channel-compatibility constraint,
not a correctness issue — but it changes which algorithm a release
pipeline can actually deploy.

## F-04 — Low: GnuPG 2.5.x adds post-quantum encryption (ML-KEM) but no post-quantum signing

**Observed.** The GnuPG 2.5 series (current 2.5.21, 2 July 2026)
introduces "Kyber (aka ML-KEM or FIPS-203) as PQC encryption
algorithm" (lists.gnupg.org announcements for 2.5.19/2.5.20/2.5.21).
No released 2.5.x version supports ML-DSA or SLH-DSA signatures;
OpenPGP release signing remains RSA/EdDSA. The 2.4 series has reached
end-of-life, so the supported GnuPG is 2.5.x — which still cannot sign
with a post-quantum algorithm.

**Why it matters.** Teams that sign releases with GPG (detached
`.asc`/`.sig` files, the oldest release-signing workflow) have no
upgrade path to PQC signatures inside GnuPG; migration means changing
the signing tool, not just the key type.

## F-05 — Low: minisign and signify are Ed25519-only by design, with no post-quantum migration path

**Observed.** minisign implements the minisign scheme on Ed25519
(`EdDSA` / `HashEdDSA` algorithm identifiers, 64-byte signatures;
pkg.go.dev minisign package). signify(1) (OpenBSD) signs checksum
lists and files with a single fixed algorithm family and offers no
algorithm selection. Neither tool has a post-quantum mode, and neither
project has announced one. Both remain correct and useful for
classical signing; they simply cannot be the vehicle for a PQC
release signature.

**Why it matters.** Lightweight release signing (OpenBSD releases,
small projects, checksum-list signing) has no drop-in PQC replacement
in the same tools. Adopters must either keep classical signatures
alongside PQC ones (dual signing) or switch tools entirely.

## F-06 — Low: pure-Python SLH-DSA is three to four orders of magnitude slower than liboqs

**Observed.** slh-dsa 0.2.5 (pure Python) signing medians (n=1,
`outputs/run1/results.json`): SHA2-128s 5.07 s, SHA2-256s 8.06 s per
signature, against liboqs 0.16.0 medians of 0.67 s (128s) and 1.05 s
(256s) on this machine — and liboqs itself is running its reference
(non-AVX2) path here. Key generation in slh-dsa takes ~1.2–2.0 s per
keypair for the "s" sets (20–85 ms for the "f" sets). Verification is
fast in both (5.5–24.1 ms pure Python vs 0.7–4.8 ms liboqs). The
slh-dsa package is a correct second implementation (its signatures
verify under liboqs and vice versa for all 12 sets), but it is a
reference/educational implementation, not a signing engine.

**Why it matters.** A release pipeline that signs with a pure-Python
SLH-DSA implementation would take minutes to sign a release with many
artifacts; the C implementation is mandatory for production use, and
the "s" (small-signature) parameter sets are the slowest to sign.

## F-07 — Low: the machine a release engineer uses today may not have post-quantum-capable OpenSSL

**Observed.** This machine runs OpenSSL 3.0.13 (30 January 2024);
`openssl list -signature-algorithms` contains neither ML-DSA nor
SLH-DSA (recorded in `outputs/run1/results.json`, environment, and in
`outputs/run1/benchmark-run.log`). OpenSSL added native ML-KEM, ML-DSA
and SLH-DSA in 3.5 (8 April 2025, LTS to 8 April 2030). Any release
tooling linked against the OS OpenSSL (3.0.x on this machine) cannot
produce or verify PQC signatures until the library is upgraded — and
the FIPS-validated OpenSSL module is still 3.1.2, which predates PQC.

**Why it matters.** "Upgrade OpenSSL" is a prerequisite step that is
easy to miss: the algorithms exist in the standard and in the library,
but not necessarily in the library a given build or signing host links
against. The runnable check is `openssl version` plus
`openssl list -signature-algorithms | grep -E 'ML-DSA|SLH-DSA'`.

## F-08 — Low (verified behaviour, no weakness): cross-implementation agreement holds for all 15 signature parameter sets

**Observed.** ML-DSA: dilithium-py signatures verify under liboqs and
liboqs signatures verify under dilithium-py for all 3 sets.
SLH-DSA: slh-dsa (pure Python, FIPS 205 pure signing) signatures
verify under liboqs and liboqs signatures verify under slh-dsa for all
12 sets (`outputs/run1/results.json`, cross_implementation; all
`True`). Adversarial behaviour is consistent across implementations:
flipped signatures and wrong messages fail verification everywhere;
truncated signatures are refused (liboqs driver length check) or
return False (Python); wrong-parameter-set keys are refused; a 300-byte
ML-DSA context is refused by both implementations. Note for migrators:
SLH-DSA has no context parameter — FIPS 205 pure signing takes no
`ctx`, so an ML-DSA workflow that binds releases with `ctx` must drop
or re-encode that binding when moving to SLH-DSA.

## F-09 — Low: parameter choice depends on the compliance regime — CNSA 2.0 mandates ML-DSA-87 and excludes SLH-DSA

**Observed.** CNSA 2.0 mandates ML-DSA-87 specifically for National
Security Systems; ML-DSA-44, ML-DSA-65, HashML-DSA and SLH-DSA are all
excluded for that regime (Red Hat OpenShift PQC blog, 2026, citing
CNSA 2.0). NIST's general guidance treats ML-DSA-65 as the default
and SLH-DSA as the conservative backup. A release pipeline that picks
ML-DSA-65 as "the default" is not CNSA 2.0-compliant for NSS use, and
one that picks SLH-DSA for its conservative security is excluded from
NSS entirely. (Secondary source; see citations.md.)

**Why it matters.** There is no single "right" parameter set: the
choice must be driven by the target regime, and the choice must be
recorded with the signature (see F-01) because different regimes will
accept different parameter sets.
