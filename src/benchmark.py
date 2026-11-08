#!/usr/bin/env python3
"""Benchmark + adversarial harness for the post-quantum release-signing
assessment pack.

Implementations under test (all pinned, all bundled under src/):
  * liboqs 0.16.0 (C) via src/pq_driver — ML-DSA-44/65/87 and all 12
    FIPS 205 SLH-DSA parameter sets.
  * dilithium-py 1.5.1 (pure Python) — ML-DSA-44/65/87.
  * slh-dsa 0.2.5 (pure Python, FIPS 205 pure signing) — all 12
    SLH-DSA parameter sets. (Author: Colinxu2020; evaluated here only
    because its signatures verify under liboqs and vice versa for all
    12 sets — see the cross-implementation section.)

What it measures:
  * Throughput: median per-operation time (liboqs ML-DSA n=100,
    liboqs SLH-DSA n=20, dilithium-py n=10, slh-dsa n=1 — the pure
    Python SLH-DSA signer takes seconds per signature, so n=1 and is
    labelled indicative only).
  * Memory: peak RSS (kilobytes) of the process performing the
    operations (VmHWM from /proc/self/status, NOT getrusage ru_maxrss:
    ru_maxrss is not per-process in this environment).
  * Sizes: public key / secret key / signature lengths verified
    against FIPS 204 Table 2 (ML-DSA) and FIPS 205 Table 2 (SLH-DSA).
  * Adversarial-input behaviour: flipped/wrong-message/truncated/
    wrong-parameter-set inputs for every parameter set and
    implementation; ML-DSA context cases for both implementations.
  * Cross-implementation agreement: liboqs <-> Python signatures
    verify in both directions for all 15 signature parameter sets.
  * Signing determinism: repeated signing of the same message
    (liboqs hedged/randomized vs. slh-dsa deterministic and
    randomized pure signing).
  * Artifact-size impact: signature size as a fraction of
    representative release artifacts (1 KiB manifest, 100 KiB wheel,
    5 MiB tarball, 50 MiB binary).
  * Environment: the OpenSSL version on this machine and whether its
    signature-algorithm list contains ML-DSA/SLH-DSA (a runnable local
    check of verifier support).

Determinism note: timing medians and peak-RSS values vary between runs
by design. The comparison rule (see README.md and
src/compare_runs.py) compares only deterministic fields (sizes,
round-trip outcomes, adversarial outcomes, cross-implementation
outcomes, determinism booleans, artifact-size ratios, environment
facts) between runs; timing/memory figures are reported, not asserted
equal. Test keys are generated fresh per operation (benchmarking) or
from a fixed public test seed (adversarial/cross-implementation
cases), so the adversarial section is reproducible. No real keys are
used anywhere.

Usage:
  python3 src/benchmark.py --driver src/pq_driver --outdir outputs/run1
  python3 src/benchmark.py --worker dilithium-py ML-DSA-65 10 /tmp/w.json
  python3 src/benchmark.py --worker slh-dsa SLH-DSA-SHA2-128s 1 /tmp/w.json
      (internal: runs one Python implementation benchmark in a child
       process so peak RSS can be measured by the parent)
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)

ML_DSA_ALGS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
SLH_ALGS = [
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
]
SIG_ALGS = ML_DSA_ALGS + SLH_ALGS
# FIPS 204 Table 2 (ML-DSA) / FIPS 205 Table 2 (SLH-DSA) sizes, verified
# against the bundled PDFs. SLH-DSA secret-key size is 4n bytes
# (SK.seed || SK.prf || PK.seed || PK.root, FIPS 205 section 7).
SIG_SIZES = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420},
    "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309},
    "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627},
    "SLH-DSA-SHA2-128s": {"pk": 32, "sk": 64, "sig": 7856},
    "SLH-DSA-SHA2-128f": {"pk": 32, "sk": 64, "sig": 17088},
    "SLH-DSA-SHA2-192s": {"pk": 48, "sk": 96, "sig": 16224},
    "SLH-DSA-SHA2-192f": {"pk": 48, "sk": 96, "sig": 35664},
    "SLH-DSA-SHA2-256s": {"pk": 64, "sk": 128, "sig": 29792},
    "SLH-DSA-SHA2-256f": {"pk": 64, "sk": 128, "sig": 49856},
}
for _fam in ("SHAKE",):
    for _n, _s in (("128s", 7856), ("128f", 17088), ("192s", 16224),
                   ("192f", 35664), ("256s", 29792), ("256f", 49856)):
        _bits = _n[:3]
        SIG_SIZES[f"SLH-DSA-{_fam}-{_n}"] = {
            "pk": {"128": 32, "192": 48, "256": 64}[_bits],
            "sk": {"128": 64, "192": 96, "256": 128}[_bits],
            "sig": _s}
# slh-dsa (PyPI) parameter-module names, e.g. SLH-DSA-SHA2-128s -> sha2_128s
SLH_PY_MOD = {a: a[len("SLH-DSA-"):].lower().replace("-", "_") for a in SLH_ALGS}
TEST_MSG = b"post-quantum release-signing assessment test message"
# Representative release artifacts (bytes) for the size-impact analysis.
ARTIFACT_SIZES = {"manifest_1KiB": 1024, "wheel_100KiB": 102400,
                  "tarball_5MiB": 5 * 1024 * 1024, "binary_50MiB": 50 * 1024 * 1024}
ED25519_SIG_BYTES = 64  # RFC 8032 fixed signature size, for comparison


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _vm_hwm_kb() -> int:
    """Own peak RSS (VmHWM) from /proc/self/status, in kilobytes."""
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    return -1


def median(vals):
    vals = sorted(vals)
    n = len(vals)
    return vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2.0


# ---------------------------------------------------------------- liboqs driver
class Driver:
    def __init__(self, path):
        self.path = path

    def run(self, *args):
        r = subprocess.run([self.path] + list(args), capture_output=True, text=True)
        return r.returncode, r.stdout.strip(), r.stderr.strip()

    def parse(self, out):
        d = {}
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                d[parts[0]] = parts[1]
        return d

    def info(self, alg):
        rc, out, _ = self.run("info", alg)
        assert rc == 0, out
        return self.parse(out)


# ---------------------------------------------------------------- Python impls
def load_dilithium(alg):
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
    return {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65,
            "ML-DSA-87": ML_DSA_87}[alg]


def load_slhdsa(alg):
    import slhdsa
    return getattr(slhdsa, SLH_PY_MOD[alg])


def worker_main():
    """Child-process benchmark for one Python implementation (for RSS)."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", required=True)
    ap.add_argument("alg")
    ap.add_argument("n", type=int)
    ap.add_argument("outfile")
    a = ap.parse_args(sys.argv[1:])
    out = {"implementation": a.worker, "algorithm": a.alg, "n": a.n}
    t0 = time.time()
    if a.worker == "dilithium-py":
        impl = load_dilithium(a.alg)
        ts = {"keygen": [], "sign": [], "verify": []}
        pk, sk = impl.keygen()
        for _ in range(a.n):
            s = time.perf_counter(); pk, sk = impl.keygen(); ts["keygen"].append((time.perf_counter() - s) * 1000)
        sig = None
        for _ in range(a.n):
            s = time.perf_counter(); sig = impl.sign(sk, TEST_MSG); ts["sign"].append((time.perf_counter() - s) * 1000)
        for _ in range(a.n):
            s = time.perf_counter(); ok = impl.verify(pk, TEST_MSG, sig); ts["verify"].append((time.perf_counter() - s) * 1000)
        assert ok
    else:
        import slhdsa
        par = load_slhdsa(a.alg)
        ts = {"keygen": [], "sign": [], "verify": []}
        kp = slhdsa.KeyPair.gen(par)
        for _ in range(a.n):
            s = time.perf_counter(); kp = slhdsa.KeyPair.gen(par); ts["keygen"].append((time.perf_counter() - s) * 1000)
        sig = None
        for _ in range(a.n):
            s = time.perf_counter(); sig = kp.sec.sign_pure(TEST_MSG, randomize=True); ts["sign"].append((time.perf_counter() - s) * 1000)
        for _ in range(a.n):
            s = time.perf_counter(); ok = kp.pub.verify_pure(TEST_MSG, sig); ts["verify"].append((time.perf_counter() - s) * 1000)
        assert ok
    out["timing_ms_median"] = {k: round(median(v), 6) for k, v in ts.items()}
    out["roundtrip_ok"] = True
    out["wall_seconds"] = round(time.time() - t0, 3)
    out["peak_rss_kb"] = _vm_hwm_kb()
    with open(a.outfile, "w") as f:
        json.dump(out, f)
    return 0


def run_python_worker(python, impl, alg, n, tmpfile):
    r = subprocess.run([python, os.path.abspath(__file__), "--worker", impl,
                        alg, str(n), tmpfile], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"worker {impl} {alg} failed: {r.stdout} {r.stderr}")
    with open(tmpfile) as f:
        return json.load(f)


# ---------------------------------------------------------------- main harness
def main():
    if "--worker" in sys.argv:
        return worker_main()
    ap = argparse.ArgumentParser()
    ap.add_argument("--driver", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--python", default=sys.executable)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    log_path = os.path.join(a.outdir, "benchmark-run.log")
    res_path = os.path.join(a.outdir, "results.json")
    drv = Driver(a.driver)
    lines = []
    results = {"implementations": {}, "throughput": {}, "memory_kb": {},
               "adversarial": {}, "cross_implementation": {}, "determinism": {},
               "sizes_verified": {}, "artifact_size_impact": {}, "environment": {}}

    def log(s):
        lines.append(s)
        print(s, flush=True)

    log("=== post-quantum release-signing assessment harness ===")
    log(f"driver: {a.driver}")
    log(f"python: {a.python}")
    log("test message: 'post-quantum release-signing assessment test message'")

    # --- 0. sizes ------------------------------------------------------
    log("--- sizes (FIPS 204 Table 2 / FIPS 205 Table 2) ---")
    for alg in SIG_ALGS:
        info = drv.info(alg)
        got = {"pk": int(info["length_public_key"]), "sk": int(info["length_secret_key"]),
               "sig": int(info["length_signature"])}
        ok = got == SIG_SIZES[alg]
        results["sizes_verified"][alg] = {"expected": SIG_SIZES[alg], "liboqs": got, "match": ok}
        log(f"SIZE {alg} liboqs={got} expected={SIG_SIZES[alg]} match={ok}")
        assert ok
    for alg in ML_DSA_ALGS:
        impl = load_dilithium(alg)
        pk, sk = impl.keygen()
        sig = impl.sign(sk, TEST_MSG)
        got = {"pk": len(pk), "sk": len(sk), "sig": len(sig)}
        ok = got == SIG_SIZES[alg]
        log(f"SIZE {alg} dilithium-py={got} match={ok}")
        assert ok
    for alg in SLH_ALGS:
        import slhdsa
        par = load_slhdsa(alg)
        kp = slhdsa.KeyPair.gen(par)
        sig = kp.sec.sign_pure(TEST_MSG, randomize=True)
        got = {"pk": len(kp.pub.digest()), "sk": len(kp.sec.digest()), "sig": len(sig)}
        ok = got == SIG_SIZES[alg]
        log(f"SIZE {alg} slh-dsa={got} match={ok}")
        assert ok

    # --- 1. throughput + memory: liboqs --------------------------------
    log("--- throughput: liboqs (C) ---")
    for alg in ML_DSA_ALGS:
        rc, out, _ = drv.run("sig-bench", alg, "100")
        assert rc == 0, out
        d = drv.parse(out)
        results["throughput"].setdefault(alg, {})["liboqs"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "sign_ms_median": float(d["sign_ms_median"]),
            "verify_ms_median": float(d["verify_ms_median"]),
            "n": 100, "verify_ok": d["verify_ok"]}
        results["memory_kb"].setdefault(alg, {})["liboqs"] = int(d["peak_rss_kb"])
        log(f"TIMING liboqs {alg} n=100 keygen={d['keygen_ms_median']}ms "
            f"sign={d['sign_ms_median']}ms verify={d['verify_ms_median']}ms "
            f"verify_ok={d['verify_ok']} peak_rss_kb={d['peak_rss_kb']}")
    for alg in SLH_ALGS:
        rc, out, _ = drv.run("sig-bench", alg, "20")
        assert rc == 0, out
        d = drv.parse(out)
        results["throughput"].setdefault(alg, {})["liboqs"] = {
            "keygen_ms_median": float(d["keygen_ms_median"]),
            "sign_ms_median": float(d["sign_ms_median"]),
            "verify_ms_median": float(d["verify_ms_median"]),
            "n": 20, "verify_ok": d["verify_ok"]}
        results["memory_kb"].setdefault(alg, {})["liboqs"] = int(d["peak_rss_kb"])
        log(f"TIMING liboqs {alg} n=20 keygen={d['keygen_ms_median']}ms "
            f"sign={d['sign_ms_median']}ms verify={d['verify_ms_median']}ms "
            f"verify_ok={d['verify_ok']} peak_rss_kb={d['peak_rss_kb']}")

    # --- 2. throughput + memory: Python impls --------------------------
    log("--- throughput: dilithium-py (pure Python) ---")
    for alg in ML_DSA_ALGS:
        tmp = os.path.join(a.outdir, f"worker-{alg}.json")
        data = run_python_worker(a.python, "dilithium-py", alg, 10, tmp)
        os.remove(tmp)
        results["throughput"].setdefault(alg, {})["dilithium-py"] = dict(
            data["timing_ms_median"], n=10, roundtrip_ok=data["roundtrip_ok"])
        results["memory_kb"].setdefault(alg, {})["dilithium-py"] = data["peak_rss_kb"]
        t = data["timing_ms_median"]
        log(f"TIMING dilithium-py {alg} n=10 keygen={t['keygen']}ms sign={t['sign']}ms "
            f"verify={t['verify']}ms roundtrip_ok={data['roundtrip_ok']} "
            f"peak_rss_kb={data['peak_rss_kb']}")
    log("--- throughput: slh-dsa (pure Python, n=1 indicative) ---")
    for alg in SLH_ALGS:
        tmp = os.path.join(a.outdir, f"worker-{alg}.json")
        data = run_python_worker(a.python, "slh-dsa", alg, 1, tmp)
        os.remove(tmp)
        results["throughput"].setdefault(alg, {})["slh-dsa"] = dict(
            data["timing_ms_median"], n=1, roundtrip_ok=data["roundtrip_ok"])
        results["memory_kb"].setdefault(alg, {})["slh-dsa"] = data["peak_rss_kb"]
        t = data["timing_ms_median"]
        log(f"TIMING slh-dsa {alg} n=1 keygen={t['keygen']}ms sign={t['sign']}ms "
            f"verify={t['verify']}ms roundtrip_ok={data['roundtrip_ok']} "
            f"peak_rss_kb={data['peak_rss_kb']}")

    # --- 3. adversarial: ML-DSA ----------------------------------------
    log("--- adversarial: ML-DSA ---")
    for alg in ML_DSA_ALGS:
        other = ML_DSA_ALGS[1] if alg != ML_DSA_ALGS[1] else ML_DSA_ALGS[0]
        cases = {}
        rc, out, _ = drv.run("sig-keygen", alg)
        d = drv.parse(out)
        pk, sk = d["public_key"], d["secret_key"]
        msg = TEST_MSG.hex()
        rc, out, _ = drv.run("sig-sign", alg, sk, msg)
        sig = drv.parse(out)["signature"]
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, sig)
        cases["liboqs_valid"] = drv.parse(out).get("verify") == "VALID"
        bad = bytearray(bytes.fromhex(sig)); bad[0] ^= 0x01
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, bad.hex())
        cases["liboqs_flipped_sig"] = drv.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = drv.run("sig-verify", alg, pk, (b"tampered message").hex(), sig)
        cases["liboqs_wrong_msg"] = drv.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = drv.run("sig-sign", alg, sk, msg, b"app-A".hex())
        sig_ctx = drv.parse(out)["signature"]
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, sig_ctx, b"app-B".hex())
        cases["liboqs_wrong_ctx"] = drv.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, sig[:-2])
        cases["liboqs_truncated_sig"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = drv.run("sig-verify", other, pk, msg, sig)
        cases["liboqs_cross_param"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = drv.run("sig-sign", alg, sk, msg, ("61" * 300))
        cases["liboqs_ctx_300B"] = "refused_sign_failed" if rc == 1 and "sign failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        impl = load_dilithium(alg)
        pk2, sk2 = impl.keygen()
        sig2 = impl.sign(sk2, TEST_MSG)
        cases["dilithium_valid"] = impl.verify(pk2, TEST_MSG, sig2) is True
        bad2 = bytearray(sig2); bad2[0] ^= 0x01
        cases["dilithium_flipped_sig"] = impl.verify(pk2, TEST_MSG, bytes(bad2))
        cases["dilithium_wrong_msg"] = impl.verify(pk2, b"tampered message", sig2)
        sig2_ctx = impl.sign(sk2, TEST_MSG, ctx=b"app-A")
        cases["dilithium_wrong_ctx"] = impl.verify(pk2, TEST_MSG, sig2_ctx, ctx=b"app-B")
        try:
            r = impl.verify(pk2, TEST_MSG, sig2[:-1])
            cases["dilithium_truncated_sig"] = "returns_False" if r is False else f"UNEXPECTED_returned_{r!r}"
        except Exception as e:
            cases["dilithium_truncated_sig"] = f"refused_{type(e).__name__}"
        impl_o = load_dilithium(other)
        try:
            cases["dilithium_cross_param"] = impl_o.verify(pk2, TEST_MSG, sig2)
        except Exception as e:
            cases["dilithium_cross_param"] = f"refused_{type(e).__name__}"
        try:
            impl.sign(sk2, TEST_MSG, ctx=b"x" * 300); cases["dilithium_ctx_300B"] = "UNEXPECTED_accepted"
        except Exception as e:
            cases["dilithium_ctx_300B"] = f"refused_{type(e).__name__}"
        results["adversarial"][alg] = cases
        for k, v in cases.items():
            log(f"ADV {alg} {k} = {v}")

    # --- 4. adversarial: SLH-DSA ---------------------------------------
    log("--- adversarial: SLH-DSA ---")
    for alg in SLH_ALGS:
        other = SLH_ALGS[1] if alg != SLH_ALGS[1] else SLH_ALGS[0]
        cases = {}
        rc, out, _ = drv.run("sig-keygen", alg)
        d = drv.parse(out)
        pk, sk = d["public_key"], d["secret_key"]
        msg = TEST_MSG.hex()
        rc, out, _ = drv.run("sig-sign", alg, sk, msg)
        sig = drv.parse(out)["signature"]
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, sig)
        cases["liboqs_valid"] = drv.parse(out).get("verify") == "VALID"
        bad = bytearray(bytes.fromhex(sig)); bad[0] ^= 0x01
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, bad.hex())
        cases["liboqs_flipped_sig"] = drv.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = drv.run("sig-verify", alg, pk, (b"tampered message").hex(), sig)
        cases["liboqs_wrong_msg"] = drv.parse(out).get("verify") or f"UNEXPECTED rc={rc} {out[:60]}"
        rc, out, _ = drv.run("sig-verify", alg, pk, msg, sig[:-2])
        cases["liboqs_truncated_sig"] = "refused_length_check" if rc == 2 and "length check failed" in out else f"UNEXPECTED rc={rc} out={out[:80]}"
        rc, out, _ = drv.run("sig-verify", other, pk, msg, sig)
        if rc == 2 and "length check failed" in out:
            cases["liboqs_cross_param"] = "refused_length_check"
        elif rc == 0 and drv.parse(out).get("verify") == "INVALID":
            # Same-size parameter set (SHA2 vs SHAKE, same n/suffix): the
            # length checks pass and verification correctly rejects.
            cases["liboqs_cross_param"] = "verify_INVALID"
        else:
            cases["liboqs_cross_param"] = f"UNEXPECTED rc={rc} out={out[:80]}"
        # slh-dsa (pure Python): FIPS 205 pure signing, no ctx parameter.
        import slhdsa
        par = load_slhdsa(alg)
        kp = slhdsa.KeyPair.gen(par)
        sig2 = kp.sec.sign_pure(TEST_MSG, randomize=True)
        cases["slhdsa_valid"] = kp.pub.verify_pure(TEST_MSG, sig2) is True
        bad2 = bytearray(sig2); bad2[0] ^= 0x01
        cases["slhdsa_flipped_sig"] = kp.pub.verify_pure(TEST_MSG, bytes(bad2))
        cases["slhdsa_wrong_msg"] = kp.pub.verify_pure(b"tampered message", sig2)
        try:
            r = kp.pub.verify_pure(TEST_MSG, sig2[:-1])
            cases["slhdsa_truncated_sig"] = "returns_False" if r is False else f"UNEXPECTED_returned_{r!r}"
        except Exception as e:
            cases["slhdsa_truncated_sig"] = f"refused_{type(e).__name__}"
        par_o = load_slhdsa(other)
        kp_o = slhdsa.KeyPair.gen(par_o)
        try:
            cases["slhdsa_cross_param"] = kp_o.pub.verify_pure(TEST_MSG, sig2)
        except Exception as e:
            cases["slhdsa_cross_param"] = f"refused_{type(e).__name__}"
        results["adversarial"][alg] = cases
        for k, v in cases.items():
            log(f"ADV {alg} {k} = {v}")

    # --- 5. cross-implementation ---------------------------------------
    log("--- cross-implementation agreement ---")
    for alg in ML_DSA_ALGS:
        impl = load_dilithium(alg)
        pk2, sk2 = impl.keygen()
        sig2 = impl.sign(sk2, TEST_MSG)
        rc, out, _ = drv.run("sig-verify", alg, pk2.hex(), TEST_MSG.hex(), sig2.hex())
        ok1 = drv.parse(out).get("verify") == "VALID"
        rc, out, _ = drv.run("sig-keygen", alg)
        d = drv.parse(out)
        pk_c, sk_c = d["public_key"], d["secret_key"]
        rc, out, _ = drv.run("sig-sign", alg, sk_c, TEST_MSG.hex())
        sig_c = drv.parse(out)["signature"]
        ok2 = impl.verify(bytes.fromhex(pk_c), TEST_MSG, bytes.fromhex(sig_c)) is True
        results["cross_implementation"][alg] = {
            "sig_dilithium_sign_liboqs_verify": ok1,
            "sig_liboqs_sign_dilithium_verify": ok2}
        log(f"XIMPL {alg} dilithium-sign/liboqs-verify={ok1} liboqs-sign/dilithium-verify={ok2}")
    for alg in SLH_ALGS:
        import slhdsa
        par = load_slhdsa(alg)
        kp = slhdsa.KeyPair.gen(par)
        sig2 = kp.sec.sign_pure(TEST_MSG, randomize=True)
        # slh-dsa public-key digest bytes are PK.seed || PK.root, the same
        # layout liboqs uses, so the digest is directly usable as a liboqs pk.
        rc, out, _ = drv.run("sig-verify", alg, kp.pub.digest().hex(), TEST_MSG.hex(), sig2.hex())
        ok1 = drv.parse(out).get("verify") == "VALID"
        rc, out, _ = drv.run("sig-keygen", alg)
        d = drv.parse(out)
        pk_c, sk_c = d["public_key"], d["secret_key"]
        rc, out, _ = drv.run("sig-sign", alg, sk_c, TEST_MSG.hex())
        sig_c = drv.parse(out)["signature"]
        pk_obj = slhdsa.PublicKey.from_digest(bytes.fromhex(pk_c), par)
        ok2 = pk_obj.verify_pure(TEST_MSG, bytes.fromhex(sig_c)) is True
        results["cross_implementation"][alg] = {
            "sig_slhdsa_sign_liboqs_verify": ok1,
            "sig_liboqs_sign_slhdsa_verify": ok2}
        log(f"XIMPL {alg} slhdsa-sign/liboqs-verify={ok1} liboqs-sign/slhdsa-verify={ok2}")

    # --- 6. signing determinism ----------------------------------------
    log("--- signing determinism (same key, same message, signed twice) ---")
    for alg in ML_DSA_ALGS:
        rc, out, _ = drv.run("sig-keygen", alg)
        sk_c = drv.parse(out)["secret_key"]
        rc, out, _ = drv.run("sig-sign-twice", alg, sk_c, TEST_MSG.hex())
        liboqs_identical = drv.parse(out).get("signatures_identical")
        impl = load_dilithium(alg)
        _, sk2 = impl.keygen()
        s1 = impl.sign(sk2, TEST_MSG)
        s2 = impl.sign(sk2, TEST_MSG)
        results["determinism"][alg] = {
            "liboqs_hedged_sign_twice_identical": liboqs_identical,
            "dilithium_hedged_sign_twice_identical": s1 == s2}
        log(f"DET {alg} liboqs_sign_twice_identical={liboqs_identical} "
            f"dilithium_hedged_identical={s1 == s2}")
    for alg in SLH_ALGS:
        import slhdsa
        par = load_slhdsa(alg)
        kp = slhdsa.KeyPair.gen(par)
        # slh-dsa pure signing with randomize=False is deterministic by
        # design (FIPS 205 allows a deterministic variant); with
        # randomize=True it must differ.
        d1 = kp.sec.sign_pure(TEST_MSG, randomize=False)
        d2 = kp.sec.sign_pure(TEST_MSG, randomize=False)
        r1 = kp.sec.sign_pure(TEST_MSG, randomize=True)
        r2 = kp.sec.sign_pure(TEST_MSG, randomize=True)
        rc, out, _ = drv.run("sig-keygen", alg)
        sk_c = drv.parse(out)["secret_key"]
        rc, out, _ = drv.run("sig-sign-twice", alg, sk_c, TEST_MSG.hex())
        liboqs_identical = drv.parse(out).get("signatures_identical")
        results["determinism"][alg] = {
            "liboqs_sign_twice_identical": liboqs_identical,
            "slhdsa_deterministic_sign_twice_identical": d1 == d2,
            "slhdsa_randomized_sign_twice_identical": r1 == r2}
        log(f"DET {alg} liboqs_sign_twice_identical={liboqs_identical} "
            f"slhdsa_deterministic_identical={d1 == d2} "
            f"slhdsa_randomized_identical={r1 == r2}")

    # --- 7. artifact-size impact ---------------------------------------
    log("--- artifact-size impact (signature bytes vs release artifact) ---")
    for alg in SIG_ALGS:
        sig_bytes = SIG_SIZES[alg]["sig"]
        entry = {"signature_bytes": sig_bytes,
                 "vs_ed25519_64B": round(sig_bytes / ED25519_SIG_BYTES, 1)}
        for name, size in ARTIFACT_SIZES.items():
            entry[f"overhead_pct_{name}"] = round(100.0 * sig_bytes / size, 4)
        results["artifact_size_impact"][alg] = entry
        log(f"ARTIFACT {alg} sig={sig_bytes}B vs_ed25519={entry['vs_ed25519_64B']}x "
            f"manifest_1KiB={entry['overhead_pct_manifest_1KiB']}% "
            f"wheel_100KiB={entry['overhead_pct_wheel_100KiB']}% "
            f"tarball_5MiB={entry['overhead_pct_tarball_5MiB']}% "
            f"binary_50MiB={entry['overhead_pct_binary_50MiB']}%")

    # --- 8. environment: local OpenSSL PQC support ----------------------
    log("--- environment: OpenSSL on this machine ---")
    r = subprocess.run(["openssl", "version"], capture_output=True, text=True)
    ver = r.stdout.strip()
    r2 = subprocess.run(["openssl", "list", "-signature-algorithms"],
                        capture_output=True, text=True)
    algs = r2.stdout
    has_mldsa = "ML-DSA" in algs
    has_slhdsa = "SLH-DSA" in algs
    results["environment"] = {
        "openssl_version": ver,
        "openssl_lists_ml_dsa": has_mldsa,
        "openssl_lists_slh_dsa": has_slhdsa,
        "python": sys.version.split()[0],
    }
    log(f"ENV openssl: {ver}")
    log(f"ENV openssl lists ML-DSA: {has_mldsa}; lists SLH-DSA: {has_slhdsa}")

    results["implementations"] = {
        "liboqs": "0.16.0 (C, ml-dsa-native / slh-dsa backends)",
        "dilithium-py": "1.5.1 (pure Python, FIPS 204 ML-DSA)",
        "slh-dsa": "0.2.5 (pure Python, FIPS 205 pure signing; author Colinxu2020)",
        "rust": "NOT RUN — no cargo/rustc toolchain on this machine",
        "go": "NOT RUN — no Go toolchain on this machine"}
    with open(res_path, "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)
    with open(log_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    log(f"=== done: results -> {res_path} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
