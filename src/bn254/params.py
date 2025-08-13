# bn254/params.py
import os

# Selectable backend: "mcl" / "pyecc"
BACKEND = os.getenv("BN254_BACKEND", "pyecc")

if BACKEND == "mcl":
    # TODO: Once the mcl implementation is ready, update the import path to your mcl module
    from bn254.backend_mcl import (  # ← Placeholder; if unavailable, don't switch to mcl
        g1_mul, g2_mul, g1, g2, curve_order, rand_scalar, add, pair, msm_g1
    )
    BACKEND_NAME = "mcl"
else:
    # For now, use pyecc and ensure that Fr initialization and _to_fr are fixed in backend_pyecc
    from bn254.backend_pyecc import (
        g1_mul, g2_mul, g1, g2, curve_order, rand_scalar, add
    )
    BACKEND_NAME = "pyecc"

    # Some symbols may be missing in pyecc -> provide fallback implementations
    try:
        from bn254.backend_pyecc import pair  # Use if implemented
    except Exception:
        def pair(P, Q):
            raise NotImplementedError("pair is not available in pyecc backend")

    try:
        from bn254.backend_pyecc import msm_g1  # Use if implemented
    except Exception:
        def msm_g1(bases, scalars):
            """Naive MSM fallback: ∑ s_i * B_i"""
            acc = None
            for B, s in zip(bases, scalars):
                pt = g1_mul(B, s)
                acc = add(acc, pt) if acc is not None else pt
            return acc

def _debug_backend():
    print(f"[bn254.params] Using backend: {BACKEND_NAME}")

__all__ = [
    "g1_mul", "g2_mul", "g1", "g2", "curve_order", "rand_scalar",
    "add", "pair", "msm_g1", "_debug_backend"
]
