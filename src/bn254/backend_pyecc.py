"""
backend_pyecc.py — BN‑254 implementation via **mclbn256**
========================================================

* Drop‑in replacement for the old py‑ecc backend; **file name stays the same**.
* Uses Herumi MCL’s Python binding (`pip install mclbn256`). SIMD (AVX2/512) is
  enabled automatically on x86‑64 Linux/macOS wheels.
* All public symbols (`curve_order`, `G1`, `G2`, `rand_scalar`, `g1_mul`,
  `g2_mul`, `msm_g1`, `pair`, …) keep the same names so that upper‑layer BBS+
  code runs unchanged.
"""
from __future__ import annotations

import secrets
from typing import List
import mclbn256 as mcl
from mclbn256 import G1 as _G1, G2 as _G2, Fr  # type stubs for IDEs

# ────────────────────────────────────────────────────────────────
# 1. Constants & Generators
# ────────────────────────────────────────────────────────────────

# BN‑254 scalar‑field order r (same as ALT_BN128 / Ethereum bn128 curve)
curve_order: int = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
# Canonical generators provided by the library
G1: _G1 = _G1.base_point()
G2: _G2 = _G2.base_point()

g1 = G1            # lowercase aliases kept for historic code
g2 = G2

# Additive identities (handy for equality checks)
ZERO_G1: _G1 = _G1()  # same as G1.zero() but explicit
ZERO_G2: _G2 = _G2()

# ────────────────────────────────────────────────────────────────
# 2. Scalar helpers
# ────────────────────────────────────────────────────────────────

def _to_fr(k: int) -> Fr:
    """Clamp integer into field range and wrap as Fr element."""
    return Fr(k % curve_order)


def rand_scalar() -> int:
    """Cryptographically‑secure random non‑zero scalar ∈ [1, r‑1]."""
    return secrets.randbelow(curve_order - 1) + 1

# ────────────────────────────────────────────────────────────────
# 3. Group operations (API compatible with py‑ecc)
# ────────────────────────────────────────────────────────────────

def add(P, Q):  # noqa: N802 — keep original name
    """Elliptic‑curve point addition with None‑tolerant semantics."""
    if P is None:
        return Q
    if Q is None:
        return P
    return P + Q


def multiply(P, k: int):  # noqa: N802
    """Scalar multiplication using operator overloading."""
    return P * _to_fr(k)


def g1_mul(P: _G1, k: int) -> _G1:
    return multiply(P, k)


def g2_mul(Q: _G2, k: int) -> _G2:
    return multiply(Q, k)


def msm_g1(bases: List[_G1], scalars: List[int]) -> _G1:
    """Naïve O(n) multi‑scalar‑mul (can swap for Pippenger later)."""
    acc: _G1 | None = None
    for B, s in zip(bases, scalars):
        acc = add(acc, g1_mul(B, s))
    return acc or ZERO_G1

# ────────────────────────────────────────────────────────────────
# 4. Pairing
# ────────────────────────────────────────────────────────────────

def pair(P: _G1, Q: _G2):
    """Bilinear pairing e(P, Q) ∈ GT; '@' already does final‑exp."""
    return P @ Q

# Legacy alias expected by some modules

ecc_add = add

# ────────────────────────────────────────────────────────────────
# 5. Public re‑exports
# ────────────────────────────────────────────────────────────────

__all__ = [
    "curve_order",
    "G1",
    "G2",
    "g1",
    "g2",
    "ZERO_G1",
    "ZERO_G2",
    "rand_scalar",
    "g1_mul",
    "g2_mul",
    "msm_g1",
    "add",
    "pair",
    "ecc_add",
]
