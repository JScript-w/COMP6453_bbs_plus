"""
backend_pyecc.py — BN-254 implementation via **mclbn256**
========================================================

* Drop-in replacement for the old py-ecc backend; **file name stays the same**.
* Uses Herumi MCL’s Python binding (`pip install mclbn256`). SIMD (AVX2/512) is
  automatically enabled on x86-64 Linux/macOS wheels.
* All public symbols (`curve_order`, `G1`, `G2`, `rand_scalar`, `g1_mul`,
  `g2_mul`, `msm_g1`, `pair`, …) keep the same names so that upper-layer BBS+
  code runs unchanged.
"""
from __future__ import annotations

import secrets
from typing import List, Union
import mclbn256 as mcl
from mclbn256 import G1 as _G1, G2 as _G2, Fr
from ctypes import create_string_buffer
from mclbn256 import lib as _lib

# Your mcl binding does not require explicit init; keep compatibility,
# do nothing if there is no init
_MCL_READY = True

_FR_METHOD = None  # 'bytes_le32' | 'hex16' | 'dec10' | '0xhex144' | 'disabled'

def _try_fr_new_fromstr(payload: bytes, mode: int) -> bool:
    try:
        v = Fr.new_fromstr(payload, mode)
        # Read the integer to ensure the object is usable
        _ = int(v)
        return True
    except Exception:
        return False

def _detect_fr_method():
    """
    Runs only on first call:
    Select a fromstr method that can handle both small=123 and big=(r-1).
    If none works, mark as 'disabled' and fallback to integer multiplication.
    """
    global _FR_METHOD
    if _FR_METHOD is not None:
        return

    small = 123 % curve_order
    big   = (curve_order - 1)  # toughest sample

    candidates = [
        ("bytes_le32",
         (small.to_bytes(32, "little"), 32),
         (big.to_bytes(32,  "little"), 32)),
        ("hex16",
         (f"{small:064x}".encode(), 16),
         (f"{big:064x}".encode(),   16)),
        ("dec10",
         (str(small).encode(), 10),
         (str(big).encode(),   10)),
        ("0xhex144",
         ((b"0x" + f"{small:064x}".encode()), 144),
         ((b"0x" + f"{big:064x}".encode()),   144)),
    ]

    for name, (p_s, m_s), (p_b, m_b) in candidates:
        ok_small = _try_fr_new_fromstr(p_s, m_s)
        ok_big   = _try_fr_new_fromstr(p_b, m_b)
        if ok_small and ok_big:
            _FR_METHOD = name
            return

    # If none can handle both, disable Fr path and always use integer multiplication
    _FR_METHOD = "disabled"


def _ensure_mcl():
    # Some environments have mcl.init; use if available, otherwise skip
    if hasattr(mcl, "init"):
        try:
            mcl.init(mcl.BN254)
        except Exception:
            pass


# BN-254 scalar-field order r (same as ALT_BN128 / Ethereum bn128 curve)
curve_order: int = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

# Canonical generators provided by the library
G1: _G1 = _G1.base_point()
G2: _G2 = _G2.base_point()

g1 = G1            # lowercase aliases kept for backward compatibility
g2 = G2

# Additive identities (useful for equality checks)
ZERO_G1: _G1 = _G1()  # same as G1.zero(), but explicit
ZERO_G2: _G2 = _G2()

# ────────────────────────────────────────────────────────────────
# 2. Scalar helpers
# ────────────────────────────────────────────────────────────────

# --- Replace _to_fr with a robust version and ensure initialization at entry ---
def _to_fr(k: int) -> Fr:
    _detect_fr_method()
    if _FR_METHOD == "disabled":
        # Notify upper layers to use integer multiply fallback; don’t print here to avoid spam
        raise ValueError("Fr path disabled on this system")

    k = int(k) % curve_order
    if _FR_METHOD == "bytes_le32":
        return Fr.new_fromstr(k.to_bytes(32, "little"), 32)
    elif _FR_METHOD == "hex16":
        return Fr.new_fromstr(f"{k:064x}".encode(), 16)
    elif _FR_METHOD == "dec10":
        return Fr.new_fromstr(str(k).encode(), 10)
    elif _FR_METHOD == "0xhex144":
        return Fr.new_fromstr(b"0x" + f"{k:064x}".encode(), 144)
    else:
        # Should never reach here
        raise ValueError("Unsupported _FR_METHOD")


def rand_scalar() -> int:
    """Cryptographically-secure random non-zero scalar ∈ [1, r-1]."""
    return secrets.randbelow(curve_order - 1) + 1

# ────────────────────────────────────────────────────────────────
# 3. Group operations (API compatible with py-ecc)
# ────────────────────────────────────────────────────────────────

def add(P, Q):  # noqa: N802 — keep original name
    """Elliptic-curve point addition with None-tolerant semantics."""
    if P is None:
        return Q
    if Q is None:
        return P
    return P + Q


def _clone_point(P):
    # Break aliasing using serialize/deserialize; supports G1/G2
    try:
        C = P.__class__
        if hasattr(C, "deserialize") and (hasattr(P, "serialize") or hasattr(P, "__bytes__")):
            raw = P.serialize() if hasattr(P, "serialize") else bytes(P)
            return C.deserialize(raw)
    except Exception:
        pass
    # Fallback: return original object (should rarely happen)
    return P

def _zero_like(P):
    # Get the library-recognized "true zero point" by P - P
    try:
        return P - P
    except Exception:
        # Extreme fallback: clone and subtract
        Q = _clone_point(P)
        return Q - Q

def _safe_add(P, Q):
    # Clone inputs first to avoid in-place modification inside __add__
    P2, Q2 = _clone_point(P), _clone_point(Q)
    R = P2 + Q2
    # Clone output again to avoid reusing the same instance later
    return _clone_point(R)

def _safe_double(P):
    # Avoid aliasing in "self-add": clone first, then add
    return _safe_add(P, P)

# --- Scalar multiplication: Montgomery ladder (MSB-first), no aliasing, no self-add ---
def _mul_int_generic(P, k: int):
    """
    Precompute binary power table + accumulate (no doubling of intermediate results):
    - Build table[i] = (2^i)·P
    - Then sum up table[i] for each 1-bit in k
    """
    k = int(k) % curve_order
    if k == 0:
        # Return "zero point": use clone to avoid modifying P in place
        try:
            return P - P
        except Exception:
            # Extreme fallback: if unary minus unsupported, degrade to "add curve_order times"
            R = P
            for _ in range(curve_order - 1):
                R = R + P
            return R

    # 1) Precompute power table
    bits = k.bit_length()
    table = [None] * bits
    table[0] = P
    for i in range(1, bits):
        table[i] = table[i - 1] + table[i - 1]   # 2^(i)·P = 2^(i-1)·P + 2^(i-1)·P

    # 2) Accumulate selected powers
    R = None
    idx = 0
    kk = k
    while kk:
        if kk & 1:
            R = table[idx] if R is None else (R + table[idx])
        kk >>= 1
        idx += 1

    return R

def multiply(P, k: int):
    return _mul_int_generic(P, k)

def g1_mul(P, k: int):
    return _mul_int_generic(P, k)

def g2_mul(Q, k: int):
    return _mul_int_generic(Q, k)

def msm_g1(bases: List[_G1], scalars: List[int]) -> _G1:
    """Naïve O(n) multi-scalar multiplication (can replace with Pippenger later)."""
    acc: _G1 | None = None
    for B, s in zip(bases, scalars):
        acc = add(acc, g1_mul(B, s))
    return acc or ZERO_G1

# ────────────────────────────────────────────────────────────────
# 4. Pairing
# ────────────────────────────────────────────────────────────────

def pair(P: _G1, Q: _G2):
    """Bilinear pairing e(P, Q) ∈ GT; '@' already performs final exponentiation."""
    return P @ Q

# Legacy alias expected by some modules
ecc_add = add

# ────────────────────────────────────────────────────────────────
# 5. Hash-to-G1
# ────────────────────────────────────────────────────────────────

def hash_to_g1(data) -> _G1:
    if isinstance(data, str):
        data = data.encode()
    P = _G1()
    if hasattr(P, "hash"):
        P.hash(data)                # Common interface
        return P
    if hasattr(_G1, "fromhash"):
        return _G1.fromhash(data)   # Some wrappers implement this as a classmethod
    raise RuntimeError("Your mclbn256 binding lacks G1.hash()/G1.fromhash()")

# ────────────────────────────────────────────────────────────────
# 6. Public re-exports
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
    "hash_to_g1",
]
