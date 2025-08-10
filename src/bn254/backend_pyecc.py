# backend_pyecc.py — BN254 via official py-mcl (clean + minimal)
from __future__ import annotations
import secrets
import os
os.environ.setdefault("MCL_PATH", "/Users/tiantian/local/mcl")
os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = "/Users/tiantian/local/mcl/lib" + os.pathsep + os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "")
import mcl  # ← 官方封装

# ---- init ----
_inited = False
def _ensure():
    global _inited
    if not _inited:
        mcl.init(mcl.BN254)
        # 以太坊兼容序列化（许多库默认这么做）
        if hasattr(mcl, "setETHserialization"):
            mcl.setETHserialization(True)
        _inited = True

# ---- types ----
Fr, G1, G2, GT = mcl.Fr, mcl.G1, mcl.G2, mcl.GT

# ---- constants ----
curve_order = int("21888242871839275222246405745257275088548364400416034343698204186575808495617")
def rand_scalar() -> int:
    return secrets.randbelow(curve_order - 1) + 1

# ---- helpers ----
def _fr(k: int) -> Fr:
    _ensure()
    x = Fr()
    x.setInt(int(k) % curve_order)        # 官方 setInt，稳定
    return x

# 基点
def _g1_base() -> G1:
    _ensure()
    return mcl.getBasePointG1()
def _g2_base() -> G2:
    _ensure()
    return mcl.getBasePointG2()
g1, g2 = _g1_base(), _g2_base()

# ---- group ops (与原接口同名) ----
def add(P, Q):
    _ensure()
    if P is None: return Q
    if Q is None: return P
    return P + Q

def multiply(P, k: int):
    _ensure()
    return P * _fr(k)

def g1_mul(P: G1, k: int) -> G1:
    _ensure()
    return P * _fr(k)

def g2_mul(Q: G2, k: int) -> G2:
    _ensure()
    return Q * _fr(k)

def msm_g1(bases, scalars):
    _ensure()
    acc = None
    for B, s in zip(bases, scalars):
        acc = add(acc, g1_mul(B, s))
    return acc or G1()  # 零元

# pairing 一定是 finalExp 后的真 pairing
def pair(P: G1, Q: G2) -> GT:
    _ensure()
    return mcl.pairing(P, Q)

__all__ = [
    "Fr","G1","G2","GT",
    "curve_order","rand_scalar",
    "g1","g2",
    "add","multiply","g1_mul","g2_mul","msm_g1","pair",
]
