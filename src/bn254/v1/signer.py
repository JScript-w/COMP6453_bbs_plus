# bn254/v1/signer.py
from __future__ import annotations
import os, hashlib
from bn254 import backend_pyecc as ecc

def _ser_g1(P):
    return P.serialize() if hasattr(P, "serialize") else bytes(P)

def _ser_g2(Q):
    return Q.serialize() if hasattr(Q, "serialize") else bytes(Q)

def _digest_g1(P):
    return hashlib.blake2b(_ser_g1(P), digest_size=16).hexdigest()

def sign(sk: bytes | int, attrs: list[bytes | int]) -> tuple[bytes, bytes]:
    ecc._ensure_mcl()

    # 1) 归一化 sk
    if isinstance(sk, bytes):
        x = int.from_bytes(sk, "big") % ecc.curve_order
    elif isinstance(sk, int):
        x = sk % ecc.curve_order
    else:
        raise TypeError("Unsupported secret key type for signing")

    # 2) 构造 U = g1 + Σ H_i^{m_i}
    U = ecc.g1  # 注意：mcl 的点是不可变语义，这里直接用加法得到新点
    m_ints = []
    for i, a in enumerate(attrs):
        m = int.from_bytes(a, "big") % ecc.curve_order if isinstance(a, (bytes, bytearray)) else int(a) % ecc.curve_order
        m_ints.append(m)
        Hi = ecc.hash_to_g1(f"H{i}")
        U = ecc.add(U, ecc.g1_mul(Hi, m))

    # 3) 随机 e，计算 A = U^{1/(x+e)}
    e_scalar = ecc.rand_scalar()
    while (x + e_scalar) % ecc.curve_order == 0:
        e_scalar = ecc.rand_scalar()
    denom = (x + e_scalar) % ecc.curve_order
    inv_denom = pow(denom, -1, ecc.curve_order)
    A_point = ecc.g1_mul(U, inv_denom)

    if os.getenv("BBS_DEBUG") == "1":
        denom = (x + e_scalar) % ecc.curve_order
        # 直接检查：A*(x+e) 是否等于 U
        U2 = ecc.g1_mul(A_point, denom)
        eq_U = (ecc._ser_g1(U2) == ecc._ser_g1(U)) if hasattr(ecc, "_ser_g1") else (U2.serialize() == U.serialize())
        print("[sign] A*(x+e) == U ? ", eq_U)

        T_local = ecc.g2_mul(ecc.g2, denom)  # (x+e)·g2
        lhs = ecc.pair(A_point, T_local)
        rhs = ecc.pair(U, ecc.g2)
        print("[sign] pair(A,(x+e)·g2) == pair(U,g2)?", bool(lhs == rhs))

    # 4) 输出 (A_bytes, e_bytes)
    A_bytes = _ser_g1(A_point)
    e_bytes = e_scalar.to_bytes(32, "big")
    return (A_bytes, e_bytes)
