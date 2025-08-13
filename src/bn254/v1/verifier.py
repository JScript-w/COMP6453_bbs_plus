# bn254/v1/verifier.py
from __future__ import annotations
import os, hashlib
from bn254 import backend_pyecc as ecc

def _ser_g1(P):
    return P.serialize() if hasattr(P, "serialize") else bytes(P)

def _ser_g2(Q):
    return Q.serialize() if hasattr(Q, "serialize") else bytes(Q)

def _digest_g1(P):
    return hashlib.blake2b(_ser_g1(P), digest_size=16).hexdigest()

def _digest_g2(Q):
    return hashlib.blake2b(_ser_g2(Q), digest_size=16).hexdigest()

def verify(pk: bytes | object, sig, attrs: list[bytes | int]) -> bool:
    ecc._ensure_mcl()

    # 1) Parse pk (public key)
    if isinstance(pk, (bytes, bytearray)):
        try:
            pk_point = ecc._G2.deserialize(pk)
        except Exception as e:
            raise ValueError("Invalid public key bytes") from e
    elif isinstance(pk, ecc._G2):
        pk_point = pk
    else:
        raise TypeError("Unsupported public key type")

    # 2) Parse signature (A, e)
    if isinstance(sig, (tuple, list)) and len(sig) >= 2:
        A_val, e_val = sig[0], sig[1]
    elif hasattr(sig, "A") and hasattr(sig, "e"):
        A_val, e_val = sig.A, sig.e
    elif isinstance(sig, dict):
        A_val, e_val = sig.get("A") or sig.get("a") or sig.get("sigma"), sig.get("e") or sig.get("challenge")
    else:
        raise TypeError("Unsupported signature format")

    if isinstance(A_val, (bytes, bytearray)):
        try:
            A_point = ecc._G1.deserialize(A_val)
        except Exception as e:
            raise ValueError("Invalid A bytes") from e
    elif isinstance(A_val, ecc._G1):
        A_point = A_val
    else:
        raise TypeError("Unsupported A type")

    e_int = int.from_bytes(e_val, "big") % ecc.curve_order if isinstance(e_val, (bytes, bytearray)) else int(e_val) % ecc.curve_order

    # 3) Reconstruct U
    U = ecc.g1
    m_ints = []
    for i, a in enumerate(attrs):
        m = int.from_bytes(a, "big") % ecc.curve_order if isinstance(a, (bytes, bytearray)) else int(a) % ecc.curve_order
        m_ints.append(m)
        Hi = ecc.hash_to_g1(f"H{i}")
        U = ecc.add(U, ecc.g1_mul(Hi, m))

    # 4) Pairing equation check
    T = ecc.add(pk_point, ecc.g2_mul(ecc.g2, e_int))  # pk + e·g2
    lhs = ecc.pair(A_point, T)
    rhs = ecc.pair(U, ecc.g2)

    if os.getenv("BBS_DEBUG") == "1":
        print("[verify] e(hex)      =", e_int.to_bytes(32, "big").hex())
        print("[verify] m_ints(hex) =", [hex(m)[:14] for m in m_ints])
        print("[verify] U_digest    =", _digest_g1(U))
        print("[verify] A_digest    =", _digest_g1(A_point))
        print("[verify] T_digest    =", _digest_g2(T))
        print("[verify] pairing eq  =", bool(lhs == rhs))

    return bool(lhs == rhs)
