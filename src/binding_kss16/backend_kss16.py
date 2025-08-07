
from __future__ import annotations
import secrets
from typing import Protocol

from kss16core import G1, G2, pairing


CURVE_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    16,
)

# --------- tool functions ---------
def rand_scalar() -> int:
    """返回 1 ≤ s < r 的随机数"""
    return secrets.randbelow(CURVE_ORDER - 1) + 1


def hash_to_G1(data: bytes) -> G1:
    """极简映射：把 bytes → int → 生成元乘法（仅 demo 用）"""
    return G1.generator() * (int.from_bytes(data, "big") % CURVE_ORDER)


# --------- expose unified interfaces ---------
class CurveBackend(Protocol):
    G1: type
    G2: type
    pairing: callable
    rand_scalar: callable
    hash_to_G1: callable


class _Backend:
    G1 = G1
    G2 = G2
    pairing = staticmethod(pairing)
    rand_scalar = staticmethod(rand_scalar)
    hash_to_G1 = staticmethod(hash_to_G1)


backend: CurveBackend = _Backend()  # 供外部 import
# Ensure compatibility with future Python versions  
# Secure random scalar generation  
# Define a standard interface for curve operations  

# Import G1, G2 group elements and pairing operation from the KSS16 core  
# Define the curve order (example: 768-bit order for KSS16)  

# Return a random scalar s such that 1 ≤ s < r  
# Simplified mapping from bytes to G1 (not secure, for demo purposes only)  

# Protocol defining a standard interface for elliptic curve backends  
# Concrete backend implementation using KSS16  
# Expose G1 group type  
# Expose G2 group type  
# Expose pairing operation  
# Expose random scalar generator  
# Expose hash-to-G1 mapping  

# Provide the backend as a unified interface for external use  
