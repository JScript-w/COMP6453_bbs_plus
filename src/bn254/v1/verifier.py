from typing import Sequence
from .utils import get_h_bases, encode_attributes, ensure_scalar, _scalars_digest,build_U_and_ms # ← 关键：用同一实现
from ..params import curve_order, g1, g1_mul, g2, g2_mul, pair, add, msm_g1


def verify(pk, sig, attrs, msg=None) -> bool:
    # 归一化 sig → (A, e)
    if isinstance(sig,(tuple,list)) and len(sig)>=2:
        A, e = sig[0], sig[1]
    elif hasattr(sig,"A") and hasattr(sig,"e"):
        A, e = sig.A, sig.e
    elif hasattr(sig,"sigma") and hasattr(sig,"challenge"):
        A, e = sig.sigma, sig.challenge
    else:
        raise TypeError(f"Unsupported sig type: {type(sig)}")

    e = ensure_scalar(e)
    U, _, m_scalars = build_U_and_ms(attrs)

    lhs = pair(A, add(pk, g2_mul(g2, e)))  # e(A, pk + e*g2)
    rhs = pair(U, g2)                      # e(U, g2)
    # 可留调试：
    # from .utils import _scalars_digest
    # print("[verify] m_digest=", _scalars_digest(m_scalars))
    # print("[verify] pairing eq:", lhs == rhs)
    return lhs == rhs
