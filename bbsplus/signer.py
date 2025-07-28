from typing import Sequence
from .params import (
    rand_scalar, g1_mul, g2_mul, msm_g1, pair,
    g1, g2, add, curve_order
)
from .utils import encode_attributes
# Internal ------------------------------------------------------------------ #
def _compute_A(x, e, h_bases, m_scalars):
    denom_inv = pow(x + e, -1, curve_order)
    h_part = msm_g1(h_bases, m_scalars) if m_scalars else None
    sum_pt = add(g1, h_part) if h_part else g1
    return g1_mul(sum_pt, denom_inv)

# Public API ---------------------------------------------------------------- #
def sign(sk: int, messages: list[str]):
    h_bases = [g1_mul(g1, i + 2) for i in range(len(messages))]  # deterministic
    m_scalars = encode_attributes(messages)
    e = rand_scalar()
    A = _compute_A(sk, e, h_bases, m_scalars)
    return A, e

def update_attributes(sk: int, sig, messages_old: list[str], updates: dict[int, str]):
    A_old, e = sig
    messages_new = messages_old[:]
    for idx, v in updates.items():
        messages_new[idx] = v
    h_bases = [g1_mul(g1, i + 2) for i in range(len(messages_new))]
    m_scalars = encode_attributes(messages_new)
    A_new = _compute_A(sk, e, h_bases, m_scalars)
    return A_new, e

def re_randomise(sig):
    A, e = sig
    r = rand_scalar()
    return A, (e + r) % g2.curve_order
