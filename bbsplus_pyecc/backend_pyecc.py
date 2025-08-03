from py_ecc.bls12_381 import (
    curve_order, G1, G2, add, multiply, pairing, final_exponentiate
)


import secrets

# -----------------------------------------------
# Scalars

def rand_scalar() -> int:
    """Return a random scalar ∈ ℤₚ \\ {0}."""
    return secrets.randbelow(curve_order - 1) + 1


# ----------------------------
# Group helpers

def g1_mul(P, k: int):
    return multiply(P, k % curve_order)

def g2_mul(Q, k: int):
    return multiply(Q, k % curve_order)

def msm_g1(bases, scalars):
    acc = None
    for B, s in zip(bases, scalars):
        pt = g1_mul(B, s)
        acc = add(acc, pt) if acc else pt
    return acc

def pair(P, Q):
    return final_exponentiate(pairing(Q, P))

ecc_add = add