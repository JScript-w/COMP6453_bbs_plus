"""
Backend Abstraction Layer

Provides a unified interface for elliptic curve operations, 
wrapped around the py_ecc library.
"""

from py_ecc.bls12_381.bls12_381_curve import (
    curve_order,  # The order p of the elliptic curve
    G1,  # Generator of group G1 (a point on the elliptic curve)
    G2,  # Generator of group G2 (a point on the twisted elliptic curve)
    add,  # Elliptic curve point addition
    multiply,  # Elliptic curve scalar multiplication
)

from py_ecc.bls12_381.bls12_381_pairing import (
    pairing,  # Bilinear pairing e: G1 × G2 → GT
    final_exponentiate,  # Final exponentiation step for pairings
)

import secrets

# -----------------------------------------------
# Scalars — Scalar operation functions

def rand_scalar() -> int:
    """
    Generate a cryptographically secure random scalar.

    Returns:
        int: A random scalar in ℤₚ \ {0}.
    """
    return secrets.randbelow(curve_order - 1) + 1


# ----------------------------
# Group helpers — Group operation helper functions

def g1_mul(P, k: int):
    """
    Scalar multiplication in group G1.

    This function takes a point P and a scalar k, and returns P multiplied by k.

    Args:
        P (Point2D): A point in G1
        k (int): A scalar in ℤₚ

    Returns:
        Point2D: Coordinates of the resulting point on the elliptic curve
    """
    return multiply(P, k % curve_order)  # (k mod curve_order) ensures the scalar is in range


def g2_mul(Q, k: int):
    """
    Scalar multiplication in group G2.

    Args:
        Q (Point2D): A point in G2
        k (int): A scalar in ℤₚ

    Returns:
        Point2D: A point in G2
    """
    return multiply(Q, k % curve_order)


def msm_g1(bases, scalars):
    """
    Multi-scalar multiplication.

    Efficiently compute the sum of products of multiple base points and scalars.

    Args:
        bases (List[Point2D[Field]]): List of G1 points [P1, P2, ..., Pn]
        scalars (List[int]): List of scalars [k1, k2, ..., kn]

    Returns:
        Point2D[Field]: The result ∑(Pi · ki) ∈ G1
    """
    acc = None
    for B, s in zip(bases, scalars):
        pt = g1_mul(B, s)
        acc = add(acc, pt) if acc else pt
    return acc


def pair(P, Q):
    """
    Bilinear pairing operation.

    Returns:
        GT element: The result of e(P, Q) after final exponentiation.
    """
    return final_exponentiate(pairing(Q, P))


# Alias for addition operation
ecc_add = add
