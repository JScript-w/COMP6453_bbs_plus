"""
BBS+ Verifier

Version: v0.1
"""

from ..params import g1, g2, add, g2_mul, msm_g1, pair
from .utils_v2 import encode_attributes


def verify(pk: dict, sig: tuple, messages: list[str]):
    """
    BBS+ Signature-Verifizier algorithmus

    Formula: e(A, X · Y^r) = e(g1 · h0^r · ∏_{i=1}^{L}h_i^m_i, g2)

    Principle:
    Given e(aP, bQ) = e(P,Q)^{ab}, we have:
    1. Left: e(A, X · Y^r) = e(A, g2^x · g2^(y·r)) = e(A, g2^(x + y·r))
    2. Right: e(g1 · h0^r · ∏h_i^m_i, g2)
    3. Since A = (g1 · h0^r · ∏h_i^m_i)^(1/(x + y·r))
    4. Therefore, left = e((...)^(1/(x + y·r)), g2^(x + y·r)) = e(..., g2) = Right

    Args:
        pk (Dict): public key (dict {X, Y, h_bases})
        sig (Tuple[Point2D, int]): Signature (A, r)
        messages (List[str]): List of messages

    Returns:
        bool: Is the signature valid
    """

    # Extract signature components
    A, r = sig

    # Extract public key components
    X = pk["X"]
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # Encode the message as a scalar, i.e., calculate the hash value of the message
    # mi = Hash(messages[i])
    m_scalars = encode_attributes(messages)

    # Build message commitment
    # i.e., msg_commit = g1 · h0^r · ∏_{i=1}^{L} h_i^m_i
    scalars = [1, r] + m_scalars  # [1, r, m1, m2, ..., mL]
    bases = [g1, h_bases[0]] + h_bases[1 : len(m_scalars) + 1]  # [g1, h0, h1, ..., hL]
    msg_commit = msm_g1(bases, scalars)

    # Construct left side of the equation
    # i.e., e(A, X · Y^r)
    Yr = g2_mul(Y, r)  # Y^r = g2^(y·r)
    left_g2 = add(X, Yr)  # X · Y^r = g2^x · g2^(y·r) = g2^(x + y·r)
    left = pair(A, left_g2)  # e(A, X · Y^r) -> e(A, g2^(x + y·r))

    # Construct right side of the equation
    # i.e., e(g1 · h0^r · ∏hi^{mi}, g2)
    right = pair(msg_commit, g2)

    return left == right
