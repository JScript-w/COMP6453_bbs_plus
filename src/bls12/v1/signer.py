from ..params import rand_scalar, g1_mul, g2_mul, msm_g1, pair, g1, g2, add, curve_order
from .utils import encode_attributes


# Internal ------------------------------------------------------------------ #
def _compute_A(x, e, h_bases, m_scalars):
    """
    Compute parameter A for subsequent signing and verification.

    Formula: A = (g1 * h0)

    Args:
        x (int): Private key
        e (int): Randomly chosen integer
        h_bases (Point2D): Deterministic base points
        m_scalars (): Encoded message scalars
    """
    denom_inv = pow(x + e, -1, curve_order)  # Compute: 1 / (x + e) % curve_order
    h_part = msm_g1(h_bases, m_scalars) if m_scalars else None
    sum_pt = add(g1, h_part) if h_part else g1
    return g1_mul(sum_pt, denom_inv)


# Public API ---------------------------------------------------------------- #
def sign(sk: int, messages: list[str]):
    """
    Signature algorithm.

    Args:
        sk (int): Private key
        messages (list[str]): Messages to be signed

    Returns:
        A (Point2D): A point on the elliptic curve used for subsequent signing and verification
        e (int): Random integer
    """
    h_bases = [g1_mul(g1, i + 2) for i in range(len(messages))]  # Deterministic base points
    m_scalars = encode_attributes(messages)
    e = rand_scalar()
    A = _compute_A(sk, e, h_bases, m_scalars)
    return A, e


def update_attributes(sk: int, sig, messages_old: list[str], updates: dict[int, str]):
    """
    Update message attributes in an existing signature.

    Args:
        sk (int): Private key
        sig: Existing signature (A, e)
        messages_old (list[str]): Original messages
        updates (dict[int, str]): Mapping of message indices to updated values

    Returns:
        A_new (Point2D): Updated elliptic curve point
        e (int): Same random integer as in the original signature
    """
    A_old, e = sig
    messages_new = messages_old[:]
    for idx, v in updates.items():
        messages_new[idx] = v
    h_bases = [g1_mul(g1, i + 2) for i in range(len(messages_new))]
    m_scalars = encode_attributes(messages_new)
    A_new = _compute_A(sk, e, h_bases, m_scalars)
    return A_new, e


def re_randomise(sig):
    """
    Re-randomise an existing signature.

    Args:
        sig: Existing signature (A, e)

    Returns:
        A (Point2D): Same elliptic curve point as the original signature
        e (int): Re-randomised integer
    """
    A, e = sig
    r = rand_scalar()
    return A, (e + r) % curve_order
