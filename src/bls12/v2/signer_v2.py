from .keygen_v2 import KeyPair
from ..params import curve_order, g1, msm_g1, g1_mul, rand_scalar
from .utils_v2 import encode_attributes


def compute_A(keypair: KeyPair, r, h_bases, m_scalars):
    """
    Calculate the core component A of BBS+ signature

    Formula: A = (g1 * h0^r * ∏_{i=1}^L h_i^m_i)^(1/(x + y * r))

    Args:
        r (int): Randomization factor
        h_bases (List[Point2D]): Base sequence[h0, h1, h2, ..., hL]
        m_scalars (int): 消息标量[m1, m2, ..., mL]

    Returns:
        Point2D: A ∈ G1
    """

    # Extract private key
    # x (int): Private key component 1
    # y (int): Private key component 2
    x = keypair.x
    y = keypair.y

    # Calculate the reciprocal of the denominator 1/(x + y*r)
    # e.g., denom = (x + y*r) mod p，denom_inv = denom^(-1) mod p
    denom = (x + y * r) % curve_order
    denom_inv = pow(denom, -1, curve_order)

    # Calculate the input for multi-scalar multiplication
    # e.g., g1 * h0^r * ∏_{i=1}^L h_i^m_i
    scalars = [1, r] + m_scalars  # exponential sequence: [1, r, m1, m2, ..., mL]
    bases = [g1, h_bases[0]] + h_bases[
        1 : len(m_scalars) + 1
    ]  # Base points sequence: [g1, h0, h1, ..., hL]

    sum_pt = msm_g1(bases, scalars)

    # Returns: A = sum_pt^denom_inv
    return g1_mul(sum_pt, denom_inv)


def sign(keypair: KeyPair, messages: list[str]):
    """
    BBS+ Signature Algorithm Main Function

    Args:
        keypair (KeyPair): Key pair
        messages (List[str]): List of messages awaiting signature

    Returns:
        Tuple: Signature σ = (A, r)
    """

    # Encode message as scalar
    # e.g., m_i = Hash(messages[i]) for i = 1, ..., L
    m_scalars = encode_attributes(messages)

    # Generate random blinding factors
    r = rand_scalar()

    # Calculate signature components
    A = compute_A(keypair, r, keypair.h_bases, m_scalars)

    return (A, r)


def update_attributes(
    keypair: KeyPair, sig, messages_old: list[str], updates: dict[int, str]
):
    """
    Update message attribute function

    Update some message attributes without regenerating random numbers.
    Advantages: Maintain certain characteristics of signatures and support incremental updates.

    Args:
        keypair (KeyPair): Key pair
        sig (Tuple): Original signature (A_old, r)
        messages_old (List[str]): List of original messages
        updates (Dict[int, str]): Update mapping {index: new value}

    Returns:
        Tuple: New signature (A_new, r)
    """

    A_old, r = sig

    # Update messages
    messages_new = messages_old[:]
    for idx, new_value in updates.items():
        messages_new[idx] = new_value

    # Recalculate A
    m_scalars = encode_attributes(messages_new)
    A_new = compute_A(keypair, r, keypair.h_bases, m_scalars)

    return (A_new, r)


def re_randomise(keypair: KeyPair, sig, messages: list[str]):
    """
    BBS+ Signature Randomization Function

    Generates different signatures for the same message, providing unlinkability.
    Like the previous function, this function updates the signature. The previous function obtained a new signature by updating the message, while this function updates r.
    That is, given σ = (A, r), generate σ' = (A', r') so that the two signatures cannot be linked.

    Args:
        keypair (KeyPair): Key pair
        sig (Tuple[Point2D, int]): Original signature
        messages (List[str]): List of messages

    Returns:
        Tuple[Point2D, int]: Randomized signature (A', r')
    """

    A, r = sig
    m_scalars = encode_attributes(messages)

    # Generate random increments
    delta = rand_scalar()
    r_new = (r + delta) % curve_order

    # Recalculate A
    A_new = compute_A(keypair, r_new, keypair.h_bases, m_scalars)

    return (A_new, r_new)
