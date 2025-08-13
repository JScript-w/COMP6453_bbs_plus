"""
BBS+ Zero-Knowledge Proof Module - Optimized Version
Implementation of a zero-knowledge proof protocol with selective disclosure
"""

from hashlib import sha256
from typing import Dict, List, Tuple, Any

from ..params import (
    rand_scalar,
    g1_mul,
    g2_mul,
    add,
    msm_g1,
    g1,
    g2,
    pair,
    curve_order,
)
from .utils_v2 import encode_attributes


def _hash_to_challenge(*elements) -> int:
    """
    Fiat–Shamir hash function – Generates the challenge value for a non-interactive zero-knowledge proof.

    Purpose:
        Converts a Sigma protocol from interactive to non-interactive form.
    Security:
        Uses a domain separation tag to prevent cross-protocol attacks.

    Args:
        *elements: Variable-length list of elements to be hashed.

    Returns:
        int: Challenge value c ∈ Zp
    """
    # Domain separation tag to prevent collisions between different protocols
    hasher = sha256(b"BBS_PLUS_ZKPROOF_CHALLENGE_V1")

    for elem in elements:
        if isinstance(elem, bytes):
            hasher.update(elem)
        elif isinstance(elem, int):
            # Ensure all integers are encoded with fixed length
            hasher.update(elem.to_bytes(32, "big"))
        elif isinstance(elem, tuple):  # Handle point coordinates
            # Serialize elliptic curve points
            for coord in elem:
                if isinstance(coord, int):
                    hasher.update(coord.to_bytes(32, "big"))
                else:
                    hasher.update(str(coord).encode())
        else:
            hasher.update(str(elem).encode())

    # Map to scalar field Zp
    digest = hasher.digest()
    return int.from_bytes(digest, "big") % curve_order


def prove_disclosure(
    pk: Dict, sig: Tuple, messages: List[str], disclosed_indices: List[int]
) -> Dict[str, Any]:
    """
    BBS+ selective disclosure proof generation algorithm.

    ========== Mathematical Principle ==========

    1. Sigma protocol commitment phase:
       - Generate random commitments for hidden signature components.
       - r̃ ← Zp (commitment to r)
       - m̃_j ← Zp, ∀j ∈ H (commitments to hidden messages)

    2. Commitment value computation:
       - T₁ = h₀^r̃ · ∏_{j∈H} h_j^m̃_j  (commitment in G1)
       - T₂ = Y^r̃                       (commitment in G2)
       - T₃ = e(A, T₂)                   (pairing commitment for verification)

    3. Fiat–Shamir challenge generation:
       - c = Hash(A, T₁, T₂, T₃, {m_i}_{i∈D})

    4. Schnorr response computation:
       - ẑ_r = r̃ + c·r         (response for r)
       - ẑ_{m_j} = m̃_j + c·m_j, ∀j ∈ H (responses for hidden messages)

    Args:
        pk: Public key {X, Y, h_bases}
        sig: Signature tuple (A, r)
        messages: List of all messages
        disclosed_indices: List of indices of disclosed messages

    Returns:
        Dict: Zero-knowledge proof containing all required components
    """
    # Extract public key components
    X = pk["X"]
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # Extract signature
    A, r = sig

    # ===== Step 1: Message classification =====
    # Encode messages to scalars
    m_scalars = encode_attributes(messages)

    # Separate disclosure set D and hidden set H
    hidden_indices = [i for i in range(len(messages)) if i not in disclosed_indices]
    disclosed_msgs = {i: messages[i] for i in disclosed_indices}
    hidden_scalars = {i: m_scalars[i] for i in hidden_indices}

    # ===== Step 2: Sigma protocol commitment phase =====
    r_tilde = rand_scalar()  # Commitment to r
    m_tildes = {i: rand_scalar() for i in hidden_indices}  # Commitments to hidden messages

    # Compute T₁ = h₀^r̃ · ∏_{j∈H} h_j^m̃_j
    commit_scalars = [r_tilde] + [m_tildes[i] for i in hidden_indices]
    commit_bases = [h_bases[0]] + [h_bases[i + 1] for i in hidden_indices]
    T1 = msm_g1(commit_bases, commit_scalars)

    # Compute T₂ = Y^r̃
    T2 = g2_mul(Y, r_tilde)

    # Compute T₃ = e(A, T₂)
    T3 = pair(A, T2)

    # ===== Step 3: Fiat–Shamir challenge generation =====
    challenge_input = [
        A,
        T1,
        T2,
        T3,
        len(messages),
        tuple(sorted(disclosed_indices)),
        tuple(disclosed_msgs[i] for i in sorted(disclosed_indices)),
    ]
    c = _hash_to_challenge(*challenge_input)

    # ===== Step 4: Schnorr response computation =====
    z_r = (r_tilde + c * r) % curve_order
    z_m = {i: (m_tildes[i] + c * hidden_scalars[i]) % curve_order for i in hidden_indices}

    # Build the proof
    proof = {
        "A": A,
        "T1": T1,
        "T2": T2,
        "c": c,
        "z_r": z_r,
        "z_m": z_m,
        "disclosed_indices": disclosed_indices,
        "disclosed_messages": disclosed_msgs,
        "hidden_indices": hidden_indices,
        "total_messages": len(messages),
    }
    return proof


def verify_disclosure(pk: Dict, proof: Dict) -> bool:
    """
    BBS+ selective disclosure proof verification algorithm.

    ========== Verification Equations ==========

    Main verification checks:

    1. Pairing equation check:
       e(A^c, X · Y^ẑ_r · T₂^{-1}) ?= e(g₁^c · ∏_{i∈D} h_i^{c·m_i} · (∏_{j∈H} h_j^{ẑ_{m_j}} · T₁^{-1}), g₂^c)

    2. Challenge value check:
       c ?= Hash(A, T₁, T₂, T₃, {m_i}_{i∈D})

    Mathematical basis:
    - Completeness of the Schnorr protocol
    - Bilinearity of pairings
    - Soundness of the Fiat–Shamir transform

    Args:
        pk: Public key dictionary
        proof: Zero-knowledge proof dictionary

    Returns:
        bool: Whether the proof is valid
    """
    # Extract public key components
    X = pk["X"]
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # Extract proof components
    A = proof["A"]
    T1 = proof["T1"]
    T2 = proof["T2"]
    c = proof["c"]
    z_r = proof["z_r"]
    z_m = proof["z_m"]

    disclosed_indices = proof["disclosed_indices"]
    disclosed_messages = proof["disclosed_messages"]
    hidden_indices = proof["hidden_indices"]
    total_messages = proof["total_messages"]

    # ===== Step 1: Recompute the challenge value =====
    T3 = pair(A, T2)
    challenge_input = [
        A,
        T1,
        T2,
        T3,
        total_messages,
        tuple(sorted(disclosed_indices)),
        tuple(disclosed_messages[i] for i in sorted(disclosed_indices)),
    ]
    c_verify = _hash_to_challenge(*challenge_input)
    if c != c_verify:
        print("Challenge value verification failed!")
        return False

    # Left side: h₀^{ẑ_r} · ∏_{j∈H} h_j^{ẑ_{m_j}}
    verify_scalars = [z_r] + [z_m[i] for i in hidden_indices]
    verify_bases = [h_bases[0]] + [h_bases[i + 1] for i in hidden_indices]
    left_commit = msm_g1(verify_bases, verify_scalars)

    # ===== Step 2: Main pairing equation verification =====
    # X^c · Y^{ẑ_r} · T₂^{-1}
    X_c = g2_mul(X, c)
    Y_zr = g2_mul(Y, z_r)
    T2_neg = g2_mul(T2, curve_order - 1)
    verify_g2 = add(add(X_c, Y_zr), T2_neg)

    # g₁^c · ∏_{i∈D} h_i^{c·m_i}
    disclosed_scalars = encode_attributes([disclosed_messages[i] for i in sorted(disclosed_indices)])
    B_scalars = [c]
    B_bases = [g1]
    for idx, i in enumerate(sorted(disclosed_indices)):
        B_scalars.append((c * disclosed_scalars[idx]) % curve_order)
        B_bases.append(h_bases[i + 1])
    B_disclosed = msm_g1(B_bases, B_scalars)

    # (left_commit · T₁^{-1})
    hidden_part = add(left_commit, g1_mul(T1, curve_order - 1))
    B = add(B_disclosed, hidden_part)

    # Execute pairing verification
    left_pairing = pair(g1_mul(A, c), verify_g2)
    right_pairing = pair(B, g2_mul(g2, c))
    if left_pairing != right_pairing:
        print("Pairing equation verification failed")
        return False

    return True
