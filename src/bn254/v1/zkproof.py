from hashlib import sha256
from ..params import rand_scalar, g1_mul, g2_mul, add, g1, g2, pair, curve_order
from .utils import encode_attributes


def _hash_fs(data: bytes) -> int:
    return int.from_bytes(sha256(data).digest(), "big") % curve_order


def prove_disclosure(pk, sig, messages, disclose_idx):
    r"""
    Produce a non-interactive selective-disclosure proof for a BBS⁺ signature.

    Let
        g₁∈G₁, g₂∈G₂, e(·,·):G₁×G₂→G_T
        hᵢ = g₁^{i+2}, pk = g₂ˣ, sig = (A,e) with
        A = (g₁ · ∏_{i=0}^{ℓ−1} hᵢ^{mᵢ})^{1/(x+e)}.

    Inputs
    ------
    pk           – issuer public key g₂ˣ
    sig          – (A,e) as above
    messages     – list [m₀,…,m_{ℓ−1}] ∈ 𝔽_p
    disclose_idx – set D ⊂ {0,…,ℓ−1} of revealed positions

    Protocol
    --------
    H ← {0,…,ℓ−1}\D
    for i∈H : rᵢ ←$ 𝔽_p
    c  = Hₚ(A ∥ {mᵢ}_{i∈D} ∥ pk)                  # Fiat–Shamir hash
    sᵢ = rᵢ + c·mᵢ  mod p (i∈H)

    Return proof
    π = (A , e , c , {sᵢ}_{i∈H} , {mᵢ}_{i∈D})
    """
    A, e = sig
    m_scalars = encode_attributes(messages)
    disclosed = {i: m_scalars[i] for i in disclose_idx}
    hidden_idx = [i for i in range(len(messages)) if i not in disclose_idx]

    r_vec = {i: rand_scalar() for i in hidden_idx}

    transcript = b"".join(
        [
            bytes(str(A), "utf8"),
            *[int(disclosed[i]).to_bytes(32, "big") for i in disclose_idx],
            bytes(str(pk), "utf8"),
        ]
    )
    c = _hash_fs(transcript)
    s_vec = {i: (r_vec[i] + c * m_scalars[i]) % curve_order for i in hidden_idx}

    return {
        "A": A,
        "e": e,
        "c": c,
        "s": s_vec,
        "disclosed": disclosed,
    }


def verify_disclosure(pk, proof, total_attrs):
    r"""
    Verify a selective-disclosure proof π for BBS⁺.

    Proof structure
        π = (A , e , c , {sᵢ}_{i∈H} , {mᵢ}_{i∈D}), H∪D = {0,…,ℓ−1}, H∩D = ∅.

    Step 1 – Rebuild commitment
        C = g₁ · ∏_{i∈D} hᵢ^{mᵢ} · ∏_{i∈H} hᵢ^{sᵢ} · A^{-c}

    Step 2 – Pairing check
        e(A , pk·g₂ᵉ)  ==  e(C , g₂)

    Step 3 – Fiat–Shamir consistency
        c == Hₚ(A ∥ {mᵢ}_{i∈D} ∥ pk)

    Accept iff all three conditions hold.
    """

    A, e = proof["A"], proof["e"]
    c = proof["c"]
    s_vec = proof["s"]
    disclosed = proof["disclosed"]

    h_bases = [g1_mul(g1, i + 2) for i in range(total_attrs)]

    msg_commit = g1
    for i in range(total_attrs):
        if i in disclosed:
            term = g1_mul(h_bases[i], disclosed[i])
        else:
            term = g1_mul(h_bases[i], s_vec[i])
        msg_commit = add(msg_commit, term)

    msg_commit = add(msg_commit, g1_mul(A, (-c) % curve_order))

    lhs = pair(A, add(pk, g2_mul(g2, e)))
    rhs = pair(msg_commit, g2)

    transcript = b"".join(
        [bytes(str(A), "utf8")]
        + [int(disclosed[i]).to_bytes(32, "big") for i in sorted(disclosed)]
        + [bytes(str(pk), "utf8")]
    )
    """pair_ok = (lhs == rhs)
    chal_ok = (c == _hash_fs(transcript))
    print("[debug] pair_ok=", pair_ok, "chal_ok=", chal_ok)
    return pair_ok and chal_ok"""
    return lhs == rhs and c == _hash_fs(transcript)
