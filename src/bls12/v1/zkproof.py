from hashlib import sha256

from ..params import rand_scalar, g1_mul, g2_mul, msm_g1, add, g1, g2, pair, curve_order
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

    commit_scalars = [r_vec[i] for i in hidden_idx]
    commit_bases = [g1_mul(g1, i + 2) for i in hidden_idx]
    commit = msm_g1(commit_bases, commit_scalars)

    return {
        "A": A,
        "e": e,
        "c": c,
        "s": s_vec,
        "commit": commit,
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
    commit = proof["commit"]
    disclosed = proof["disclosed"]

    h_bases = [g1_mul(g1, i + 2) for i in range(total_attrs)]

    msg_commit = g1_mul(g1, c)
    disclosed_scalars = [
        c * disclosed[i] % curve_order for i in sorted(disclosed.keys())
    ]
    disclosed_bases = [h_bases[i] for i in sorted(disclosed.keys())]

    msg_commit = add(msg_commit, msm_g1(disclosed_bases, disclosed_scalars))

    hidden_scalars = [s for s in s_vec.values()]
    hidden_bases = [h_bases[i] for i in s_vec.keys()]
    msg_commit = add(
        msg_commit,
        add(msm_g1(hidden_bases, hidden_scalars), g1_mul(commit, -1)),
    )

    lhs = pair(g1_mul(A, c), add(pk, g2_mul(g2, e)))
    rhs = pair(msg_commit, g2)

    transcript = b"".join(
        [bytes(str(A), "utf8")]
        + [int(disclosed[i]).to_bytes(32, "big") for i in sorted(disclosed)]
        + [bytes(str(pk), "utf8")]
    )

    if c != _hash_fs(transcript):
        print("挑战重构失败")
        return False

    return lhs == rhs
