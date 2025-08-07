from hashlib import sha256
from ..params import rand_scalar, g1_mul, g2_mul, add, g1, g2, pair, curve_order
from .utils import encode_attributes


def _hash_fs(data: bytes) -> int:
    return int.from_bytes(sha256(data).digest(), "big") % curve_order


def prove_disclosure(pk, sig, messages, disclose_idx):
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
            #   h_i^{s_i} · h_i^{-c}  =  h_i^{r_i + c·m_i} · h_i^{-c}
            #                       =  h_i^{r_i} · h_i^{c(m_i-1)}
            #                       → 消掉 c·m_i，留下 h_i^{r_i}
            term = add(
                g1_mul(h_bases[i], s_vec[i]),
                g1_mul(h_bases[i], (-c) % curve_order),
            )
        msg_commit = add(msg_commit, term)

    lhs = pair(A, add(pk, g2_mul(g2, e)))
    rhs = pair(msg_commit, g2)

    transcript = b"".join(
        [bytes(str(A), "utf8")]
        + [int(disclosed[i]).to_bytes(32, "big") for i in sorted(disclosed)]
        + [bytes(str(pk), "utf8")]
    )
    return lhs == rhs and c == _hash_fs(transcript)