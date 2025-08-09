from hashlib import sha256

from bls12.v2.keygen_v2 import KeyPair
from bls12.v2.signer_v2 import compute_A
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


def _hash_fs(elements: list) -> int:
    """
    Fiat-Shamir Hash Function

    Function: Convert Sigma protocol interactive proofs to non-interactive proofs

    Args:
        elements (List): List of elements requiring hashing

    Returns:
        int: Generated challenge value c ∈ Zp
    """

    data = b"BBS_PLUS_PROOF_V1"  # Domain separation identification to prevent hash collisions
    for e in elements:
        if isinstance(e, bytes):
            data += e
        elif isinstance(e, int):
            data += e.to_bytes(32, "big")  # Scalar to bytes
        else:
            data += str(e).encode()  # Convert elements to strings and then to bytes

    # Hash data to scalar domain
    return int.from_bytes(sha256(data).digest(), "big") % curve_order


def prove_disclosure(
    keypair: KeyPair, sig: tuple, messages: list[str], disclose_idx: list[int]
):
    """
    Selective disclosure certification

    Specific process (Sigma protocol):
    1. Break down the message into a disclosure part and a hidden part:
        - {mi}, where i ∈ D (D is the disclosure set)
        - {mj}, where j ∈ H (H is the hidden set)
    2. Prover construct a commitment value: C = g₁ · h₀ʳ · (∏_{i∈D} hᵢ^{mi})ⁱ · (∏_{j∈H} hⱼ^{mj})
    3. Verifier knows the disclosed messages, then he can calculate: C_Known = g₁ · (∏_{i∈D} hᵢ^{mi})
    4. Prover needs to calculate: C_Hidden = C / C_known = h₀ʳ · (∏_{j∈H} hⱼ^{mj})
    5. Verifier check: e(A, X · Yʳ) = e(C_known · C_hidden, g₂)

    Args:
        pk (Dict): Public key
        sig (Tuple): Signature (A, r)
        messages (List[str]): List of all messages
        disclose_idx (List[int]): Index of message to be disclosed

    Returns:
        Tuple: Proof
    """

    # Extract components of signature
    A, r = sig
    pk = keypair.get_pk()
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # Encode all messages
    m_scalars = encode_attributes(messages)  # [m1, m2, ..., mL]

    # Separate disclosure and hidden messages
    # D = {Disclosed messages}, H = {Hidden messages}
    disclosed_messages = {i: m_scalars[i] for i in disclose_idx}
    hidden_idx = [i for i in range(len(messages)) if i not in disclose_idx]

    # Sigma协议第一阶段：生成承诺值

    # 为所有隐藏变量生成随机值
    r_prime = rand_scalar()
    m_primes = {i: rand_scalar() for i in hidden_idx}

    # 计算承诺值 - 仅包含隐藏部分消息的随机化标量
    # 公式：C1 = h0^r' · (∏_{j∈H} hj^{mj'})
    commit_scalars = [r_prime] + [m_primes[i] for i in hidden_idx]
    commit_bases = [h_bases[0]] + [h_bases[i + 1] for i in hidden_idx]
    C1 = msm_g1(commit_bases, commit_scalars)

    # 计算G2中的承诺
    # 公式：C2 = Y^r'
    C2 = g2_mul(Y, r_prime)

    # 计算配对承诺
    T1 = pair(A, C2)
    T2 = pair(C1, g2)

    # Sigma协议第二阶段：挑战

    # 构建生成挑战的输入信息
    challenge_elements = [
        A,
        C1,
        C2,
        T1,
        T2,
        *[disclosed_messages[i] for i in sorted(disclose_idx)],  # 披露的消息
    ]

    # 生成挑战
    c = _hash_fs(challenge_elements)

    # 计算随机的A：A' = (g1 * h0^r * (∏ hl^{ml}))^(1/x+y*r')
    A_prime = compute_A(keypair, r_prime, h_bases, m_scalars)

    # Sigma协议第三阶段：响应

    # 计算r的响应值：z_r = r' + c * r
    zr = (r_prime + c * r) % curve_order

    # 计算z_{mi} = m' + c * mi (for i ∈ H)
    zm = {i: (m_primes[i] + c * m_scalars[i]) % curve_order for i in hidden_idx}

    hidden_scalars = [r] + [m_scalars[i] for i in hidden_idx]
    hidden_bases = [h_bases[0]] + [h_bases[i + 1] for i in hidden_idx]
    hidden_commit = g1_mul(msm_g1(hidden_bases, hidden_scalars), c)

    return {
        "A": A,
        "C1": C1,
        "C2": C2,
        "c": c,
        "zr": zr,
        "zm": zm,
        "disclosed_messages": disclosed_messages,
        "hidden_idx": hidden_idx,
        "hidden_commit": hidden_commit,
    }


def verify_disclosure(pk: dict, proof: dict, total_attrs: int):
    """
    BBS+选择性披露验证

    验证逻辑:
    1. 重建承诺值 (使用响应值z和挑战c)
    2. 检查配对等式
    3. 验证Fiat-Shamir挑战

    Args:
        pk (Dict): 公钥
        proof (Dict): 零知识证明π
        total_attrs (int): 总属性数量

    Returns:
        bool: 证明是否有效
    """

    # 提取公钥
    X = pk["X"]
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # 提取证明组件
    A = proof["A"]
    C1 = proof["C1"]
    C2 = proof["C2"]
    c = proof["c"]
    zr = proof["zr"]
    zm = proof["zm"]
    disclosed_messages = proof["disclosed_messages"]
    hidden_idx = proof["hidden_idx"]

    # 验证第一阶段：检查Fiat-Shamir挑战

    T1 = pair(A, C2)
    T2 = pair(C1, g2)

    # 重建挑战
    challenge_elements = [
        A,
        C1,
        C2,
        T1,
        T2,
        *[disclosed_messages[i] for i in disclosed_messages.keys()],
    ]
    c_rebuilt = _hash_fs(challenge_elements)

    if c != c_rebuilt:
        return False

    # 验证第二阶段：重建承诺值

    # 构建披露部分消息的承诺
    # 公式：disclosed_commit = ∏_{i∈D} hi^{mi}
    if disclosed_messages:
        disclosed_scalars = [
            disclosed_messages[i] for i in sorted(disclosed_messages.keys())
        ]
        disclosed_bases = [h_bases[i + 1] for i in sorted(disclosed_messages.keys())]
        disclosed_commit = msm_g1(disclosed_bases, disclosed_scalars)
    else:
        disclosed_commit = None

    # 构建完整消息承诺
    # 公式：full_commit = g1 · disclosed_commit · C1'^(1/c)
    # C1' = h0^{zr} * (∏_{j∈H} hj^{z_{mj}}) * C1^(-1)
    full_commit = g1

    if disclosed_commit:
        full_commit = add(full_commit, disclosed_commit)

    full_commit = g1_mul(full_commit, c)

    scalars = [zr] + [zmj for zmj in zm] + [-1]
    bases = [h_bases[0]] + [h_bases[j + 1] for j in hidden_idx] + [C1]
    C1_prime = msm_g1(bases, scalars)  # h0^{zr} * (∏_{j∈H} hj^{z_{mj}}) * C1^(-1)
    print(C1_prime)

    print("========================================================")
    print(proof["hidden_commit"])
    full_commit = add(full_commit, C1_prime)

    # 验证第二阶段：检查配对等式 e(A^c, X * Y^{zr} * C2^(-1)) = e(full_commit, g2)

    # 重建左等式右边的g2
    # 公式：right_g2 = X * Y^{zr} * C2^(-1)
    Yzr = g2_mul(Y, zr)  # Y^{zr}
    C2_power_neg_c = g2_mul(C2, -1)  # C2^(-1)
    Ycr = add(Yzr, C2_power_neg_c)
    right_g2 = add(X, Ycr)

    # 分别计算等式两边的值
    left = pair(g1_mul(A, c), right_g2)  # e(A^c, X * Y^{zr} * C2^(-1))
    right = pair(full_commit, g2)  # e(完整承诺, g2)

    return left == right
