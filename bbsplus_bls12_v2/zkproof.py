from hashlib import sha256
from bbsplus_bls12_v1.params import (
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
from bbsplus_bls12_v1.utils import encode_attributes


def _hash_fs(elements: list) -> int:
    """
    Fiat-Shamir 哈希函数

    Args:
        elements (List): 需要哈希的元素列表

    Returns:
        int: 生成的挑战值 c ∈ Zp
    """

    data = b"BBS_PLUS_PROOF_V1"  # 域分离标识，防止哈希冲突
    for e in elements:
        if isinstance(e, bytes):
            data += e
        elif isinstance(e, int):
            data += e.to_bytes(32, "big")  # 标量转字节
        else:
            data += str(e).encode()  # 元素转字符串再转字节

    # 将数据哈希到标量域
    return int.from_bytes(sha256(data).digest(), "big") % curve_order


def prove_disclosure(
    pk: dict, sig: tuple, messages: list[str], disclose_idx: list[int]
):
    """
    BBS+选择性披露证明

    证明拥有有效签名，同时只披露部分消息

    具体流程：
    1. 将消息分解为披露部分和隐藏部分:
        - {mi}, 其中i ∈ D (D为披露集合)
        - {mj}, 其中j ∈ H (H为隐藏集合)
    2. Prover构造一个承诺值：C = g₁ · h₀ʳ · (∏_{i∈D} hᵢ^{mi})ⁱ · (∏_{j∈H} hⱼ^{mj})
    3. Verifier知道披露的消息，因此他可以计算：C_Known = g₁ · (∏_{i∈D} hᵢ^{mi})
    4. Prover需要计算：C_Hidden = C / C_known = h₀ʳ · (∏_{j∈H} hⱼ^{mj})
    5. Prover然后证明：e(A, X · Yʳ) = e(C_known · C_hidden, g₂)

    Args:
        pk (Dict): 公钥
        sig (Tuple): 签名(A, r)
        messages (List[str]): 完整消息列表
        disclose_idx (List[int]): 要披露的消息索引

    Returns:
        Tuple: 完整的零知识证明
    """

    # 提取签名分量
    A, r = sig
    X = pk["X"]
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # 编码所有消息
    m_scalars = encode_attributes(messages)  # [m1, m2, ..., mL]

    # 分离披露和隐藏消息
    # D = {披露消息}, H = {隐藏消息}
    disclosed_messages = {i: m_scalars[i] for i in disclose_idx}
    hidden_idx = [i for i in range(len(messages)) if i not in disclose_idx]

    # 生成承诺值
