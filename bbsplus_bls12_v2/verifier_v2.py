"""
BBS+验证器

Version: v0.1
"""

from bbsplus_bls12_v1.params import g1, g2, add, g2_mul, msm_g1, pair
from bbsplus_bls12_v1.utils import encode_attributes


def verify(pk: dict, sig: tuple, messages: list[str]):
    """
    BBS+签名验证算法

    计算公式：e(A, X · Y^r) = e(g1 · h0^r · ∏_{i=1}^{L}h_i^m_i, g2)

    验证原理:
    已知 e(aP, bQ) = e(P,Q)^{ab}，因此可得
    1. 左边: e(A, X · Y^r) = e(A, g2^x · g2^(y·r)) = e(A, g2^(x + y·r))
    2. 右边: e(g1 · h0^r · ∏h_i^m_i, g2)
    3. 由于A = (g1 · h0^r · ∏h_i^m_i)^(1/(x + y·r))
    4. 所以左边 = e((...)^(1/(x + y·r)), g2^(x + y·r)) = e(..., g2) = 右边

    Args:
        pk (Dict): 公钥(public key)字典 {X, Y, h_bases}
        sig (Tuple[Point2D, int]): 签名 (A, r)
        messages (List[str]): 消息列表

    Returns:
        bool: 签名是否有效
    """

    # 提取签名分量
    A, r = sig

    # 提取公钥分量
    X = pk["X"]
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # 编码消息为标量，即计算消息的哈希值
    # mi = Hash(messages[i])
    m_scalars = encode_attributes(messages)

    # 构建消息承诺
    # 即：msg_commit = g1 · h0^r · ∏_{i=1}^{L} h_i^m_i
    scalars = [1, r] + m_scalars  # [1, r, m1, m2, ..., mL]
    bases = [g1, h_bases[0]] + h_bases[1 : len(m_scalars) + 1]  # [g1, h0, h1, ..., hL]
    msg_commit = msm_g1(bases, scalars)

    # 构建验证等式左边
    # 即：e(A, X · Y^r)
    Yr = g2_mul(Y, r)  # Y^r = g2^(y·r)
    left_g2 = add(X, Yr)  # X · Y^r = g2^x · g2^(y·r) = g2^(x + y·r)
    left = pair(A, left_g2)  # e(A, X · Y^r) -> e(A, g2^(x + y·r))

    # 构建验证等式右边
    # 即：e(g1 · h0^r · ∏hi^{mi}, g2)
    right = pair(msg_commit, g2)

    return left == right
