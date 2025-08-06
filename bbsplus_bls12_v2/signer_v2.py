from bbsplus_bls12_v2.keygen import KeyPair
from bbsplus_bls12_v1.params import curve_order, g1, msm_g1, g1_mul, rand_scalar
from bbsplus_bls12_v1.utils import encode_attributes


def _compute_A(x, y, r, h_bases, m_scalars):
    """
    计算BBS+签名的核心分量A

    具体公式：A = (g1 * h0^r * ∏_{i=1}^L h_i^m_i)^(1/(x + y * r))

    Args:
        x (int): 私钥分量1
        y (int): 私钥分量2
        r (): 随机盲化因子
        h_bases (List[Point2D]): 基点序列[h0, h1, h2, ..., hL]
        m_scalars (int): 消息标量[m1, m2, ..., mL]

    Returns:
        Point2D: A ∈ G1
    """

    # 计算分母的模逆 1/(x + y*r)
    # 即：denom = (x + y*r) mod p，denom_inv = denom^(-1) mod p
    denom = (x + y * r) % curve_order
    denom_inv = pow(denom, -1, curve_order)

    # 计算多标量乘法的输入
    # 即：g1 * h0^r * ∏_{i=1}^L h_i^m_i
    scalars = [1, r] + m_scalars  # 指数序列[1, r, m1, m2, ..., mL]
    bases = [g1, h_bases[0]] + h_bases[
        1 : len(m_scalars) + 1
    ]  # 基点序列[g1, h0, h1, ..., hL]

    sum_pt = msm_g1(bases, scalars)

    # 返回：A = sum_pt^denom_inv
    return g1_mul(sum_pt, denom_inv)


def sign(keypair: KeyPair, messages: list[str]):
    """
    BBS+签名算法主函数

    Args:
        keypair (KeyPair): 密钥对
        messages (List[str]): 待签名的消息列表

    Returns:
        Tuple: 签名σ = (A, r)
    """

    # 编码消息为标量
    # 即：m_i = Hash(messages[i]) for i = 1, ..., L
    m_scalars = encode_attributes(messages)

    # 生成随机盲化因子
    r = rand_scalar()

    # 计算签名分量
    A = _compute_A(keypair.x, keypair.y, r, keypair.h_bases, m_scalars)

    return (A, r)


def update_attributes(
    keypair: KeyPair, sig, messages_old: list[str], updates: dict[int, str]
):
    """
    更新消息属性功能

    在不重新生成随机数的情况下，更新部分消息属性
    优势：保持签名的某些特征，支持增量更新

    Args:
        keypair (KeyPair): 密钥对
        sig (Tuple): 原始签名 (A_old, r)
        messages_old (List[str]): 原始消息列表
        updates (Dict[int, str]): 更新映射 {索引: 新值}

    Returns:
        Tuple: 新签名 (A_new, r)
    """

    A_old, r = sig

    # 更新消息
    messages_new = messages_old[:]
    for idx, new_value in updates.items():
        messages_new[idx] = new_value

    # 重新计算A
    m_scalars = encode_attributes(messages_new)
    A_new = _compute_A(keypair.x, keypair.y, r, keypair.h_bases, m_scalars)

    return (A_new, r)


def re_randomise_plus(keypair: KeyPair, sig, messages: list[str]):
    """
    BBS+签名随机化功能

    生成同一消息的不同签名，提供不可链接性
    和上一个函数一样都是更新签名，上面那个是通过更新消息得到新签名，这个是更新r
    即：给定σ = (A, r)，生成σ' = (A', r')使得两个签名无法关联

    Args:
        keypair (KeyPair): 密钥对
        sig (Tuple[Point2D, int]): 原始签名
        messages (List[str]): 消息列表

    Returns:
        Tuple[Point2D, int]: 随机化后的签名(A', r')
    """

    A, r = sig
    m_scalars = encode_attributes(messages)

    # 生成随机增量
    delta = rand_scalar()
    r_new = (r + delta) % curve_order

    # 重新计算A
    A_new = _compute_A(keypair.x, keypair.y, r_new, keypair.h_bases, m_scalars)

    return (A_new, r_new)
