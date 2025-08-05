from .params import rand_scalar, g1_mul, g2_mul, msm_g1, pair, g1, g2, add, curve_order
from .utils import encode_attributes


# Internal ------------------------------------------------------------------ #
def _compute_A(x, e, h_bases, m_scalars):
    """
    计算参数A，用于后续签名和验证

    计算公式：A = (g1 * h0)

    Args:
        x (int): 私钥
        e (int): 随机选择的整数
        h_bases (Point2D): 确定性基点
        m_scalars ()
    """
    denom_inv = pow(x + e, -1, curve_order)  # 计算：1/(x+e) % curve_order
    h_part = msm_g1(h_bases, m_scalars) if m_scalars else None
    sum_pt = add(g1, h_part) if h_part else g1
    return g1_mul(sum_pt, denom_inv)


# Public API ---------------------------------------------------------------- #
def sign(sk: int, messages: list[str]):
    """
    签名算法

    Args:
        sk (int): 私钥
        messages (list[str]): 要加密的信息

    Returns:
        A (Point2D): 椭圆曲线上的点，用于后续签名和验证
        e (int): 随机整数
    """
    h_bases = [g1_mul(g1, i + 2) for i in range(len(messages))]  # 确定性基点
    m_scalars = encode_attributes(messages)
    e = rand_scalar()
    A = _compute_A(sk, e, h_bases, m_scalars)
    return A, e


def update_attributes(sk: int, sig, messages_old: list[str], updates: dict[int, str]):
    A_old, e = sig
    messages_new = messages_old[:]
    for idx, v in updates.items():
        messages_new[idx] = v
    h_bases = [g1_mul(g1, i + 2) for i in range(len(messages_new))]
    m_scalars = encode_attributes(messages_new)
    A_new = _compute_A(sk, e, h_bases, m_scalars)
    return A_new, e


def re_randomise(sig):
    A, e = sig
    r = rand_scalar()
    return A, (e + r) % curve_order
