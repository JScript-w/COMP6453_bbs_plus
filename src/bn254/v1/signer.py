from ..params import curve_order,rand_scalar, g1_mul, g2_mul, msm_g1, pair, g1, g2, add, curve_order
from .utils import encode_attributes, get_h_bases, ensure_scalar, _scalars_digest, build_U_and_ms


# Internal ------------------------------------------------------------------ #
def _compute_A(x, e, h_bases, m_scalars):
    """
    计算参数 A。
    常见形式：U = g1 + Σ H_i^{m_i}；A = U^{(x+e)^{-1} mod r}
    """
    # 1) 规范化标量类型
    x = int(x) % curve_order
    e = ensure_scalar(e)  # ← 关键：bytes/str/int 都变成 [0, r) 内的 int

    # 2) 基本合法性检查
    if h_bases and m_scalars and len(h_bases) != len(m_scalars):
        raise ValueError(f"len(h_bases)={len(h_bases)} != len(m_scalars)={len(m_scalars)}")

    # 3) 计算 U = g1 + Σ H_i^{m_i}
    hm = msm_g1(h_bases, m_scalars) if m_scalars else None
    U  = add(g1, hm) if hm is not None else g1

    # 4) 计算 (x + e)^(-1) mod r（避免 0）
    denom = (x + e) % curve_order
    if denom == 0:
        # 极小概率事件：e ≡ -x (mod r)
        raise ZeroDivisionError("x + e == 0 (mod r); please resample e")

    denom_inv = pow(denom, -1, curve_order)  # Python 3.8+：负幂求模逆

    # 5) A = U ^ denom_inv
    return g1_mul(U, denom_inv)


# Public API ---------------------------------------------------------------- #
def sign(sk, attrs):
    # 1) 统一构造 U / m_scalars（与 verifier 完全一致）
    U, h_bases, m_scalars = build_U_and_ms(attrs)

    # 2) 随机 e（真实 BBS+ 做法）；调试阶段可改成确定性但两侧要同步
    e = rand_scalar()

    # 3) A = U^{(x+e)^{-1}}
    x = int(sk) % curve_order
    denom = (x + e) % curve_order
    if denom == 0:
        raise ZeroDivisionError("x + e == 0 (mod r); resample e")
    denom_inv = pow(denom, -1, curve_order)
    A = g1_mul(U, denom_inv)

    # 4) 自检（打印一次，便于确认签名内自洽）
    try:
        ok = (pair(A, g2_mul(g2, denom)) == pair(U, g2))
        print("[sign] U vs A check:", ok)
        # 你也可以打印摘要
        # print("[sign] m_digest=", _scalars_digest(m_scalars))
    except Exception:
        pass

    return (A, e)


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



