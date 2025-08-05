"""
后端抽象层

提供椭圆曲线运算的统一接口，基于py_ecc库封装
"""

from py_ecc.bls12_381.bls12_381_curve import (
    curve_order,  # 椭圆曲线的阶数p
    G1,  # G1群的生成元 (椭圆曲线上的点)
    G2,  # G2群的生成元 (扭曲椭圆曲线上的点)
    add,  # 椭圆曲线点加法运算
    multiply,  # 椭圆曲线标量乘法运算
)

from py_ecc.bls12_381.bls12_381_pairing import (
    pairing,  # 双线性配对 e: G1 × G2 → GT
    final_exponentiate,  # 配对的最终指数运算
)


import secrets

# -----------------------------------------------
# Scalars 标量运算函数


def rand_scalar() -> int:
    """
    生成加密学安全的随机标量

    Returns:
        int: a random scalar ∈ ℤₚ \\ {0}.
    """
    return secrets.randbelow(curve_order - 1) + 1


# ----------------------------
# Group helpers 群运算辅助函数


def g1_mul(P, k: int):
    """
    G1群上的标量乘法

    这个函数接受参数P和k，返回生成元g1，

    Args:
        P (Point2D): G1内的点
        k (int): Zp内的标量

    Returns:
        Point2D: 椭圆曲线上的点坐标
    """
    return multiply(P, k % curve_order)  # (k mod curve_order)确保在正确范围内


def g2_mul(Q, k: int):
    """
    G2群上的标量乘法

    Args:
        Q (Point2D): G2内的点
        k (int): Zp内的标量

    Returns:
        Point2D: G2内的点
    """
    return multiply(Q, k % curve_order)


def msm_g1(bases, scalars):
    """
    多标量乘法
    """
    acc = None
    for B, s in zip(bases, scalars):
        pt = g1_mul(B, s)
        acc = add(acc, pt) if acc else pt
    return acc


def pair(P, Q):
    """
    双线性配对运算
    """
    return final_exponentiate(pairing(Q, P))


ecc_add = add
