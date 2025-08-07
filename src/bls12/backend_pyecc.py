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

    高效计算多个基点和标量的乘积和

    Args:
        bases (List[Point2D[Field]]): G1群点的列表[P1, P2, ..., Pn]
        scalars (int): 标量列表[k1, k2, ..., kn]

    Returns:
        Point2D[Field]: ∑(Pi · ki) ∈ G1
    """
    acc = None
    for B, s in zip(bases, scalars):
        pt = g1_mul(B, s)
        acc = add(acc, pt) if acc else pt
    return acc


def pair(P, Q):
    """
    双线性配对运算

    Returns:

    """
    return final_exponentiate(pairing(Q, P))


ecc_add = add
# Import curve parameters and group operations
# curve_order: the order of the elliptic curve group
# G1, G2: generators of the groups G1 and G2 respectively
# add: elliptic curve point addition
# multiply: elliptic curve scalar multiplication

# Import pairing functions
# pairing: bilinear pairing function e: G1 × G2 → GT
# final_exponentiate: final exponentiation step in pairing calculation

# Import cryptographically secure random number generator

# Scalars

# Generate a cryptographically secure random scalar in the range [1, curve_order-1]

# Group helpers

# Scalar multiplication on G1 group
# Inputs: point P in G1, scalar k
# Returns: point k*P on G1

# Scalar multiplication on G2 group
# Inputs: point Q in G2, scalar k
# Returns: point k*Q on G2

# Multi-scalar multiplication on G1
# Efficiently compute the sum of multiple scalar multiplications ∑(P_i * k_i)
# Inputs: list of G1 points bases, list of scalars scalars
# Returns: the combined point in G1

# Bilinear pairing operation
# Inputs: P in G1, Q in G2
# Returns: element in GT after applying final exponentiation

# Alias for point addition function
