import hashlib
from .params import rand_scalar, g1_mul, g1, curve_order


def hash_to_scalar(data: bytes) -> int:
    """
    字节串到标量的哈希映射

    功能：将任意长度的字节串计算Hash后映射到标量域Zp
    安全性：使用SHA-256确保单向性和抗碰撞性

    Returns:
        int: 返回值小于椭圆曲线的阶数curve_order，同时不为0
    """
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % curve_order or 1


def hash_to_g1(label: bytes):
    """
    标签到G1群元素的映射

    Map label to fixed point: g1 * H(label).
    """
    return g1_mul(g1, hash_to_scalar(label))


def encode_attributes(attrs: list[str]) -> list[int]:
    return [hash_to_scalar(a.encode()) for a in attrs]
