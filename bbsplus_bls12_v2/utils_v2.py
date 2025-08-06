"""
增强工具函数

Version: 0.1
"""

import hashlib
from bbsplus_bls12_v1.params import curve_order


def hash_to_scalar(data: bytes) -> int:
    """
    安全的哈希到标量映射

    功能: 将任意字节串安全地映射到Zp
    安全性: 使用域分离防止不同用途的哈希冲突

    Args:
        data (bytes): 输入字节串
    Returns:
        int: 标量 ∈ Zp
    """

    # 添加域分离前缀
    digest = hashlib.sha256(b"BBS_PLUS_H2S_" + data).digest()

    # 映射到标量域，同时避免0值
    return int.from_bytes(digest, "big") % curve_order or 1


def hash_to_g1(label: bytes):
    """
    使用RFC标准的hash-to-curve算法安全的哈希到G1群映射

    Args:
        label (bytes): 输入标签

    Returns:
        Point2D: G1群元素
    """

    pass


def encode_attributes(attrs: list[str]) -> list[int]:
    """
    属性编码函数

    Args:
        attrs (List[str]): 属性字符串列表

    Returns:
        List[int]: 标量列表
    """

    return [hash_to_scalar(a.encode()) for a in attrs]
