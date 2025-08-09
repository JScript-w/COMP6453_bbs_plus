"""
Enhanced tool functions

Version: 0.1
"""

import hashlib
from ..params import curve_order, g1_mul, g1


def hash_to_scalar(data: bytes) -> int:
    """
    Secure hash-to-scalar mapping

    Functionality: Securely maps any byte string to Zp
    Security: Uses domain separation to prevent hash collisions between different uses

    Args:
        data (bytes): Input byte string

    Returns:
        int: Scalar ∈ Zp
    """

    # Add domain separation prefix
    digest = hashlib.sha256(b"BBS_PLUS_H2S_" + data).digest()

    # Map to scalar domain while avoiding zero values
    return int.from_bytes(digest, "big") % curve_order or 1


def hash_to_g1(label: bytes):
    """
    Mapping to G1 groups

    Args:
        label (bytes): Input label

    Returns:
        Point2D: G1 group elements
    """

    return g1_mul(g1, hash_to_scalar(label))


def encode_attributes(attrs: list[str]) -> list[int]:
    """
    Attribute encoding function

    Args:
        attrs (List[str]): List of attribute strings

    Returns:
        List[int]: List of scalars
    """

    return [hash_to_scalar(a.encode()) for a in attrs]
