import hashlib
from ..params import rand_scalar, g1_mul, g1, curve_order


def hash_to_scalar(data: bytes) -> int:
    """
    Hash mapping from byte string to scalar.

    Function:
        Computes the hash of an arbitrary-length byte string and maps it
        into the scalar field Zp.
    Security:
        Uses SHA-256 to ensure one-wayness and collision resistance.

    Returns:
        int: A value less than the elliptic curve order (curve_order) and not equal to 0.
    """
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % curve_order or 1


def hash_to_g1(label: bytes):
    """
    Map a label to an element in the G1 group.

    Maps the label to a fixed point: g1 * H(label).

    Returns:
        Point2D: An element in the G1 group.
    """
    return g1_mul(g1, hash_to_scalar(label))


def encode_attributes(attrs: list[str]) -> list[int]:
    """
    Encode a list of attributes into scalar values.

    Args:
        attrs (list[str]): List of attribute strings.

    Returns:
        list[int]: List of scalars corresponding to the hashed attributes.
    """
    return [hash_to_scalar(a.encode()) for a in attrs]
