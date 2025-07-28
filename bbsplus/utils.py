import hashlib
from .params import rand_scalar, g1_mul, g1, curve_order

def hash_to_scalar(data: bytes) -> int:
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % curve_order or 1

def hash_to_g1(label: bytes):
    """Map label to fixed point: g1 * H(label)."""
    return g1_mul(g1, hash_to_scalar(label))

def encode_attributes(attrs: list[str]) -> list[int]:
    return [hash_to_scalar(a.encode()) for a in attrs]
