from __future__ import annotations
from bn254 import backend_pyecc as ecc

class KeyPair:
    """KeyPair structure for BBS+ on BN254."""
    def __init__(self, sk: int | bytes | None = None):
        ecc._ensure_mcl()
        # Generate a random secret key if not provided
        if sk is None:
            sk_int = ecc.rand_scalar()
        else:
            # If provided as bytes or int, normalize to int
            if isinstance(sk, bytes):
                sk_int = int.from_bytes(sk, 'big') % ecc.curve_order
            elif isinstance(sk, int):
                sk_int = sk % ecc.curve_order
            else:
                raise TypeError("Unsupported secret key type")
            if sk_int == 0:
                # Ensure non-zero
                sk_int = ecc.rand_scalar()
        # Compute public key as G2^sk
        pk_point = ecc.g2_mul(ecc.g2, sk_int)
        # Store keys (sk as 32-byte scalar, pk in compressed form)
        self.sk: bytes = sk_int.to_bytes(32, 'big')
        self.pk = pk_point.serialize() if hasattr(pk_point, "serialize") else bytes(pk_point)

    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a new random KeyPair."""
        return cls()

    def __iter__(self):
        # Enable unpacking to (sk, pk)
        yield self.sk
        yield self.pk

def keygen() -> tuple[bytes, bytes]:
    """
    Generate a BBS+ key pair on BN254.
    Returns (sk_bytes, pk_bytes).
    """
    kp = KeyPair.generate()
    return (kp.sk, kp.pk)
