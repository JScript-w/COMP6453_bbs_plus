from dataclasses import dataclass
from ..params import rand_scalar, g2_mul, g2


@dataclass(slots=True)
class KeyPair:
    sk: int  # Private key: a single random scalar
    pk: tuple  # Public key: a point in the G2 group, pk = g2^{sk}

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = rand_scalar()  # Generate a random scalar as the private key
        pk = g2_mul(g2, sk)  # Compute the public key by multiplying g2 with sk
        return cls(sk, pk)  # Return the KeyPair object
