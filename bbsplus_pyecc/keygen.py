from dataclasses import dataclass
from .params import rand_scalar, g2_mul, g2

@dataclass(slots=True)
class KeyPair:
    sk: int
    pk: tuple          # point in G2

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = rand_scalar()
        pk = g2_mul(g2, sk)
        return cls(sk, pk)
