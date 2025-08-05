from dataclasses import dataclass
from .params import rand_scalar, g2_mul, g2


@dataclass(slots=True)
class KeyPair:
    sk: int  # 私钥：单个随机标量
    pk: tuple  # 公钥：G2群中的点 pk=g2^{sk}

    @classmethod
    def generate(cls) -> "KeyPair":
        sk = rand_scalar()
        pk = g2_mul(g2, sk)
        return cls(sk, pk)
