from dataclasses import dataclass

from py_ecc.typing import Point2D

from ..params import g2_mul, rand_scalar, g2
from .utils_v2 import hash_to_g1


# Setting slot to True allows you to:
# 1. Store attributes without using __dict__, but instead reserve a fixed amount of space for each attribute.
# 2. Access attributes faster than looking them up in a dictionary, since they are stored in fixed memory locations.
# 3. Prevent new attributes from being added dynamically.
@dataclass(slots=True)
class KeyPair:
    """
    BBS+ Key Pair Class

    Function: Stores complete BBS+ key information.
    Features: Uses a dual private key structure (x, y), which is more secure than a single private key.
    """

    x: int  # 私钥分量1：随机数 x ∈ Zp
    y: int  # 私钥分量2: 随机数 y ∈ Zp
    X: Point2D  # 公钥分量1: X = g2^x ∈ G2
    Y: Point2D  # 公钥分量2：Y = g2^y ∈ G2
    h_bases: list  # 消息基点：[h0, h1, h2, ...] ∈ G1^(L+1)

    @classmethod
    def generate(cls, max_attributes: int) -> "KeyPair":
        """
        Generate key pair

        Args:
            max_attributes (int): 支持的最大属性数量

        Returns:
            KeyPair: 返回类实例
        """

        # Generate double keys
        x = rand_scalar()
        y = rand_scalar()

        # Calculate the corresponding public key
        X = g2_mul(g2, x)
        Y = g2_mul(g2, y)

        # Generate message base points, (L+1) in total
        h_bases = []

        # h0: The basis of blind factors
        h_bases.append(hash_to_g1(b"BBS_PLUS_H0"))

        # h1, h2, ..., hL: Base points for each message attribute
        for i in range(max_attributes):
            label = f"BBS_PLUS_H{i+1}".encode()  # 为每个属性生成唯一标签
            h_bases.append(hash_to_g1(label))  # 哈希映射到G1群得到独立基点

        return cls(x, y, X, Y, h_bases)

    def get_pk(self):
        """
        Extract public key information

        Returns:
            dict: Public key components
        """

        return {"X": self.X, "Y": self.Y, "h_bases": self.h_bases}
