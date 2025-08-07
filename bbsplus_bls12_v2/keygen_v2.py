from dataclasses import dataclass

from py_ecc.typing import Point2D

from bbsplus_bls12_v1.backend_pyecc import g2_mul, rand_scalar
from bbsplus_bls12_v1.params import g2
from utils_v2 import hash_to_g1


# 将slot设置为True可以：
# 1. 不使用 __dict__存储属性，而是为每个属性预留固定大小的空间
# 2. 由于属性存储在固定的内存位置，访问速度会比通过字典查找更快。
# 3. 防止动态添加新属性
@dataclass(slots=True)
class KeyPair:
    """
    BBS+密钥对类

    功能：存储BBS+完整密钥信息
    特点：使用双私钥结构(x, y)，比单私钥更安全
    """

    x: int  # 私钥分量1：随机数 x ∈ Zp
    y: int  # 私钥分量2: 随机数 y ∈ Zp
    X: Point2D  # 公钥分量1: X = g2^x ∈ G2
    Y: Point2D  # 公钥分量2：Y = g2^y ∈ G2
    h_bases: list  # 消息基点：[h0, h1, h2, ...] ∈ G1^(L+1)

    @classmethod
    def generate(cls, max_attributes: int) -> "KeyPair":
        """
        生成密钥对

        Args:
            max_attributes (int): 支持的最大属性数量

        Returns:
            KeyPair: 返回类实例
        """

        # 生成双私钥
        x = rand_scalar()
        y = rand_scalar()

        # 计算对应公钥
        X = g2_mul(g2, x)
        Y = g2_mul(g2, y)

        # 生成消息基点，共(L+1)个
        h_bases = []

        # h0: 盲化因子的基点
        h_bases.append(hash_to_g1(b"BBS_PLUS_H0"))

        # h1, h2, ..., hL: 各消息属性的基点
        for i in range(max_attributes):
            label = f"BBS_PLUS_H{i+1}".encode()  # 为每个属性生成唯一标签
            h_bases.append(hash_to_g1(label))  # 哈希映射到G1群得到独立基点

        return cls(x, y, X, Y, h_bases)

    def get_pk(self):
        """
        提取公钥信息

        Returns:
            dict: 可以公开的密钥组件
        """

        return {"X": self.X, "Y": self.Y, "h_bases": self.h_bases}
