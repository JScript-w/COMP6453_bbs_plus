# BLS椭圆曲线实现BBS+签名 v1.0

## 核心数学公式

### 密钥

- 私钥：$sk \in \mathbb{Z}_p$ (单个随机标量)
- 公钥：$pk = g_2^{sk}$

### 签名

签名结构：$(A, e)$

- $A = (g_1 \cdot \prod{h_i}^{m_i})^{(\frac{1}{(sk+e)} \mod p)}$
- $e \in \mathbb{Z}_p$
