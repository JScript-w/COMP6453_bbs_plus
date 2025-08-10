# BBS+ 签名方案实现

## 📋 项目简介

本项目是BBS+（Boneh-Boyen-Shacham Plus）签名方案的Python实现，支持选择性披露和零知识证明。BBS+是一种基于配对的短签名方案，特别适用于需要隐私保护的数字身份和凭证系统。

### 核心特性

- ✅ **短签名**: 无论签名消息数量多少，签名大小固定
- ✅ **选择性披露**: 可以选择性地披露部分签名消息，隐藏其他消息
- ✅ **零知识证明**: 证明拥有有效签名而不泄露签名本身
- ✅ **签名随机化**: 支持签名的重新随机化，提供不可链接性
- ✅ **动态更新**: 支持在不重新生成随机数的情况下更新消息属性

## 🏗️ 项目结构

```
bbs_plus/
├── __init__.py           # 模块导出接口
├── keygen_v2.py          # 密钥生成模块
├── signer_v2.py          # 签名生成、更新和随机化
├── verifier_v2.py        # 签名验证模块
├── zkproof_v2.py         # 零知识证明生成和验证
└── utils_v2.py           # 工具函数（哈希、编码等）
```

### 模块功能说明

| 模块             | 功能       | 主要接口                                                  |
| ---------------- | ---------- | --------------------------------------------------------- |
| `keygen_v2.py`   | 密钥对生成 | `KeyPair.generate(max_attributes)`                        |
| `signer_v2.py`   | 签名操作   | `sign()`, `update_attributes()`, `re_randomise()`         |
| `verifier_v2.py` | 签名验证   | `verify()`                                                |
| `zkproof_v2.py`  | 零知识证明 | `prove_disclosure()`, `verify_disclosure()`               |
| `utils_v2.py`    | 辅助函数   | `hash_to_scalar()`, `hash_to_g1()`, `encode_attributes()` |

## 🔢 数学原理

### 1. 基础设置

BBS+签名基于**Type-3双线性配对群**，使用三个循环群：

- **G₁, G₂**: 阶为素数p的椭圆曲线群
- **Gₜ**: 目标群
- **配对函数**: e: G₁ × G₂ → Gₜ

### 2. 密钥结构

与传统签名方案不同，BBS+使用**双私钥结构**：

```
私钥: (x, y) ∈ Zₚ × Zₚ
公钥: (X, Y) = (g₂ˣ, g₂ʸ) ∈ G₂ × G₂
基点: {h₀, h₁, ..., hₗ} ∈ G₁
```

其中：

- `h₀`: 用于盲化因子的基点
- `h₁, ..., hₗ`: 每个消息属性对应的基点

### 3. 签名生成

对于消息集合 `{m₁, m₂, ..., mₗ}`，签名算法：

```
1. 选择随机数 r ← Zₚ
2. 计算 A = (g₁ · h₀ʳ · ∏ᵢ₌₁ˡ hᵢᵐⁱ)^(1/(x + y·r))
3. 输出签名 σ = (A, r)
```

**核心公式**：

$A = (g₁ \cdot h_0^r \cdot \prod_{i=1}^l h_i^mⁱ)^(\frac{1}{x + y·r})$

### 4. 签名验证

验证方程基于配对的双线性性质：

$e(A, X \cdot Y^r) ?= e(g₁ · h_0^r \cdot ∏ᵢ₌₁ˡ hᵢᵐⁱ, g₂)$

**验证原理**：

- 左边：`e(A, X · Yʳ) = e(A, g₂ˣ · g₂ʸʳ) = e(A, g₂^(x+y·r))`
- 右边：`e(g₁ · h₀ʳ · ∏hᵢᵐⁱ, g₂)`
- 由于 `A = (...)^(1/(x+y·r))`，两边相等

### 5. 零知识证明（选择性披露）

使用**Schnorr-like Sigma协议**实现选择性披露：

#### 证明生成步骤：

1. **承诺阶段**：
   - 为隐藏值生成随机承诺：`r̃ ← Zₚ`, `m̃ⱼ ← Zₚ`
   - 计算承诺：`T₁ = h₀^r̃ · ∏ⱼ∈H hⱼ^m̃ⱼ`
   - 计算：`T₂ = Y^r̃`

2. **挑战生成**（Fiat-Shamir）：
   - `c = Hash(A, T₁, T₂, T₃, {mᵢ}ᵢ∈D)`

3. **响应计算**：
   - `ẑᵣ = r̃ + c·r`
   - `ẑₘⱼ = m̃ⱼ + c·mⱼ` (对所有隐藏消息)

#### 验证方程：

验证者检查：

- 承诺重构：`T₁ ?= h₀^ẑᵣ · ∏ⱼ∈H hⱼ^ẑₘⱼ · T₁^(-c)`
- 配对验证：`e(A^c, X · Y^ẑᵣ · T₂^(-1)) ?= e(B, g₂^c)`

## 🚀 使用示例

### 基础签名和验证

```python
from bbs_plus import KeyPair, sign, verify

# 生成密钥对（支持5个属性）
keypair = KeyPair.generate(max_attributes=5)

# 准备消息
messages = ["姓名:张三", "年龄:25", "城市:北京", "职业:工程师", "薪资:50000"]

# 生成签名
signature = sign(keypair, messages)

# 提取公钥
pk = keypair.get_pk()

# 验证签名
is_valid = verify(pk, signature, messages)
print(f"签名验证结果: {is_valid}")
```

### 选择性披露

```python
from bbs_plus import prove_disclosure, verify_disclosure

# 选择披露的消息索引（只披露姓名和城市）
disclosed_indices = [0, 2]  # 披露第1个和第3个消息

# 生成零知识证明
proof = prove_disclosure(pk, signature, messages, disclosed_indices)

# 验证者只能看到披露的消息，其他消息保持隐藏
is_valid = verify_disclosure(pk, proof)
print(f"选择性披露验证结果: {is_valid}")
```

### 消息更新

```python
from bbs_plus import update_attributes

# 更新某些属性（例如更新年龄和薪资）
updates = {
    1: "年龄:26",  # 更新第2个消息
    4: "薪资:60000"  # 更新第5个消息
}

# 生成新签名（保持相同的r值）
new_signature = update_attributes(keypair, signature, messages, updates)
```

### 签名随机化

```python
from bbs_plus import re_randomise

# 重新随机化签名（生成不可链接的新签名）
randomized_sig = re_randomise(keypair, signature, messages)

# 新签名仍然有效，但与原签名不可链接
is_valid = verify(pk, randomized_sig, messages)
```

## 🔄 与BBS签名的对比优势

| 特性           | BBS签名        | BBS+签名       | 优势说明                |
| -------------- | -------------- | -------------- | ----------------------- |
| **签名大小**   | 3个群元素      | 2个元素 (A, r) | ✅ **更短的签名**       |
| **验证效率**   | 需要多次配对   | 2次配对运算    | ✅ **更高效的验证**     |
| **密钥结构**   | 单私钥         | 双私钥 (x, y)  | ✅ **更强的安全性**     |
| **消息承诺**   | 复杂的承诺结构 | 简化的线性结构 | ✅ **更简单的实现**     |
| **零知识证明** | 复杂的证明协议 | 标准Sigma协议  | ✅ **更清晰的证明逻辑** |
| **随机化**     | 需要重新计算   | 高效的重随机化 | ✅ **更好的隐私保护**   |
| **批量操作**   | 有限支持       | 优化的批量验证 | ✅ **更好的可扩展性**   |

### 具体优势分析

1. **更紧凑的签名**
   - BBS+签名只需要 `(A, r)` 两个元素
   - 在BLS12-381曲线上，签名大小约96字节

2. **更强的安全性**
   - 双私钥结构 `(x, y)` 提供额外的安全层
   - 基于q-SDH假设，在标准模型下可证明安全

3. **更灵活的消息处理**
   - 支持动态消息更新而不改变随机数
   - 高效的增量更新机制

4. **更好的隐私特性**
   - 签名随机化提供完美的不可链接性
   - 选择性披露不泄露任何隐藏消息的信息

## 📊 性能特征

| 操作     | 时间复杂度 | 空间复杂度 |
| -------- | ---------- | ---------- |
| 密钥生成 | O(L)       | O(L)       |
| 签名生成 | O(L)       | O(1)       |
| 签名验证 | O(L)       | O(1)       |
| 证明生成 | O(L)       | O(H)       |
| 证明验证 | O(L)       | O(1)       |

其中：

- L: 消息属性总数
- H: 隐藏消息数量

## 🛡️ 安全性考虑

1. **密码学假设**
   - 基于q-Strong Diffie-Hellman (q-SDH)假设
   - 在Type-3配对群上实现

2. **随机数安全**
   - 使用密码学安全的随机数生成器
   - 签名随机数r必须保密

3. **哈希函数**
   - 使用SHA-256进行消息编码
   - 域分离防止跨协议攻击

4. **零知识性**
   - 选择性披露满足零知识性
   - 未披露消息在信息论上是隐藏的

## 📚 参考文献

1. **BBS+原始论文**: Au, M. H., Susilo, W., & Mu, Y. (2006). "Constant-Size Dynamic k-TAA"
2. **BBS签名**: Boneh, D., Boyen, X., & Shacham, H. (2004). "Short Group Signatures"
3. **IETF标准草案**: "The BBS Signature Scheme" (draft-irtf-cfrg-bbs-signatures)
4. **配对曲线**: "BLS12-381 For The Rest Of Us"

## 📝 许可证

本项目采用Apache 2.0许可证

## 🤝 贡献

欢迎提交Issue和Pull Request！

---

-
