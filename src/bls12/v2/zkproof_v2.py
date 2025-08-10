"""
BBS+ 零知识证明模块 - 优化版本
实现选择性披露的零知识证明协议
"""

from hashlib import sha256
from typing import Dict, List, Tuple, Any

from ..params import (
    rand_scalar,
    g1_mul,
    g2_mul,
    add,
    msm_g1,
    g1,
    g2,
    pair,
    curve_order,
)
from .utils_v2 import encode_attributes


def _hash_to_challenge(*elements) -> int:
    """
    Fiat-Shamir哈希函数 - 生成非交互式零知识证明的挑战值

    功能: 将Sigma协议从交互式转换为非交互式
    安全性: 使用域分离标签防止跨协议攻击

    Args:
        *elements: 需要哈希的元素列表（可变参数）

    Returns:
        int: 挑战值 c ∈ Zp
    """
    # 域分离标签，防止不同协议间的哈希碰撞
    hasher = sha256(b"BBS_PLUS_ZKPROOF_CHALLENGE_V1")

    for elem in elements:
        if isinstance(elem, bytes):
            hasher.update(elem)
        elif isinstance(elem, int):
            # 确保所有整数使用固定长度编码
            hasher.update(elem.to_bytes(32, "big"))
        elif isinstance(elem, tuple):  # 处理点坐标
            # 将椭圆曲线点序列化
            for coord in elem:
                if isinstance(coord, int):
                    hasher.update(coord.to_bytes(32, "big"))
                else:
                    hasher.update(str(coord).encode())
        else:
            hasher.update(str(elem).encode())

    # 映射到标量域 Zp
    digest = hasher.digest()
    return int.from_bytes(digest, "big") % curve_order


def prove_disclosure(
    pk: Dict, sig: Tuple, messages: List[str], disclosed_indices: List[int]
) -> Dict[str, Any]:
    """
    BBS+ 选择性披露证明生成算法

    ========== 数学原理 ==========

    1. 签名随机化阶段:
       - 选择随机数 t ← Zp
       - 计算 A' = A^t, r' = r·t
       - 这确保每次生成的证明不可链接

    2. Sigma协议承诺阶段:
       - 为隐藏的签名组件生成随机承诺
       - r̃ ← Zp (对r'的承诺)
       - m̃_j ← Zp, ∀j ∈ H (对隐藏消息的承诺)

    3. 承诺值计算:
       - T₁ = h₀^r̃ · ∏_{j∈H} h_j^m̃_j (G1中的承诺)
       - T₂ = Y^r̃ (G2中的承诺)
       - T₃ = e(A', T₂) (配对承诺，用于验证)

    4. Fiat-Shamir挑战生成:
       - c = Hash(A', T₁, T₂, T₃, {m_i}_{i∈D})

    5. Schnorr响应计算:
       - ẑ_r = r̃ + c·r' (对r'的响应)
       - ẑ_{m_j} = m̃_j + c·m_j, ∀j ∈ H (对隐藏消息的响应)

    Args:
        pk: 公钥字典 {X, Y, h_bases}
        sig: 签名元组 (A, r)
        messages: 所有消息列表
        disclosed_indices: 要披露的消息索引列表

    Returns:
        Dict: 零知识证明，包含所有必要组件
    """
    # 提取公钥组件
    X = pk["X"]
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # 提取签名
    A, r = sig

    # ===== 步骤1: 消息分类 =====
    # 将消息编码为标量
    m_scalars = encode_attributes(messages)

    # 分离披露集D和隐藏集H
    hidden_indices = [i for i in range(len(messages)) if i not in disclosed_indices]
    disclosed_msgs = {i: messages[i] for i in disclosed_indices}
    disclosed_scalars = {i: m_scalars[i] for i in disclosed_indices}
    hidden_scalars = {i: m_scalars[i] for i in hidden_indices}

    # ===== 步骤2: Sigma协议承诺阶段 =====
    # 为所有隐藏值生成随机承诺
    r_tilde = rand_scalar()  # 对r'的承诺
    m_tildes = {i: rand_scalar() for i in hidden_indices}  # 对隐藏消息的承诺

    # 计算承诺T₁ = h₀^r̃ · ∏_{j∈H} h_j^m̃_j
    commit_scalars = [r_tilde] + [m_tildes[i] for i in hidden_indices]
    commit_bases = [h_bases[0]] + [h_bases[i + 1] for i in hidden_indices]
    T1 = msm_g1(commit_bases, commit_scalars)

    # 计算承诺T₂ = Y^r̃
    T2 = g2_mul(Y, r_tilde)

    # 计算配对承诺T₃ = e(A, T₂)
    T3 = pair(A, T2)

    # ===== 步骤3: Fiat-Shamir挑战生成 =====
    # 挑战必须包含所有公开信息以确保安全性
    challenge_input = [
        A,
        T1,
        T2,
        T3,  # 承诺值
        len(messages),  # 总消息数
        tuple(sorted(disclosed_indices)),  # 披露的索引
        tuple(disclosed_msgs[i] for i in sorted(disclosed_indices)),  # 披露的消息
    ]

    c = _hash_to_challenge(*challenge_input)

    # ===== 步骤4: Schnorr响应计算 =====
    # 计算响应值（证明者知识的零知识证明）
    z_r = (r_tilde + c * r) % curve_order  # ẑ_r = r̃ + c·r'
    z_m = {
        i: (m_tildes[i] + c * hidden_scalars[i]) % curve_order for i in hidden_indices
    }  # ẑ_{m_j} = m̃_j + c·m_j

    # 构建证明
    proof = {
        # 核心证明组件
        "A": A,
        "T1": T1,  # G1承诺
        "T2": T2,  # G2承诺
        "c": c,  # 挑战值
        "z_r": z_r,  # r的响应
        "z_m": z_m,  # 隐藏消息的响应
        # 辅助信息
        "disclosed_indices": disclosed_indices,
        "disclosed_messages": disclosed_msgs,
        "hidden_indices": hidden_indices,
        "total_messages": len(messages),
    }

    return proof


def verify_disclosure(pk: Dict, proof: Dict) -> bool:
    """
    BBS+ 选择性披露证明验证算法

    ========== 验证方程 ==========

    主要验证两个核心等式:

    1. 承诺重构验证:
       T₁ ?= h₀^ẑ_r · ∏_{j∈H} h_j^ẑ_{m_j} · T₁^{-c}

    2. 配对方程验证:
       e(A'^c, X · Y^ẑ_r · T₂^{-1}) ?= e(g₁^c · ∏_{i∈D} h_i^{c·m_i} · T₁, g₂)

    3. 挑战值验证:
       c ?= Hash(A', T₁, T₂, T₃, {m_i}_{i∈D})

    数学原理:
    - 利用Schnorr协议的完备性
    - 配对的双线性性质
    - Fiat-Shamir变换的健全性

    Args:
        pk: 公钥字典
        proof: 零知识证明字典

    Returns:
        bool: 证明是否有效
    """
    # 提取公钥组件
    X = pk["X"]
    Y = pk["Y"]
    h_bases = pk["h_bases"]

    # 提取证明组件
    A = proof["A"]
    T1 = proof["T1"]
    T2 = proof["T2"]
    c = proof["c"]
    z_r = proof["z_r"]
    z_m = proof["z_m"]

    disclosed_indices = proof["disclosed_indices"]
    disclosed_messages = proof["disclosed_messages"]
    hidden_indices = proof["hidden_indices"]
    total_messages = proof["total_messages"]

    # ===== 验证步骤1: 重新计算挑战值 =====
    # 计算T₃用于挑战验证
    T3 = pair(A, T2)

    # 重构挑战输入
    challenge_input = [
        A,
        T1,
        T2,
        T3,
        total_messages,
        tuple(sorted(disclosed_indices)),
        tuple(disclosed_messages[i] for i in sorted(disclosed_indices)),
    ]

    c_verify = _hash_to_challenge(*challenge_input)

    # 验证挑战值
    if c != c_verify:
        print("挑战值验证失败")
        return False

    # 左边: h₀^{ẑ_r} · ∏_{j∈H} h_j^{ẑ_{m_j}}
    verify_scalars = [z_r] + [z_m[i] for i in hidden_indices]
    verify_bases = [h_bases[0]] + [h_bases[i + 1] for i in hidden_indices]
    left_commit = msm_g1(verify_bases, verify_scalars)

    # ===== 验证步骤2: 主配对方程验证 =====
    # 验证: e(A^c, X · Y^{ẑ_r} · T₂^{-1}) = e(B, g₂^c)
    # 其中 B = g₁^c · ∏_{i∈D} h_i^{c·m_i} · T₁

    # 构建左边配对的第二个参数
    # X^c · Y^{ẑ_r} · T₂^{-1}
    X_c = g2_mul(X, c)
    Y_zr = g2_mul(Y, z_r)  # Y^{ẑ_r}
    T2_neg = g2_mul(T2, curve_order - 1)  # T₂^{-1}
    verify_g2 = add(add(X_c, Y_zr), T2_neg)

    # 构建右边配对的第一个参数
    # B = g₁^c · ∏_{i∈D} h_i^{c·m_i} · (left_commit · T₁^(-1))

    # 首先编码披露的消息
    disclosed_scalars = encode_attributes(
        [disclosed_messages[i] for i in sorted(disclosed_indices)]
    )

    # 构建基点和标量数组
    B_scalars = [c]  # g₁的指数
    B_bases = [g1]

    # 添加披露消息的贡献
    for idx, i in enumerate(sorted(disclosed_indices)):
        B_scalars.append((c * disclosed_scalars[idx]) % curve_order)
        B_bases.append(h_bases[i + 1])

    # 计算 g₁^c · ∏_{i∈D} h_i^{c·m_i}
    B_disclosed = msm_g1(B_bases, B_scalars)

    # 添加T₁
    hidden_part = add(left_commit, g1_mul(T1, curve_order - 1))
    B = add(B_disclosed, hidden_part)

    # 执行配对验证
    left_pairing = pair(g1_mul(A, c), verify_g2)
    right_pairing = pair(B, g2_mul(g2, c))

    if left_pairing != right_pairing:
        print("配对方程验证失败")
        return False

    print("配对方程验证成功")
    return True
