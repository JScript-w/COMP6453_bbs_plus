"""
backend_pyecc.py — BN-254 implementation via **mclbn256**
========================================================

* Drop-in replacement for the old py-ecc backend; **file name stays the same**.
* Uses Herumi MCL’s Python binding (`pip install mclbn256`). SIMD (AVX2/512) is
  enabled automatically on x86-64 Linux/macOS wheels.
* All public symbols (`curve_order`, `G1`, `G2`, `rand_scalar`, `g1_mul`,
  `g2_mul`, `msm_g1`, `pair`, …) keep the same names so that upper-layer BBS+
  code runs unchanged.
"""
from __future__ import annotations

import secrets
from typing import List, Union
import mclbn256 as mcl
from mclbn256 import G1 as _G1, G2 as _G2, Fr
from ctypes import create_string_buffer
from mclbn256 import lib as _lib

# 你的 mcl 绑定不需要显式 init；保持兼容，如果没有 init 就什么都不做
_MCL_READY = True


_FR_METHOD = None  # 'bytes_le32' | 'hex16' | 'dec10' | '0xhex144' | 'disabled'

def _try_fr_new_fromstr(payload: bytes, mode: int) -> bool:
    try:
        v = Fr.new_fromstr(payload, mode)
        # 读一遍整数，确保对象可用
        _ = int(v)
        return True
    except Exception:
        return False

def _detect_fr_method():
    """
    只在首次调用时运行：
    选出一条能同时处理 small=123 与 big=(r-1) 的 fromstr 路径。
    否则标记为 'disabled'，后续直接走整数乘法。
    """
    global _FR_METHOD
    if _FR_METHOD is not None:
        return

    small = 123 % curve_order
    big   = (curve_order - 1)  # 最苛刻的样本

    candidates = [
        ("bytes_le32",
         (small.to_bytes(32, "little"), 32),
         (big.to_bytes(32,  "little"), 32)),
        ("hex16",
         (f"{small:064x}".encode(), 16),
         (f"{big:064x}".encode(),   16)),
        ("dec10",
         (str(small).encode(), 10),
         (str(big).encode(),   10)),
        ("0xhex144",
         ((b"0x" + f"{small:064x}".encode()), 144),
         ((b"0x" + f"{big:064x}".encode()),   144)),
    ]

    for name, (p_s, m_s), (p_b, m_b) in candidates:
        ok_small = _try_fr_new_fromstr(p_s, m_s)
        ok_big   = _try_fr_new_fromstr(p_b, m_b)
        if ok_small and ok_big:
            _FR_METHOD = name
            return

    # 没有任何一条能同时覆盖 -> 禁用 Fr 路径，统一走整数乘法
    _FR_METHOD = "disabled"


def _ensure_mcl():
    # 某些环境有 mcl.init，这里做个“有则用之，无则跳过”的兼容
    if hasattr(mcl, "init"):
        try:
            mcl.init(mcl.BN254)
        except Exception:
            pass


# BN-254 scalar-field order r (same as ALT_BN128 / Ethereum bn128 curve)
curve_order: int = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

# Canonical generators provided by the library
G1: _G1 = _G1.base_point()
G2: _G2 = _G2.base_point()

g1 = G1            # lowercase aliases kept for historic code
g2 = G2

# Additive identities (handy for equality checks)
ZERO_G1: _G1 = _G1()  # same as G1.zero() but explicit
ZERO_G2: _G2 = _G2()

# ────────────────────────────────────────────────────────────────
# 2. Scalar helpers
# ────────────────────────────────────────────────────────────────

# --- 替换 _to_fr 为稳健版，并在入口确保初始化 ---
def _to_fr(k: int) -> Fr:
    _detect_fr_method()
    if _FR_METHOD == "disabled":
        # 提醒上层 multiply 走整数兜底；不要在这里 print 以免刷屏
        raise ValueError("Fr path disabled on this system")

    k = int(k) % curve_order
    if _FR_METHOD == "bytes_le32":
        return Fr.new_fromstr(k.to_bytes(32, "little"), 32)
    elif _FR_METHOD == "hex16":
        return Fr.new_fromstr(f"{k:064x}".encode(), 16)
    elif _FR_METHOD == "dec10":
        return Fr.new_fromstr(str(k).encode(), 10)
    elif _FR_METHOD == "0xhex144":
        return Fr.new_fromstr(b"0x" + f"{k:064x}".encode(), 144)
    else:
        # 理论上不会走到
        raise ValueError("Unsupported _FR_METHOD")




def rand_scalar() -> int:
    """Cryptographically-secure random non-zero scalar ∈ [1, r-1]."""
    return secrets.randbelow(curve_order - 1) + 1

# ────────────────────────────────────────────────────────────────
# 3. Group operations (API compatible with py-ecc)
# ────────────────────────────────────────────────────────────────

def add(P, Q):  # noqa: N802 — keep original name
    """Elliptic-curve point addition with None-tolerant semantics."""
    if P is None:
        return Q
    if Q is None:
        return P
    return P + Q


def _clone_point(P):
    # 用 serialize/deserialize 断开别名；支持 G1/G2
    try:
        C = P.__class__
        if hasattr(C, "deserialize") and (hasattr(P, "serialize") or hasattr(P, "__bytes__")):
            raw = P.serialize() if hasattr(P, "serialize") else bytes(P)
            return C.deserialize(raw)
    except Exception:
        pass
    # 兜底：返回原对象（一般不会走到）
    return P

def _zero_like(P):
    # 用 P - P 得到库认可的“真零点”
    try:
        return P - P
    except Exception:
        # 极端兜底：clone 后相减
        Q = _clone_point(P)
        return Q - Q

def _safe_add(P, Q):
    # 对输入先 clone，避免库在 __add__ 里就地修改入参
    P2, Q2 = _clone_point(P), _clone_point(Q)
    R = P2 + Q2
    # 再 clone 一次输出，避免后续使用同一实例
    return _clone_point(R)

def _safe_double(P):
    # 避免“自加”别名：用 clone 后相加
    return _safe_add(P, P)

# --- 标量乘：Montgomery ladder（MSB-first），无别名，无自加 ---
def _mul_int_generic(P, k: int):
    """
    预计算二进制幂表 + 累加（不对“中间结果”做加倍）：
    - 先构造 table[i] = (2^i)·P
    - 然后把 k 的二进制位为 1 的 table[i] 累加即可
    """
    k = int(k) % curve_order
    if k == 0:
        # 返回“零点”：用 clone 不破坏 P；尽量避免对 P 做原地操作
        try:
            return P - P
        except Exception:
            # 极端兜底：如果不支持一元负号，退化成“加 curve_order 次”拿零点（几乎不会走到）
            R = P
            for _ in range(curve_order - 1):
                R = R + P
            return R

    # 1) 预计算幂表
    bits = k.bit_length()
    table = [None] * bits
    table[0] = P
    for i in range(1, bits):
        table[i] = table[i - 1] + table[i - 1]   # 2^(i)·P = 2^(i-1)·P + 2^(i-1)·P

    # 2) 累加选中的幂
    R = None
    idx = 0
    kk = k
    while kk:
        if kk & 1:
            R = table[idx] if R is None else (R + table[idx])
        kk >>= 1
        idx += 1

    return R

def multiply(P, k: int):
    return _mul_int_generic(P, k)

def g1_mul(P, k: int):
    return _mul_int_generic(P, k)

def g2_mul(Q, k: int):
    return _mul_int_generic(Q, k)

def msm_g1(bases: List[_G1], scalars: List[int]) -> _G1:
    """Naïve O(n) multi-scalar-mul (can swap for Pippenger later)."""
    acc: _G1 | None = None
    for B, s in zip(bases, scalars):
        acc = add(acc, g1_mul(B, s))
    return acc or ZERO_G1

# ────────────────────────────────────────────────────────────────
# 4. Pairing
# ────────────────────────────────────────────────

def pair(P: _G1, Q: _G2):
    """Bilinear pairing e(P, Q) ∈ GT; '@' already does final-exp."""
    return P @ Q

# Legacy alias expected by some modules
ecc_add = add

# ────────────────────────────────────────────────────────────────
# 5. Hash-to-G1
# ────────────────────────────────────────────────────────────────

def hash_to_g1(data) -> _G1:
    if isinstance(data, str):
        data = data.encode()
    P = _G1()
    if hasattr(P, "hash"):
        P.hash(data)                # 常见接口
        return P
    if hasattr(_G1, "fromhash"):
        return _G1.fromhash(data)   # 有些封装是 classmethod
    raise RuntimeError("Your mclbn256 binding lacks G1.hash()/G1.fromhash()")

# ────────────────────────────────────────────────────────────────
# 6. Public re-exports
# ────────────────────────────────────────────────────────────────

__all__ = [
    "curve_order",
    "G1",
    "G2",
    "g1",
    "g2",
    "ZERO_G1",
    "ZERO_G2",
    "rand_scalar",
    "g1_mul",
    "g2_mul",
    "msm_g1",
    "add",
    "pair",
    "ecc_add",
    "hash_to_g1",
]



