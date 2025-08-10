# bn254/params.py
import os

BACKEND = os.getenv("BN254_BACKEND", "pyecc")  # 可切: "mcl" / "pyecc"

if BACKEND == "mcl":
    # TODO: 有了 mcl 实现后，把下面的导入路径改成你的 mcl 模块
    from bn254.backend_mcl import (  # ← 先占位；没有就别切 mcl
        g1_mul, g2_mul, g1, g2, curve_order, rand_scalar, add, pair, msm_g1
    )
    BACKEND_NAME = "mcl"
else:
    # 现阶段走 pyecc，并确保 backend_pyecc 里 Fr 初始化和 _to_fr 已修好
    from bn254.backend_pyecc import (
        g1_mul, g2_mul, g1, g2, curve_order, rand_scalar, add
    )
    BACKEND_NAME = "pyecc"

    # 有些符号 pyecc 里可能没有 -> 提供兜底实现
    try:
        from bn254.backend_pyecc import pair  # 若实现了就用
    except Exception:
        def pair(P, Q):
            raise NotImplementedError("pair is not available in pyecc backend")

    try:
        from bn254.backend_pyecc import msm_g1  # 若实现了就用
    except Exception:
        def msm_g1(bases, scalars):
            """naive MSM 兜底：∑ s_i * B_i"""
            acc = None
            for B, s in zip(bases, scalars):
                pt = g1_mul(B, s)
                acc = add(acc, pt) if acc is not None else pt
            return acc

def _debug_backend():
    print(f"[bn254.params] Using backend: {BACKEND_NAME}")

__all__ = [
    "g1_mul", "g2_mul", "g1", "g2", "curve_order", "rand_scalar",
    "add", "pair", "msm_g1", "_debug_backend"
]
