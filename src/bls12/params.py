"""
Re‑Exports for core library so the rest of the code stays backend‑agnostic.
"""

from .backend_pyecc import (
    rand_scalar,
    g1_mul,
    g2_mul,
    msm_g1,
    pair,
    ecc_add as add,
    G1,
    G2,
    curve_order,  # 群的阶数
)


# Canonical generators (tuples from py‑ecc)
g1 = G1  # G1群生成元
g2 = G2  # G2群生成元
