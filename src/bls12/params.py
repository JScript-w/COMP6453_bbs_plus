"""
Re-Exports for the core library so the rest of the code remains backend-agnostic.
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
    curve_order,  # Order of the group
)

# Canonical generators (tuples from py-ecc)
g1 = G1  # Generator of group G1
g2 = G2  # Generator of group G2
