# BBS+ Signature on BLS Elliptic Curve v1.0

## Core Mathematical Formulas

### Keys

1. Private Key:
   $sk \in \mathbb{Z}_p$ (a single random scalar)
2. Public Key:
   $pk = g_2^{sk}$

### Signature

Signature Structure:
$(A, e)$

- $A = (g_1 \cdot \prod{h_i}^{m_i})^{(\frac{1}{(sk+e)} \mod p)}$
- $e \in \mathbb{Z}_p$
