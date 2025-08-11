# BBS+ Signature using BLS Elliptic Curve v1.0

This project implements the BBS+ multi-message signature scheme based on the BLS12-381 pairing-friendly elliptic curve. It is suitable for privacy-preserving applications such as anonymous credentials and selective disclosure. The implementation is written in Python and uses the `py_ecc` library for bilinear pairing computations.

---

## Core Mathematical Formulas

### Key Generation

1. Private Key:

   $$
   sk \in \mathbb{Z}_p \quad \text{(a random scalar)}
   $$

2. Public Key:

   $$
   pk = g_2^{sk}
   $$

---

### Signature

Signature structure:

$$
\sigma = (A, e)
$$

- Signature computation:

  $$
  A = (g_1 \cdot \prod_{i=1}^n h_i^{m_i})^{\frac{1}{sk + e}} \mod p
  $$

- $e \in \mathbb{Z}_p$ is a random challenge.

---

### Verification

Signature is valid if the following pairing equation holds:

$$
e(A, pk \cdot g_2^e) \stackrel{?}{=} e(g_1 \cdot \prod_{i=1}^n h_i^{m_i}, g_2)
$$

---

## Project Structure

```
v1/
├── __init__.py  # Module export interface
├── keygen.py    # Key generation
├── signer.py    # Signature creation, update, and re-randomization
├── utils.py     # Utilities (hashing, encoding, etc.)
├── verifier.py  # Signature verification
└── zkproof.py   # ZK proof creation and verification
```

---
