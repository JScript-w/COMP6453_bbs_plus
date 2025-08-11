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
  A = \left(g_1 \cdot \prod_{i=1}^n h_i^{m_i}\right)^{\frac{1}{sk + e}} \mod p
  $$

- $e \in \mathbb{Z}_p$ is a random challenge.

---

### Verification

Signature is valid if the following pairing equation holds:

$$
e(A, pk \cdot g_2^e) \stackrel{?}{=} e\left(g_1 \cdot \prod_{i=1}^n h_i^{m_i}, g_2\right)
$$

---

## Project Structure

```
COMP6453_bbs_plus-main/
├── main.py                  # Main CLI entry point
├── requirements.txt         # Project dependencies
├── src/
│   └── bls12/
│       ├── v1/              # Optimized version (fixed structure, fast sign)
│       └── v2/              # Standard version (sign time grows with n)
├── tests/                   # Unit tests and performance benchmarks
```

---

## Installation and Usage

### Requirements

- Python 3.10+
- `uv` package manager (recommended)
- Linux/macOS/WSL environment (due to limitations of py_ecc on Windows)

### Install dependencies

```bash
uv sync
```

Activate the virtual environment (first time):

```bash
source .venv/bin/activate
```

Run the main program:

```bash
python main.py
```

---

## Usage

After running, an interactive CLI menu appears:

```text
1. basic                # Basic signing and verification
2. selective_disclosure# Selective disclosure (if implemented)
3. update              # Key update (if implemented)
4. bench               # Performance benchmark for sign/verify
```

Choose a test type and input the number of attributes n to be signed:

```
Input test type number: 5
n | sign (ms) | verify (ms)
--+-----------+-------------
```

The system will output the time consumed for signing and verifying in milliseconds.

---

## Benchmark Results

Two implementations were tested:

- **bls12_v2**: A standard implementation that processes each message independently.
- **bls12_v1**: An optimized version where sign time is nearly constant (possibly fixed-message template or precomputation).

### bls12_v2 (default)

| Number of Attributes (n) | Sign Time (ms) | Verify Time (ms) |
| ------------------------ | -------------- | ---------------- |
| 1                        | 41.251         | 11322.060        |
| 5                        | 127.184        | 11338.829        |
| 10                       | 222.612        | 11513.343        |

### bls12_v1 (optimized)

| Number of Attributes (n) | Sign Time (ms) | Verify Time (ms) |
| ------------------------ | -------------- | ---------------- |
| 1                        | 21.897         | 11703.461        |
| 5                        | 22.033         | 11595.577        |
| 10                       | 21.650         | 11824.938        |
| 20                       | 21.920         | 12053.933        |

> Note: Verification time remains high due to use of pure Python `py_ecc` pairing library. Consider switching to a C-based library like `blst` or `mcl` for faster pairing operations.

---

## References

- Boneh, D., Boyen, X., & Shacham, H. (2004). Short Group Signatures.
- BBS+ Signatures in AnonCreds: https://identity.foundation/bbs-signature/
- py_ecc pairing library: https://github.com/ethereum/py_ecc
