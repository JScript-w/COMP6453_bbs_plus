# BBS+ Signature

## Introduction

We have implemented two versions of the BBS+ signature scheme using the BLS12-381 elliptic curve. Details of these two versions can be found at:

[BLS12_V1](./src/bls12/v1/README.md)

[BLS12_V2](./src/bls12/v2/README.md)

## Installation

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

Run the main program to test:

```bash
uv run main.py
```

---

## Usage

After running, an interactive CLI menu appears:

```text
1. basic                 # Basic signing and verification
2. selective_disclosure  # Selective disclosure (if implemented)
3. update                # Key update (if implemented)
4. bench                 # Performance benchmark for sign/verify
0. Exit
Input test type number:
```

Choose a test type and input the curve type:

```
1. BLS12_V1
2. BLS12_V2
3. ALL
0. Back
Input test curve number:
```

The system will run the test and output the time consumed for signing and verifying in milliseconds.

---

## Benchmark Results

Two implementations were tested:

### bls12_v1 (Faster)

| Number of Attributes (n) | Sign Time (ms) | Verify Time (ms) |
| ------------------------ | -------------- | ---------------- |
| 1                        | 28.645         | 5959.375         |
| 5                        | 84.792         | 5994.605         |
| 10                       | 153.817        | 6073.008         |
| 20                       | 297.823        | 6419.118         |

### bls12_v2 (Dual secret-key)

| Number of Attributes (n) | Sign Time (ms) | Verify Time (ms) |
| ------------------------ | -------------- | ---------------- |
| 1                        | 44.767         | 6187.042         |
| 5                        | 102.516        | 6250.037         |
| 10                       | 101.651        | 6244.830         |
| 20                       | 101.840        | 6252.118         |

> Note: Verification time remains high due to use of pure Python `py_ecc` pairing library. Consider switching to a C-based library like `blst` or `mcl` for faster pairing operations.

---

## References

- Boneh, D., Boyen, X., & Shacham, H. (2004). Short Group Signatures.
- BBS+ Signatures in AnonCreds: https://identity.foundation/bbs-signature/
- py_ecc pairing library: https://github.com/ethereum/py_ecc
