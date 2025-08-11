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
| 1                        | 31.288         | 6188.981         |
| 5                        | 92.619         | 6264.377         |
| 10                       | 166.947        | 6343.696         |
| 20                       | 308.661        | 6458.902         |

### bls12_v2 (Dual secret-key)

| Number of Attributes (n) | Sign Time (ms) | Verify Time (ms) |
| ------------------------ | -------------- | ---------------- |
| 1                        | 43.445         | 6177.910         |
| 5                        | 101.797        | 6232.624         |
| 10                       | 172.807        | 6327.362         |
| 20                       | 325.710        | 6456.706         |

> Note: Verification time remains high due to use of pure Python `py_ecc` pairing library. Consider switching to a C-based library like `blst` or `mcl` for faster pairing operations.

---

## References

- Boneh, D., Boyen, X., & Shacham, H. (2004). Short Group Signatures.
- BBS+ Signatures in AnonCreds: https://identity.foundation/bbs-signature/
- py_ecc pairing library: https://github.com/ethereum/py_ecc
