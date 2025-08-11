# BBS+

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

Run the main program to test:

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

### bls12_v2 (Dual secret-key)

| Number of Attributes (n) | Sign Time (ms) | Verify Time (ms) |
| ------------------------ | -------------- | ---------------- |
| 1                        | 41.251         | 11322.060        |
| 5                        | 127.184        | 11338.829        |
| 10                       | 222.612        | 11513.343        |

### bls12_v1 (Default)

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
