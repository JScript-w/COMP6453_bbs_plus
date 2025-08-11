# BBS+ Signature Scheme — BLS12-381 v1

This module implements the **BBS+ multi-message signature** scheme on the BLS12-381 pairing-friendly elliptic curve.\
It supports **basic signing/verification**, **attribute updates**, **re-randomization**, and **selective disclosure proofs**.

---

## Features

- **Key generation** — produces a random scalar secret key and a corresponding G2 public key.
- **Signing** — efficient fixed-structure BBS+ signing over multiple messages.
- **Verification** — pairing-based verification for correctness.
- **Attribute update** — efficiently update a subset of signed messages without re-signing all attributes.
- **Re-randomization** — refresh signatures to prevent correlation attacks.
- **Selective disclosure** — generate zero-knowledge proofs revealing only chosen attributes.

---

## API Overview

### Key Generation

```python
from bls12.v1 import KeyPair
kp = KeyPair.generate()
```

- `kp.sk`: secret key (scalar in Fr)
- `kp.pk`: public key (point in G2)

---

### Signing

```python
from bls12.v1 import sign
sig = sign(kp.sk, ["msg1", "msg2", "msg3"])
# sig = (A, e)
```

- `A` — G1 point
- `e` — random scalar

---

### Verification

```python
from bls12.v1 import verify
ok = verify(kp.pk, sig, ["msg1", "msg2", "msg3"])
```

---

### Updating Attributes

```python
from bls12.v1 import update_attributes
sig2 = update_attributes(kp.sk, sig,
                         ["msg1", "msg2", "msg3"],
                         {1: "new_msg2"})
```

---

### Re-randomization

```python
from bls12.v1 import re_randomise
sig3 = re_randomise(sig2)
```

---

### Selective Disclosure Proofs

```python
from bls12.v1 import prove_disclosure, verify_disclosure

proof = prove_disclosure(kp.pk, sig, ["m1", "m2", "m3"], disclose_idx={0, 2})
ok = verify_disclosure(kp.pk, proof, total_attrs=3)
```

---

## Mathematical Notes

- **Public key**:\
  \(pk = g_2^{sk}\)

- **Signature**:\
  \(A = \left(g_1 \\cdot \\prod_{i=0}^{n-1} h_i^{m_i}\\right)^{1 / (sk + e)}\)\
  with random \(e \\in \\mathbb{Z}_p\).

- **Verification equation**:\
  \(e(A, pk \\cdot g_2^e) \\overset{?}{=} e\\left(g_1 \\cdot \\prod h_i^{m_i}, g_2\\right)\)

- **Selective disclosure**:\
  Prove knowledge of hidden attributes \(m_i\) without revealing them, while showing the signature is valid for both revealed and hidden attributes.

---

## Project Structure

```
bls12/v1/
    __init__.py         # API exports
    keygen.py           # KeyPair class
    signer.py           # sign, update, re_randomise
    verifier.py         # verify
    utils.py            # hash & encoding helpers
    zkproof.py          # prove_disclosure, verify_disclosure
```

---

## Requirements

- Python 3.10+
- `py_ecc` for BLS12-381 curve and pairing operations
- Linux/macOS/WSL recommended for performance and compatibility

Install:

```bash
pip install -r requirements.txt
```

