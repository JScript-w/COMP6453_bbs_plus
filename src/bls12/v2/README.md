# BBS+ Signature Scheme Implementation

## 📋 Solution Overview

This project is a Python implementation of the BBS+ (Boneh-Boyen-Shacham Plus) signature scheme, which supports selective disclosure and zero-knowledge proofs. BBS+ is a pairing-based short signature scheme that is particularly suitable for digital identity and credential systems that require privacy protection.

### Core Features

- ✅ **Short signature**: The signature size is fixed regardless of the number of signed messages
- ✅ **Selective disclosure**: You can selectively disclose some of the signed messages and hide others
- ✅ **Zero-knowledge proof**: Prove possession of a valid signature without revealing the signature itself
- ✅ **Signature randomization**: Supports re-randomization of signatures, providing unlinkability
- ✅ **Dynamic updates**: Supports updating message attributes without regenerating random numbers

## 🏗️ Module export interface

```
v2/
├── __init__.py           # Module export interface
├── keygen_v2.py          # Key generation
├── signer_v2.py          # Signature creation, update, and re-randomization
├── verifier_v2.py        # Signature verification
├── zkproof_v2.py         # ZK proof creation and verification
└── utils_v2.py           # Utilities (hashing, encoding, etc.)
```

### Module Descriptions

| Module           | Purpose                | Main Interfaces                                           |
| ---------------- | ---------------------- | --------------------------------------------------------- |
| `keygen_v2.py`   | Key generation         | `KeyPair.generate(max_attributes)`                        |
| `signer_v2.py`   | Signing                | `sign()`, `update_attributes()`, `re_randomise()`         |
| `verifier_v2.py` | Verification           | `verify()`                                                |
| `zkproof_v2.py`  | ZK proofs              | `prove_disclosure()`, `verify_disclosure()`               |
| `utils_v2.py`    | Some helpful functions | `hash_to_scalar()`, `hash_to_g1()`, `encode_attributes()` |

## 🔢 Mathematical Foundations

### 1. Basic setup

BBS+ is built on **Type-3 bilinear pairing groups** with three cyclic groups：

- **$G_1$, $G_2$**: Elliptic-curve groups of prime order p
- **$G_t$**: Target group
- **Pairing function** $$e: \quad G_1 \times G_2 \rightarrow G_t$$

### 2. Key

Unlike traditional schemes, BBS+ uses a **dual-secret** structure:

Secret key: $(x, y) \in Z_p \times Z_p$

Public key: $(X, Y) = (g_2^x, g_2^y) \in G_2 \times G_2$

Bases: $\{h_0, h_1, ..., h_l\} \in G_1$

Where：

- $h_0$: Base for the blinding factor
- $h_1, ..., h_l$: Per-attribute bases

### 3. Signing

For messages ${m_1, m_2, ..., m_l}$, the signing algorithm：

1. Choose a random $r \leftarrow Z_p$
2. Compute $A = (g_1 \cdot h_0^r \cdot \prod_{i=1}^l h_i^m)^{\frac{1}{x + y \cdot r}}$
3. Output signature $σ = (A, r)$

**Core formula**：

$A = (g_1 \cdot h_0^r \cdot \prod_{i=1}^l h_i^{m_i}ⁱ)^{\frac{1}{x + y \cdot r}}$

### 4. Verification

Verification relies on bilinearity:

$e(A, X \cdot Y^r) \\; ?= e(g_1 \cdot h_0^r \cdot \prod_{i=1}^l h_i^mⁱ, g_2)$

**Explanation:**

- Left：$ e(A, X \cdot Y^r) = e(A, g_2^x · g_2^{yr}) = e(A, g_2^{(x + y \cdot r)}) $
- Right：$e(g_1 \cdot h_0^r \cdot \prod h_i^{m_i}ⁱ, g_2)$
- Since $A = (...)^{\frac{1}{x+y·r}}$, both sides are equal.

### 5. Zero-Knowledge Proofs (Selective Disclosure)

A **Schnorr-like Sigma Protocol** is used for selective disclosure：

#### Proof generation：

1. **Commitment**：
   - Sample：
     - $r̃ \leftarrow Z_p$
     - $m̃_j \leftarrow Z_p$

   - Compute commitment T1：

     $$T_1 = h_0^r̃ \cdot \prod_{j \in H} h_j^{m̃_j}$$

   - Compute commitment T2：

   $$T_2 = Y^r̃$$

2. **Challenge**（Fiat-Shamir）：
   - $c = Hash(A, T_1, T_2, T_3, {m_i}({i \in D}))$

3. **Response**：
   - $ẑᵣ = r̃ + c \cdot r$
   - $ẑ_{m_j} = m̃_j + c·m_j$ (for all hidden messages)

#### Verification checks：

$$e(A^c, X \cdot Y^{ẑ_r} \cdot T_2^{(-1)}) ?= e(B, g_2^c)$$

## 🚀 Usage Examples

### Basic signing and verification

```python
from bbs_plus import KeyPair, sign, verify

# Generate a key pair with support for 5 attributes
keypair = KeyPair.generate(max_attributes=5)

# Prepare messages
messages = ["Name: Jack", "Age: 25", "City: Sydney", "Job: Engineer", "Salary: 50000"]

# Create signature
signature = sign(keypair, messages)

# Extract public key
pk = keypair.get_pk()

# Verify signature
is_valid = verify(pk, signature, messages)
print(f"Signature verified: {is_valid}")
```

### Selective disclosure

```python
from bbs_plus import prove_disclosure, verify_disclosure

# Indices to disclose (only name and city)
disclosed_indices = [0, 2]

# Create zero-knowledge proof
proof = prove_disclosure(pk, signature, messages, disclosed_indices)

# Verifier sees only disclosed messages, others remain hidden
is_valid = verify_disclosure(pk, proof)
print(f"Selective disclosure verified: {is_valid}")
```

### Update messages

```python
from bbs_plus import update_attributes

# Update some attributes, for example age and salary
updates = {
    1: "Age: 26",
    4: "Salary: 60000"
}

# Create a new signature while keeping the same randomness r
new_signature = update_attributes(keypair, signature, messages, updates)
```

### Signature re-randomization

```python
from bbs_plus import re_randomise

# Re-randomize signature to make it unlinkable
randomized_sig = re_randomise(keypair, signature, messages)

# New signature remains valid but is unlinkable to the original
is_valid = verify(pk, randomized_sig, messages)
```

## 🔄 Advantages over v1

| Feature                  | Signature_v1            | Signature_v2          | Advantage                                      |
| ------------------------ | ----------------------- | --------------------- | ---------------------------------------------- |
| **Signature size**       | 3 group elements        | 2 elements (A, r)     | ✅ **Shorter signatures**                      |
| **Key structure**        | Single secret           | Dual secrets (x, y)   | ✅ **Stronger security**                       |
| **Randomization factor** | No randomization factor | Random factor m̃ and r̃ | ✅ **Hide messages and signature component r** |

### Detailed advantage

1. **Compact signature**
   - BBS+ uses only `(A, r)`
   - About 96 bytes on BLS12-381

2. **Stronger security**
   - Dual secret `(x, y)` adds security margin
   - Secure in the standard model under the q-SDH assumption

3. **Flexible message handling**
   - Dynamic updates without changing randomness
   - Efficient incremental updates

4. **Better privacy**
   - Re-randomization yields perfect unlinkability
   - Selective disclosure reveals nothing about hidden messages

## 📊 Performance Characteristics

| Operation       | Time Complexity | Space Complexity |
| --------------- | --------------- | ---------------- |
| Key generation  | O(L)            | O(L)             |
| Signing         | O(L)            | O(1)             |
| Verification    | O(L)            | O(1)             |
| Proof creation  | O(L)            | O(H)             |
| Proof verifying | O(L)            | O(1)             |

Where：

- L: total number of attributes/messages
- H: number of hidden attributes/messages

## 🛡️ Security consideration

1. **Cryptographic assumption**
   - Based on the q-Strong Diffie–Hellman assumption
   - Implemented over Type-3 pairings

2. Randomness
   - Use a cryptographically secure RNG
   - Keep the signing randomness r secret

3. Hashing
   - Use SHA-256 for message encoding
   - Domain separation to prevent cross-protocol issues

4. Zero-knowledge
   - Selective disclosure is zero-knowledge
   - Undisclosed messages are information-theoretically hidden

## 📚 References

1. [decentralized-identity/bbs-signature: The BBS Signature Scheme](https://github.com/decentralized-identity/bbs-signature)
2. [mattrglobal/bbs-signatures: An implementation of BBS+ signatures for node and browser environments](https://github.com/mattrglobal/bbs-signatures)
