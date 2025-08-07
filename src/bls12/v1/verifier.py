from typing import Sequence
from ..params import g1_mul, g2_mul, pair, g1, g2, add
from .utils import encode_attributes


def verify(pk, sig, messages):
    A, e = sig
    h_bases = [g1_mul(g1, i + 2) for i in range(len(messages))]
    m_scalars = encode_attributes(messages)

    msg_part = g1
    for h, m in zip(h_bases, m_scalars):
        msg_part = add(msg_part, g1_mul(h, m))

    left = pair(A, add(pk, g2_mul(g2, e)))
    right = pair(msg_part, g2)
    return left == right
# Verify BBS+ signature
# pk: public key (point in G2)
# sig: signature tuple (A point in G1, scalar e)
# messages: list of message strings

# Compute deterministic bases for messages
# Encode messages to scalar values

# Calculate message commitment part: g1 + sum(h_i * m_i)

# Pairing check: e(A, pk + e*g2) == e(msg_part, g2)
# Returns True if signature is valid, False otherwise

