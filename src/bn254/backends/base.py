# bn254/backends/base.py
from __future__ import annotations
from typing import Protocol, Sequence, Tuple, Any
from dataclasses import dataclass
from bn254.optim.config import OptimConfig

BytesLike = bytes  # Simplified; can be extended later to include memoryview/bytearray

class IBbsBackend(Protocol):
    """
    Unified backend interface. 
    All backends (v1 / pyecc / others) must implement this set of methods.
    """
    name: str
    curve: str
    simd: bool

    def __init__(self, optim: OptimConfig): ...

    # Basic API
    def keygen(self) -> Tuple[BytesLike, BytesLike]: ...
    def sign(self, sk: BytesLike, msg: BytesLike, attrs: Sequence[BytesLike]) -> BytesLike: ...
    def verify(self, pk: BytesLike, sig: BytesLike, msg: BytesLike, attrs: Sequence[BytesLike]) -> bool: ...

    # (Optional) Selective Disclosure / Proof API — Only if implemented in v1/zkproof.py
    def prove(self, pk: BytesLike, sig: BytesLike, disclosed: Sequence[int], attrs: Sequence[BytesLike], msg: BytesLike) -> Any: ...
    def verify_proof(self, pk: BytesLike, proof: Any, disclosed: Sequence[int], msg: BytesLike) -> bool: ...
