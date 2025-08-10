# bn254/backends/base.py
from __future__ import annotations
from typing import Protocol, Sequence, Tuple, Any
from dataclasses import dataclass
from bn254.optim.config import OptimConfig

BytesLike = bytes  # 简化；后续可扩展 memoryview/bytearray

class IBbsBackend(Protocol):
    """
    统一后端接口。所有后端（v1 / pyecc / 其他）都实现这套方法。
    """
    name: str
    curve: str
    simd: bool

    def __init__(self, optim: OptimConfig): ...

    # 基础 API
    def keygen(self) -> Tuple[BytesLike, BytesLike]: ...
    def sign(self, sk: BytesLike, msg: BytesLike, attrs: Sequence[BytesLike]) -> BytesLike: ...
    def verify(self, pk: BytesLike, sig: BytesLike, msg: BytesLike, attrs: Sequence[BytesLike]) -> bool: ...

    # （可选）选择性披露 / 证明 API —— 仅当你在 v1/zkproof.py 已实现
    def prove(self, pk: BytesLike, sig: BytesLike, disclosed: Sequence[int], attrs: Sequence[BytesLike], msg: BytesLike) -> Any: ...
    def verify_proof(self, pk: BytesLike, proof: Any, disclosed: Sequence[int], msg: BytesLike) -> bool: ...
