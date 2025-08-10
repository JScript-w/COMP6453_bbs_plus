# bn254/backends/__init__.py
from __future__ import annotations
from typing import Literal
from bn254.optim.config import OptimConfig
from .base import IBbsBackend
from .v1_backend import V1BN254SIMDBackend
from .pyecc_backend import PYECCBackend

BackendName = Literal["v1", "pyecc"]

def get_backend(name: BackendName = "v1", optim: OptimConfig | None = None) -> IBbsBackend:
    optim = optim or OptimConfig()
    if name == "v1":
        return V1BN254SIMDBackend(optim)
    elif name == "pyecc":
        return PYECCBackend(optim)
    else:
        raise ValueError(f"未知后端：{name}")
