# bn254/backends/pyecc_backend.py
from __future__ import annotations
from typing import Sequence, Tuple, Any
from bn254.optim.config import OptimConfig
from bn254.backends.base import IBbsBackend
from bn254.utils.instrumentation import maybe_profile_section

# 直接复用你现有的 bn254/backend_pyecc.py
import bn254.backend_pyecc as pyecc

class PYECCBackend(IBbsBackend):
    name = "pyecc_bn254_baseline"
    curve = "BN254"
    simd = False  # 作为非 SIMD 基线

    def __init__(self, optim: OptimConfig):
        self.optim = optim
        # 如果 backend_pyecc 有配置入口，可在这里传入；否则忽略

    def keygen(self) -> Tuple[bytes, bytes]:
        fn = getattr(pyecc, "keygen", None) or getattr(pyecc, "generate_keypair", None)
        if fn is None:
            raise AttributeError("backend_pyecc: 未找到 keygen()/generate_keypair()")
        return fn()

    def sign(self, sk: bytes, msg: bytes, attrs: Sequence[bytes]) -> bytes:
        fn = getattr(pyecc, "sign", None) or getattr(pyecc, "sign_message", None)
        if fn is None:
            raise AttributeError("backend_pyecc: 未找到 sign()/sign_message()")
        with maybe_profile_section(self.optim.profile, "pyecc.sign"):
            return fn(sk, msg, attrs)

    def verify(self, pk: bytes, sig: bytes, msg: bytes, attrs: Sequence[bytes]) -> bool:
        fn = getattr(pyecc, "verify", None) or getattr(pyecc, "verify_signature", None)
        if fn is None:
            raise AttributeError("backend_pyecc: 未找到 verify()/verify_signature()")
        with maybe_profile_section(self.optim.profile, "pyecc.verify"):
            return fn(pk, sig, msg, attrs)

    # pyecc 通常没有 zk；如果有，请补适配
    def prove(self, *args, **kwargs) -> Any:
        raise NotImplementedError

    def verify_proof(self, *args, **kwargs) -> bool:
        raise NotImplementedError
