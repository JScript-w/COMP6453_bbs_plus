# bn254/backends/pyecc_backend.py
from __future__ import annotations
from typing import Sequence, Tuple, Any
from bn254.optim.config import OptimConfig
from bn254.backends.base import IBbsBackend
from bn254.utils.instrumentation import maybe_profile_section

# Directly reuse your existing bn254/backend_pyecc.py
import bn254.backend_pyecc as pyecc

class PYECCBackend(IBbsBackend):
    name = "pyecc_bn254_baseline"
    curve = "BN254"
    simd = False  # Used as a non-SIMD baseline

    def __init__(self, optim: OptimConfig):
        self.optim = optim
        # If backend_pyecc has a configuration entry, pass it here; otherwise, ignore.

    def keygen(self) -> Tuple[bytes, bytes]:
        fn = getattr(pyecc, "keygen", None) or getattr(pyecc, "generate_keypair", None)
        if fn is None:
            raise AttributeError("backend_pyecc: keygen()/generate_keypair() not found")
        return fn()

    def sign(self, sk: bytes, msg: bytes, attrs: Sequence[bytes]) -> bytes:
        fn = getattr(pyecc, "sign", None) or getattr(pyecc, "sign_message", None)
        if fn is None:
            raise AttributeError("backend_pyecc: sign()/sign_message() not found")
        with maybe_profile_section(self.optim.profile, "pyecc.sign"):
            return fn(sk, msg, attrs)

    def verify(self, pk: bytes, sig: bytes, msg: bytes, attrs: Sequence[bytes]) -> bool:
        fn = getattr(pyecc, "verify", None) or getattr(pyecc, "verify_signature", None)
        if fn is None:
            raise AttributeError("backend_pyecc: verify()/verify_signature() not found")
        with maybe_profile_section(self.optim.profile, "pyecc.verify"):
            return fn(pk, sig, msg, attrs)

    # pyecc usually does not have zk; if it does, please add the adaptation
    def prove(self, *args, **kwargs) -> Any:
        raise NotImplementedError

    def verify_proof(self, *args, **kwargs) -> bool:
        raise NotImplementedError
