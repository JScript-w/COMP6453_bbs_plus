# bn254/backends/v1_backend.py
from __future__ import annotations
from typing import Sequence, Tuple, Any
from bn254.optim.config import OptimConfig
from bn254.backends.base import IBbsBackend
from bn254.utils.instrumentation import maybe_profile_section

# 这里按你的现有结构导入 v1
from bn254.v1 import keygen as v1_keygen
from bn254.v1 import signer as v1_signer
from bn254.v1 import verifier as v1_verifier


def _normalize_sig(sig):
    # tuple/list: 取前两个
    if isinstance(sig, (tuple, list)):
        if len(sig) >= 2:
            return (sig[0], sig[1])

    # dict: 智能找 key
    if isinstance(sig, dict):
        kl = {k.lower(): k for k in sig.keys()}
        A_key = next((kl[k] for k in ("a", "sigma", "point", "a_point", "sig_a") if k in kl), None)
        e_key = next((kl[k] for k in ("e", "challenge", "c") if k in kl), None)
        if A_key and e_key:
            return (sig[A_key], sig[e_key])

    # 对象: 有属性 A/e
    if hasattr(sig, "A") and hasattr(sig, "e"):
        return (getattr(sig, "A"), getattr(sig, "e"))

    # 再退一步：对象里有 sigma/challenge
    if hasattr(sig, "sigma") and hasattr(sig, "challenge"):
        return (getattr(sig, "sigma"), getattr(sig, "challenge"))

    raise TypeError(f"无法归一化签名对象类型: {type(sig)}")


try:
    from bn254.v1 import zkproof as v1_zk
except Exception:  # 没有 zk 也没关系
    v1_zk = None

# 可选：如果 v1/utils 里没有 set_optim，请在该文件里加一个空函数以避免导入错误
try:
    from bn254.v1 import utils as v1_utils
    HAS_SET_OPTIM = hasattr(v1_utils, "set_optim")
except Exception:
    v1_utils = None
    HAS_SET_OPTIM = False

class V1BN254SIMDBackend(IBbsBackend):
    name = "bn254_v1_simd"
    curve = "BN254"
    simd = True  # 你的 v1 是基于 SIMD 的实现

    def __init__(self, optim: OptimConfig):
        self.optim = optim
        if HAS_SET_OPTIM:
            v1_utils.set_optim(optim)

    def keygen(self):
        # v1.keygen() 返回 (sk, pk)；适配层对外统一返回 (pk, sk)
        res = v1_keygen.keygen()
        if isinstance(res, (tuple, list)) and len(res) == 2:
            sk_bytes, pk_bytes = res
            return pk_bytes, sk_bytes
        # 兼容其它形式（几乎用不到）
        return res

    def sign(self, sk: bytes, msg: bytes, attrs: Sequence[bytes]) -> bytes:
        fn = getattr(v1_signer, "sign", None) or getattr(v1_signer, "sign_message", None)
        if fn is None:
            raise AttributeError("v1.signer: 未找到 sign()/sign_message()")

        from inspect import signature, Parameter
        params = [p for p in signature(fn).parameters.values()
                  if p.kind in (Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD)]

        with maybe_profile_section(self.optim.profile, "v1.sign"):
            if len(params) >= 3:
                raw = fn(sk, msg, attrs)  # (sk, msg, attrs)
            elif len(params) == 2:
                first = params[0].name.lower()
                raw = fn(sk, attrs) if first in {"sk", "x", "secret", "priv", "private_key", "key", "sk_bytes",
                                                 "sk_int"} \
                    else fn(msg, attrs)  # (sk,attrs) 或 (msg,attrs)
            else:
                try:
                    raw = fn(sk, msg, attrs)
                except TypeError:
                    try:
                        raw = fn(sk, attrs)
                    except TypeError:
                        raw = fn(msg, attrs)

        return _normalize_sig(raw)


    def verify(self, pk: bytes, sig: bytes, msg: bytes, attrs: Sequence[bytes]) -> bool:
        fn = getattr(v1_verifier, "verify", None) or getattr(v1_verifier, "verify_signature", None)
        if fn is None:
            raise AttributeError("v1.verifier: 未找到 verify()/verify_signature()")

        from inspect import signature, Parameter
        params = [p for p in signature(fn).parameters.values()
                  if p.kind in (Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD)]
        names = [p.name.lower() for p in params]

        def _call_once(args):
            """仅调用一次；若返回布尔值，无论 True/False 都直接用；只有 TypeError 才换排列。"""
            with maybe_profile_section(self.optim.profile, "v1.verify"):
                return fn(*args)

        # 先按“名字”判断
        try:
            if len(params) >= 4:
                return bool(_call_once((pk, sig, msg, attrs)))
            elif len(params) == 3:
                if "sig" in names or "signature" in names or "sigma" in names:
                    return bool(_call_once((pk, sig, attrs)))  # 期望 (pk, sig, attrs)
                if "msg" in names or "message" in names:
                    return bool(_call_once((pk, msg, attrs)))  # 期望 (pk, msg, attrs)
                # 名字不明，就先试常见 (pk, sig, attrs)
                return bool(_call_once((pk, sig, attrs)))
            elif len(params) == 2:
                if "sig" in names or "signature" in names or "sigma" in names:
                    return bool(_call_once((pk, sig)))
                if "attrs" in names or "messages" in names or "attributes" in names or "ms" in names or "m" in names:
                    return bool(_call_once((pk, attrs)))
                return bool(_call_once((pk, sig)))  # 兜底
            else:
                return bool(_call_once((pk, sig, attrs)))
        except TypeError:
            # 只有在形参不匹配时才尝试备选排列
            for args in ((pk, sig, attrs), (pk, msg, attrs), (sig, attrs), (pk, attrs)):
                try:
                    return bool(_call_once(args))
                except TypeError:
                    continue
            raise

    def prove(self, pk: bytes, sig: bytes, disclosed: Sequence[int], attrs: Sequence[bytes], msg: bytes) -> Any:
        if v1_zk is None:
            raise NotImplementedError("v1.zkproof 未提供")
        fn = getattr(v1_zk, "prove", None)
        if fn is None:
            raise AttributeError("v1.zkproof: 未找到 prove()")
        return fn(pk, sig, disclosed, attrs, msg)

    def verify_proof(self, pk: bytes, proof: Any, disclosed: Sequence[int], msg: bytes) -> bool:
        if v1_zk is None:
            raise NotImplementedError("v1.zkproof 未提供")
        fn = getattr(v1_zk, "verify_proof", None) or getattr(v1_zk, "verify", None)
        if fn is None:
            raise AttributeError("v1.zkproof: 未找到 verify_proof()/verify()")
        return fn(pk, proof, disclosed, msg)
