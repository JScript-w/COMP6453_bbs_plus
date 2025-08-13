import hashlib
from ..params import rand_scalar, g1_mul, g1, curve_order, msm_g1, add

from ..backend_pyecc import G1
from mclbn256 import G1 as _MclG1

def hash_to_scalar(data: bytes) -> int:
    """
    Hash mapping from a byte string to a scalar.

    Function:
        Computes the hash of an arbitrary-length byte string and maps it 
        into the scalar field Zp.
    Security:
        Uses SHA-256 to ensure one-wayness and collision resistance.

    Returns:
        int: A value less than the elliptic curve order (curve_order) and not equal to 0.
    """
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % curve_order or 1


def hash_to_g1(label: bytes):
    """
    Map a label to G1.
    Important: `hashAndMapTo` / `mapToG1` modify the object in place and return None!
    Always "create the object first, then call the method, then return the object",
    otherwise you will end up passing None.
    """
    P = G1()
    if hasattr(P, "hashAndMapTo"):
        P.hashAndMapTo(label)
        return P
    if hasattr(P, "mapToG1"):
        P.mapToG1(label)
        return P

    # Fallback: if no mapping API is available, revert to the old approach 
    # (discrete log known; slightly weaker security but still functional).
    h = int.from_bytes(label, "big") % curve_order
    return g1_mul(g1, h)


def _as_bytes(x):
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("utf-8")
    if isinstance(x, int):
        # Use shortest big-endian representation; 0 still takes 1 byte
        n = (x.bit_length() + 7) // 8 or 1
        return x.to_bytes(n, "big", signed=False)
    # Fallback: for structured objects, try JSON; if that fails, use repr
    try:
        import json
        return json.dumps(x, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception:
        return repr(x).encode("utf-8")


def ensure_scalar(x):
    """Convert any type into a scalar int (mod r)."""
    from ..params import curve_order
    if isinstance(x, int):
        return x % curve_order
    # bytes/str/other → first convert to bytes, then hash to scalar
    return hash_to_scalar(_as_bytes(x)) % curve_order


def encode_attributes(attrs):
    # Uniformly convert attributes into scalar ints
    return [ensure_scalar(a) for a in attrs]


def get_h_bases(n: int):
    bases = [hash_to_g1(b"H" + i.to_bytes(4, "big")) for i in range(n)]
    # Guard: prevent None from entering MSM
    if any(b is None for b in bases):
        raise RuntimeError(
            "hash_to_g1 returned None — check if you mistakenly wrote `return P.hashAndMapTo(...)`"
        )
    return bases


try:
    from bn254.optim.config import OptimConfig
except Exception:
    OptimConfig = None  # Fallback to avoid breaking imports

_GLOBAL_OPTIM = None


def set_optim(optim):
    """
    Allow external (backend adapter) to set optimization parameters.
    If v1 internally needs them, you can store these values into your 
    existing global variables/context here. For example:
        some_global.window = optim.window
        some_global.enable_precompute = optim.precompute
        some_global.threads = optim.threads

    For now, we simply store a copy so that `_GLOBAL_OPTIM` can be directly
    read later in v1 if needed.
    """
    global _GLOBAL_OPTIM
    _GLOBAL_OPTIM = optim


def get_optim():
    return _GLOBAL_OPTIM


def build_U_and_ms(attrs):
    """Single source: first compute m_scalars, then U = g1 + Σ H_i^{m_i}."""
    h_bases   = get_h_bases(len(attrs))
    m_scalars = encode_attributes(attrs)
    U = add(g1, msm_g1(h_bases, m_scalars) if m_scalars else None)
    return U, h_bases, m_scalars


def _scalars_digest(ms):
    """Create a stable digest for a list of int scalars, useful for debugging comparisons."""
    import hashlib
    b = b"|".join(int(m % curve_order).to_bytes(32, "big") for m in ms)
    return hashlib.sha256(b).hexdigest()
