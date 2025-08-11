import hashlib
from ..params import rand_scalar, g1_mul, g1, curve_order, msm_g1, add

from ..backend_pyecc import G1
from mclbn256 import G1 as _MclG1
def hash_to_scalar(data: bytes) -> int:
    """
    字节串到标量的哈希映射

    功能：将任意长度的字节串计算Hash后映射到标量域Zp
    安全性：使用SHA-256确保单向性和抗碰撞性

    Returns:
        int: 返回值小于椭圆曲线的阶数curve_order，同时不为0
    """
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % curve_order or 1



def hash_to_g1(label: bytes):
    """
    把 label 映射到 G1。
    重要：hashAndMapTo/mapToG1 修改对象本身，返回值是 None！
    一定要“先创建，再调用，再 return 对象”，否则就会把 None 传下去。
    """
    P = G1()
    if hasattr(P, "hashAndMapTo"):
        P.hashAndMapTo(label)
        return P
    if hasattr(P, "mapToG1"):
        P.mapToG1(label)
        return P

    # 兜底：无映射 API 时退回旧方案（已知离散对数，安全性稍弱但可运行）
    h = int.from_bytes(label, "big") % curve_order
    return g1_mul(g1, h)

def _as_bytes(x):
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("utf-8")
    if isinstance(x, int):
        # 用最短 big-endian 表示；0 也占 1 字节
        n = (x.bit_length() + 7) // 8 or 1
        return x.to_bytes(n, "big", signed=False)
    # 兜底：结构化对象尽量 JSON，失败再 repr
    try:
        import json
        return json.dumps(x, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception:
        return repr(x).encode("utf-8")
def ensure_scalar(x):
    """把任意类型转成标量 int（mod r）。"""
    from ..params import curve_order
    if isinstance(x, int):
        return x % curve_order
    # bytes/str/其他 → 先拿 bytes，再 hash 到标量
    return hash_to_scalar(_as_bytes(x)) % curve_order

def encode_attributes(attrs):
    # 统一把属性转成标量 int
    return [ensure_scalar(a) for a in attrs]


def get_h_bases(n: int):
    bases = [hash_to_g1(b"H" + i.to_bytes(4, "big")) for i in range(n)]
    # 守护：防止返回 None 混进 MSM
    if any(b is None for b in bases):
        raise RuntimeError("hash_to_g1 返回了 None，请检查实现是否误写成 `return P.hashAndMapTo(...)`")
    return bases


try:
    from bn254.optim.config import OptimConfig
except Exception:
    OptimConfig = None  # 兜底，不破坏现有导入

_GLOBAL_OPTIM = None


def set_optim(optim):
    """
    供外部（后端适配器）设置优化参数。若 v1 内部需要，可在此处把参数
    写入你现有的全局变量/上下文中。例如：
        some_global.window = optim.window
        some_global.enable_precompute = optim.precompute
        some_global.threads = optim.threads
    目前先存一份，后面你在 v1 内部用得到可以直接读取 `_GLOBAL_OPTIM`。
    """
    global _GLOBAL_OPTIM
    _GLOBAL_OPTIM = optim

def get_optim():
    return _GLOBAL_OPTIM


def build_U_and_ms(attrs):
    """唯一来源：先算 m_scalars，再 U = g1 + Σ H_i^{m_i}。"""
    h_bases   = get_h_bases(len(attrs))
    m_scalars = encode_attributes(attrs)
    U = add(g1, msm_g1(h_bases, m_scalars) if m_scalars else None)
    return U, h_bases, m_scalars


def _scalars_digest(ms):
    """给一组int标量做个稳定摘要，便于对照调试。"""
    import hashlib
    b = b"|".join(int(m % curve_order).to_bytes(32, "big") for m in ms)
    return hashlib.sha256(b).hexdigest()