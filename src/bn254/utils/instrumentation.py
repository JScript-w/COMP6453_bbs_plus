# bn254/utils/instrumentation.py
from __future__ import annotations
import time
from contextlib import contextmanager
from statistics import mean

def now_ms() -> float:
    return time.perf_counter() * 1000.0

@contextmanager
def maybe_profile_section(enabled: bool, label: str):
    if not enabled:
        yield
        return
    t0 = now_ms()
    try:
        yield
    finally:
        t1 = now_ms()
        print(f"[profile] {label}: {t1 - t0:.3f} ms")

def measure_many(fn, times: int = 10):
    """简单测量：返回 [ms,...] 列表与均值"""
    xs = []
    for _ in range(times):
        t0 = now_ms()
        fn()
        xs.append(now_ms() - t0)
    return xs, mean(xs)

def percentile(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = (len(xs) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[int(k)]
    return xs[f] + (xs[c] - xs[f]) * (k - f)
