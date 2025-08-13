# bn254/utils/instrumentation.py
from __future__ import annotations
import time
from contextlib import contextmanager
from statistics import mean

def now_ms() -> float:
    """Return the current time in milliseconds."""
    return time.perf_counter() * 1000.0

@contextmanager
def maybe_profile_section(enabled: bool, label: str):
    """
    Context manager to optionally profile a code section.

    Args:
        enabled (bool): Whether profiling is enabled.
        label (str): A label to identify the profiled section.
    """
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
    """
    Simple measurement: returns a list of execution times [ms, ...] and the mean.

    Args:
        fn (callable): Function to measure.
        times (int): Number of times to run the function.

    Returns:
        tuple[list[float], float]: List of execution times in milliseconds, and the average.
    """
    xs = []
    for _ in range(times):
        t0 = now_ms()
        fn()
        xs.append(now_ms() - t0)
    return xs, mean(xs)

def percentile(xs, p):
    """
    Calculate the p-th percentile of a list of numbers.

    Args:
        xs (list[float]): Data values.
        p (float): Percentile to calculate (0–100).

    Returns:
        float: The p-th percentile value.
    """
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = (len(xs) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[int(k)]
    return xs[f] + (xs[c] - xs[f]) * (k - f)
