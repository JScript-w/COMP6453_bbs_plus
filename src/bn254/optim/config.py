# bn254/optim/config.py
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class OptimConfig:
    """
    Unified performance/implementation configuration. 
    Backends read parameters as needed; parameters that have no effect can be ignored.
    """
    window: int | None = None          # MSM window size (used later for wNAF/fixed window)
    precompute: bool = False           # Whether to enable precomputation tables
    threads: int = 1                   # Level of parallelism / number of threads
    batch: int = 1                     # Default batch size for benchmark/batch APIs
    seed: int = 42                     # Seed for reproducible experiments
    serialize_compressed: bool = True  # (Reserved) Serialization strategy
    profile: bool = False              # Whether to output detailed timing
