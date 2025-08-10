# bn254/optim/config.py
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class OptimConfig:
    """
    统一的性能/实现参数。后端按需读取；无影响的参数可以忽略。
    """
    window: int | None = None          # MSM 窗口大小（后续用于 wNAF/固定窗）
    precompute: bool = False           # 是否启用预计算表
    threads: int = 1                   # 并行度/线程数
    batch: int = 1                     # 基准/批量 API 的缺省 batch
    seed: int = 42                     # 可复现实验
    serialize_compressed: bool = True  # （预留）序列化策略
    profile: bool = False              # 是否输出详细计时
