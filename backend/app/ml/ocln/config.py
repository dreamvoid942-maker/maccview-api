"""Minimal Config for the vendored feature engine.

The upstream ocln/config.py imports torch in __post_init__ purely to pick a
device. The feature engine reads exactly one field, FEATURE_DIM, so this stub
keeps the exact compute_features body without pulling the training stack into
the API process.
"""
from dataclasses import dataclass


@dataclass
class Config:
    FEATURE_DIM: int = 48
