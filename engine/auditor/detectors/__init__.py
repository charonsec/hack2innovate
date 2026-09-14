"""Detector registry."""
from . import (
    reentrancy,
    access_control,
    unchecked_call,
    timestamp,
    overflow,
    delegatecall,
    oracle,
)

ALL = [
    reentrancy,
    access_control,
    unchecked_call,
    timestamp,
    overflow,
    delegatecall,
    oracle,
]