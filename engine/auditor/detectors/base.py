"""Detector protocol + Finding intermediate representation."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class Finding:
    """Intermediate finding. Pipeline converts to schema.Vulnerability."""
    type: str                       # e.g. "REENTRANCY"
    line_start: int
    line_end: int
    description: str
    recommendation: str
    evidence: list[str] = field(default_factory=list)
    node_ids: list[int] = field(default_factory=list)   # Slither node ids for CFG highlight
    confidence: float = 90.0
    remediated_code: str = ""
    references: list[str] = field(default_factory=list)


class Detector(Protocol):
    name: str
    def detect(self, slither_obj: Any, source: str) -> list[Finding]: ...   