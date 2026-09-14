"""Overflow/underflow detector for Solidity <0.8 (no SafeMath)."""
from __future__ import annotations
import re
from typing import Any
from .base import Finding

_PRAGMA = re.compile(r"pragma\s+solidity\s+[\^~>=<]*\s*(\d+)\.(\d+)")
_ARITH = re.compile(r"\b([A-Za-z_]\w*)\s*([+\-*])\s*(?!=)")


def _is_pre_08(source: str) -> bool:
    m = _PRAGMA.search(source)
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2))
    return (major, minor) < (0, 8)


def detect(slither_obj: Any, source: str) -> list[Finding]:
    if not _is_pre_08(source):
        return []
    if "SafeMath" in source or "using SafeMath" in source:
        return []

    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        for m in _ARITH.finditer(line):
            var, op = m.group(1), m.group(2)
            if var in {"return", "require", "if", "for", "while"}:
                continue
            vuln_type = "INTEGER_UNDERFLOW" if op == "-" else "INTEGER_OVERFLOW"
            findings.append(Finding(
                type=vuln_type,
                line_start=i,
                line_end=i,
                description=(
                    f"Arithmetic on `{var}` at line {i} without SafeMath. Under "
                    f"Solidity <0.8, `{op}` can silently wrap around (SWC-101)."
                ),
                recommendation=(
                    "Upgrade to Solidity >=0.8.0 (built-in overflow checks) or use "
                    "OpenZeppelin's `SafeMath` library for all arithmetic."
                ),
                evidence=[f"Line {i}: {stripped}"],
                confidence=80.0,
                references=["https://swcregistry.io/docs/SWC-101"],
            ))
            break  # one finding per line
    return findings