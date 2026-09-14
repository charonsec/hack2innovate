"""Oracle price-manipulation heuristic.

Flags patterns where a spot balance / AMM reserve is used to derive a price:
- `token.balanceOf(...)` assigned to a variable named like *price* or multiplied
  into a price/collateral value
- `.getReserves()` / `.slot0()` used without a TWAP / Chainlink wrapper
"""
from __future__ import annotations
import re
from typing import Any
from .base import Finding

_SPOT = re.compile(r"\.(balanceOf|getReserves|slot0)\s*\(")
_PRICEY = re.compile(r"price|collateral|value|oracle", re.I)
_CHAINLINK = re.compile(r"AggregatorV3|latestRoundData|chainlink", re.I)


def detect(slither_obj: Any, source: str) -> list[Finding]:
    if _CHAINLINK.search(source):
        return []  # already using a proper oracle

    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, start=1):
        if not _SPOT.search(line):
            continue
        # look at surrounding ±3 lines for price-y context
        ctx = "\n".join(lines[max(0, i - 4):min(len(lines), i + 3)])
        if not _PRICEY.search(ctx):
            continue
        findings.append(Finding(
            type="ORACLE_MANIPULATION",
            line_start=i,
            line_end=i,
            description=(
                f"Spot price derived from `{_SPOT.search(line).group(1)}` at line {i}. "
                f"A flash-loan attacker can move the pool balance within a single "
                f"transaction, skewing any price derived from it (SWC-113)."
            ),
            recommendation=(
                "Use a time-weighted average price (TWAP) or a Chainlink "
                "AggregatorV3Interface feed with a staleness check."
            ),
            evidence=[f"Line {i}: {line.strip()}"],
            confidence=75.0,
            references=["https://swcregistry.io/docs/SWC-113"],
        ))
        break  # one finding per contract is enough
    return findings