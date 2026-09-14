"""Timestamp dependence detector."""
from __future__ import annotations
import re                                   
from typing import Any
from .base import Finding

def detect(slither_obj: Any, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()

    # Terms that hint the timestamp is being used for fairness / randomness
    fairness_terms = ("lottery", "winner", "random", "prize", "game", "fair", "seed", "draw")

    for i, line in enumerate(lines, start=1):
        if "block.timestamp" not in line and "block.number" not in line:
            continue

        # Skip valid staleness checks: `block.timestamp - X < Y` or `block.timestamp > X + Y`
        if re.search(r"block\.timestamp\s*[-+]\s*\w+", line) and (
            "stale" in line.lower() or "updated" in line.lower()
        ):
            continue

        # Must be in decision logic
        decision_ctx = any(k in line for k in ("if", "require", "assert"))
        if not decision_ctx:
            continue

        # Only flag if:
        #  (a) modulo arithmetic (classic bad randomness), OR
        #  (b) fairness/randomness terms in nearby context
        has_modulo = "%" in line
        ctx = "\n".join(lines[max(0, i - 6):min(len(lines), i + 4)]).lower()
        has_fairness_ctx = any(t in ctx for t in fairness_terms)

        if not (has_modulo or has_fairness_ctx):
            continue

        findings.append(Finding(
            type="TIMESTAMP_DEPENDENCE",
            line_start=i,
            line_end=i,
            description=(
                f"`block.timestamp` is used for randomness or fairness logic at line {i}. "
                f"Miners can nudge timestamps within a small window, biasing any "
                f"outcome derived from them (SWC-116)."
            ),
            recommendation=(
                "Do not use `block.timestamp` for randomness or fairness. Use a "
                "commit-reveal scheme or Chainlink VRF for randomness."
            ),
            evidence=[f"Line {i}: {line.strip()}"],
            confidence=85.0,
            references=["https://swcregistry.io/docs/SWC-116"],
        ))
    return findings