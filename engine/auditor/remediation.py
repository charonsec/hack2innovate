from __future__ import annotations

import difflib


def remediation_for(vuln_type: str) -> str:
    fixes = {
        "REENTRANCY": "Apply Checks-Effects-Interactions and consider ReentrancyGuard/nonReentrant.",
        "ACCESS_CONTROL": "Protect privileged functions with onlyOwner or equivalent access control.",
        "UNCHECKED_RETURN": "Check the return value of low-level external calls.",
        "TIMESTAMP_DEPENDENCE": "Avoid block.timestamp for randomness; use a trusted randomness source.",
    }
    return fixes.get(vuln_type, "Apply the recommended fix and re-run the audit.")


def unified_diff(original: str, fixed: str, filename: str = "contract.sol") -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
    )


def secure_template(source: str, findings: list) -> str:
    """Generate a conservative hardened source for the report."""

    fixed = source

    for finding in sorted(
        findings,
        key=lambda f: f.line_start,
        reverse=True,
    ):
        if finding.type != "REENTRANCY":
            continue

        lines = fixed.splitlines(keepends=True)

        call = finding.line_start - 1
        state = finding.line_end - 1

        if not (0 <= call < len(lines) and 0 <= state < len(lines)):
            continue

        # Move the detected state update before the external call.
        state_line = lines.pop(state)
        lines.insert(call, state_line)

        fixed = "".join(lines)

    return fixed
