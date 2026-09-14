"""Severity → CVSS + SWC mapping. Static, deterministic, defensible."""
from __future__ import annotations

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}

CVSS_BY_TYPE: dict[str, float] = {
    "REENTRANCY": 9.8,
    "ACCESS_CONTROL": 9.1,
    "UNCHECKED_RETURN": 7.5,
    "TIMESTAMP_DEPENDENCE": 5.3,
    "INTEGER_OVERFLOW": 8.1,
    "INTEGER_UNDERFLOW": 8.1,
    "ORACLE_MANIPULATION": 9.0,
    "FLASH_LOAN": 8.8,
    "DELEGATECALL": 8.5,
    "UNINITIALIZED_STORAGE": 7.0,
    "FRONT_RUNNING": 6.5,
    "SELF_DESTRUCT": 9.2,
}

SEVERITY_BY_TYPE: dict[str, str] = {
    "REENTRANCY": "CRITICAL",
    "ACCESS_CONTROL": "CRITICAL",
    "UNCHECKED_RETURN": "HIGH",
    "TIMESTAMP_DEPENDENCE": "MEDIUM",
    "INTEGER_OVERFLOW": "HIGH",
    "INTEGER_UNDERFLOW": "HIGH",
    "ORACLE_MANIPULATION": "HIGH",
    "FLASH_LOAN": "HIGH",
    "DELEGATECALL": "HIGH",
    "UNINITIALIZED_STORAGE": "MEDIUM",
    "FRONT_RUNNING": "MEDIUM",
    "SELF_DESTRUCT": "CRITICAL",
}

SWC_BY_TYPE: dict[str, str] = {
    "REENTRANCY": "SWC-107",
    "ACCESS_CONTROL": "SWC-105",
    "UNCHECKED_RETURN": "SWC-104",
    "TIMESTAMP_DEPENDENCE": "SWC-116",
    "INTEGER_OVERFLOW": "SWC-101",
    "INTEGER_UNDERFLOW": "SWC-101",
    "ORACLE_MANIPULATION": "SWC-113",
    "FLASH_LOAN": "SWC-107",
    "DELEGATECALL": "SWC-112",
    "UNINITIALIZED_STORAGE": "SWC-109",
    "FRONT_RUNNING": "SWC-114",
    "SELF_DESTRUCT": "SWC-106",
}

TITLE_BY_TYPE: dict[str, str] = {
    "REENTRANCY": "Reentrancy",
    "ACCESS_CONTROL": "Missing Access Control",
    "UNCHECKED_RETURN": "Unchecked Return Value",
    "TIMESTAMP_DEPENDENCE": "Timestamp Dependence",
    "INTEGER_OVERFLOW": "Integer Overflow",
    "INTEGER_UNDERFLOW": "Integer Underflow",
    "ORACLE_MANIPULATION": "Oracle Price Manipulation",
    "FLASH_LOAN": "Flash Loan Vulnerability",
    "DELEGATECALL": "Dangerous Delegatecall",
    "UNINITIALIZED_STORAGE": "Uninitialized Storage Pointer",
    "FRONT_RUNNING": "Front-Running Susceptibility",
    "SELF_DESTRUCT": "Reachable Self-Destruct",
}


def severity_for(vuln_type: str) -> str:
    return SEVERITY_BY_TYPE.get(vuln_type, "MEDIUM")


def cvss_for(vuln_type: str) -> float:
    return CVSS_BY_TYPE.get(vuln_type, 5.0)


def swc_for(vuln_type: str) -> str:
    return SWC_BY_TYPE.get(vuln_type, "SWC-000")


def title_for(vuln_type: str) -> str:
    return TITLE_BY_TYPE.get(vuln_type, vuln_type.replace("_", " ").title())


def risk_score(findings: list) -> tuple[float, str]:
    """Compute 0-100 risk and a label. Higher = worse."""
    if not findings:
        return 0.0, "Safe"
    weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFORMATIONAL": 1}
    score = sum(weights.get(f.severity, 1) for f in findings)
    score = min(score, 100.0)
    if score >= 60:
        label = "Critical"
    elif score >= 35:
        label = "High"
    elif score >= 15:
        label = "Medium"
    elif score > 0:
        label = "Low"
    else:
        label = "Safe"
    return score, label


def audit_score(findings: list) -> float:
    """0-100 where higher is BETTER (frontend displays this)."""
    risk, _ = risk_score(findings)
    return round(max(0.0, 100.0 - risk), 1)