"""Run the engine against the labeled benchmark corpus.

Usage:
    cd engine && python tests/run_benchmark.py
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditor.pipeline import run_audit  # noqa: E402

MANIFEST = ROOT.parent / "backend" / "benchmark" / "MANIFEST.json"
FIXTURES = ROOT / "tests" / "fixtures"


def main() -> None:
    manifest = json.loads(MANIFEST.read_text())
    total_expected = 0
    total_hit = 0
    total_found = 0
    total_fp = 0
    rows = []

    for entry in manifest["contracts"]:
        rel = entry["file"]
        path = FIXTURES / rel
        if not path.exists():
            rows.append((rel, "MISSING", "", "❌"))
            continue
        source = path.read_text()
        name = path.stem
        try:
            report = run_audit(name, source)
        except Exception as e:
            rows.append((rel, ",".join(entry["expected"]) or "(none)", f"ERROR: {e}", "❌"))
            continue

        found_types = sorted({v.type for v in report.vulnerabilities})
        expected = set(entry["expected"])
        found = set(found_types)

        hits = expected & found
        misses = expected - found
        fps = found - expected

        total_expected += len(expected)
        total_hit += len(hits)
        total_found += len(found)
        total_fp += len(fps)

        status = "✅" if not misses and not fps else (
            "🟡" if not misses else "❌"
        )
        rows.append((rel, ",".join(sorted(expected)) or "(none)",
                     ",".join(sorted(found)) or "(none)", status))

    print(f"{'Contract':<28} {'Expected':<32} {'Found':<32} Status")
    print("-" * 100)
    for r in rows:
        print(f"{r[0]:<28} {r[1]:<32} {r[2]:<32} {r[3]}")

    precision = total_hit / total_found if total_found else 1.0
    recall = total_hit / total_expected if total_expected else 1.0
    print("-" * 100)
    print(f"Precision: {precision:.2%}   Recall: {recall:.2%}   "
          f"TP: {total_hit}  FP: {total_fp}  Expected total: {total_expected}")


if __name__ == "__main__":
    main()