#!/usr/bin/env python3
"""
Benchmark harness for HexAudit against a large, unlabeled dataset of
real-world Solidity contracts (e.g. contract_dataset_github/).

Since this dataset has no ground-truth labels, this measures:
  ROBUSTNESS: parse/compile success rate, crash rate (by exception type),
              timeout rate, latency distribution (p50/p95/p99).
  DETECTION:  findings per contract, category breakdown, severity
              breakdown, % of contracts with zero findings.

=== WIRE-UP (the only thing you need to edit) ===
Edit `run_single_audit()` below to call your actual pipeline. It currently
tries a few common entrypoint names in engine/auditor/pipeline.py and
falls back to a clear error telling you what to fix. Point me at your
pipeline.py's real function signature and I'll wire this exactly instead
of guessing.

=== USAGE ===
    python benchmark_github_dataset.py \\
        --dataset-dir /home/frost-walk/Downloads/data/Ethereum_smart_contract_datast/contract_dataset_github \\
        --workers 8 \\
        --timeout 30 \\
        --limit 2000 \\
        --output results

Resumable: re-running with the same --output skips files already recorded
in results/raw.jsonl, so a killed run can be restarted cheaply.
"""
import argparse
import json
import os
import re
import statistics
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FutTimeoutError
from pathlib import Path
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# WIRE-UP: point this at your real pipeline. Edit freely.
# ---------------------------------------------------------------------------
def run_single_audit(sol_path: str) -> dict:
    """
    Calls the real HexAudit pipeline: run_audit(contract_name, source_code).
    Returns a dict with:
      {
        "findings": [ {"category": <Vulnerability.type>, "severity": <Vulnerability.severity>}, ... ],
        "scan_duration": <float or None>,
      }
    Raises on failure — the harness classifies exceptions for you.
    """
    import uuid as _uuid

    # Make the repo's engine/ package importable from wherever this script lives.
    repo_root = Path(__file__).resolve().parent
    for candidate in [repo_root, repo_root / "engine", repo_root.parent / "engine", repo_root.parent]:
        if (candidate / "auditor").exists():
            sys.path.insert(0, str(candidate))
            break

    from auditor.pipeline import run_audit  # engine/auditor/pipeline.py

    with open(sol_path, "r", errors="replace") as f:
        source_code = f.read()

    # Unique per-call name: run_audit writes a temp file named after
    # contract_name, and workers run in parallel, so avoid collisions
    # across contracts that share a filename stem across repos.
    base_name = Path(sol_path).stem or "contract"
    contract_name = f"{base_name}_{os.getpid()}_{_uuid.uuid4().hex[:6]}"

    report = run_audit(contract_name, source_code)

    # Normalize whatever schema.py's AuditReport actually is (pydantic v1/v2,
    # dataclass, or plain object) into a plain dict.
    if hasattr(report, "model_dump"):
        data = report.model_dump()
    elif hasattr(report, "dict"):
        data = report.dict()
    elif hasattr(report, "__dict__"):
        data = report.__dict__
    else:
        data = report

    vulns = data.get("vulnerabilities", []) or []
    findings = []
    for v in vulns:
        vd = v if isinstance(v, dict) else (v.model_dump() if hasattr(v, "model_dump")
              else v.dict() if hasattr(v, "dict") else v.__dict__)
        findings.append({
            "category": vd.get("type", "unknown"),
            "severity": vd.get("severity", "unknown"),
        })

    return {
        "findings": findings,
        "scan_duration": data.get("scan_duration"),
    }


# ---------------------------------------------------------------------------
# Harness internals — shouldn't need to touch below this line.
# ---------------------------------------------------------------------------

PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^\s;]+)")


def classify_exception(exc: BaseException) -> str:
    """Buckets exceptions into coarse categories so the report is readable."""
    msg = str(exc).lower()
    name = type(exc).__name__
    if "import" in msg or "not found" in msg or "no such file" in msg:
        return "missing_import_or_file"
    if "compil" in msg or "solc" in msg or "pragma" in msg:
        return "compile_error"
    if "timeout" in name.lower():
        return "timeout"
    if "memory" in msg:
        return "out_of_memory"
    return f"other:{name}"


def _worker(sol_path: str) -> dict:
    """Runs in a subprocess so a segfault/hang in one contract can't kill the batch."""
    start = time.time()
    try:
        with open(sol_path, "r", errors="replace") as f:
            src = f.read()
        pragma_match = PRAGMA_RE.search(src)
        pragma = pragma_match.group(1) if pragma_match else None
        loc = src.count("\n") + 1

        result = run_single_audit(sol_path)
        elapsed = time.time() - start

        findings = result.get("findings", []) if isinstance(result, dict) else []
        categories = Counter(f.get("category", "unknown") for f in findings)
        severities = Counter(f.get("severity", "unknown") for f in findings)

        return {
            "path": sol_path,
            "status": "ok",
            "elapsed_s": round(elapsed, 4),
            "loc": loc,
            "pragma": pragma,
            "finding_count": len(findings),
            "categories": dict(categories),
            "severities": dict(severities),
        }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "path": sol_path,
            "status": "error",
            "error_class": classify_exception(e),
            "error_msg": str(e)[:300],
            "elapsed_s": round(elapsed, 4),
            "traceback": traceback.format_exc()[-1500:],
        }


def find_contracts(dataset_dir: str, limit: int | None) -> list[str]:
    paths = []
    for root, _dirs, files in os.walk(dataset_dir):
        for fname in files:
            if fname.endswith(".sol"):
                paths.append(os.path.join(root, fname))
                if limit and len(paths) >= limit:
                    return paths
    return paths


def load_already_done(raw_path: Path) -> set:
    done = set()
    if raw_path.exists():
        with open(raw_path) as f:
            for line in f:
                try:
                    done.add(json.loads(line)["path"])
                except Exception:
                    continue
    return done


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    k = (len(values) - 1) * pct
    f, c = int(k), min(int(k) + 1, len(values) - 1)
    if f == c:
        return values[f]
    return values[f] + (values[c] - values[f]) * (k - f)


def summarize(raw_path: Path, out_dir: Path):
    records = []
    with open(raw_path) as f:
        for line in f:
            records.append(json.loads(line))

    total = len(records)
    ok = [r for r in records if r["status"] == "ok"]
    errors = [r for r in records if r["status"] == "error"]

    error_by_class = Counter(r["error_class"] for r in errors)
    latencies = [r["elapsed_s"] for r in ok]

    all_categories = Counter()
    all_severities = Counter()
    for r in ok:
        for cat, n in r.get("categories", {}).items():
            all_categories[cat] += n
        for sev, n in r.get("severities", {}).items():
            all_severities[sev] += n

    finding_counts = [r["finding_count"] for r in ok]
    zero_finding = sum(1 for c in finding_counts if c == 0)

    pragma_dist = Counter(r.get("pragma") for r in ok if r.get("pragma"))

    summary = {
        "total_contracts": total,
        "ok": len(ok),
        "errors": len(errors),
        "success_rate": round(len(ok) / total, 4) if total else 0,
        "error_breakdown": dict(error_by_class.most_common()),
        "latency_seconds": {
            "mean": round(statistics.mean(latencies), 4) if latencies else 0,
            "median": round(statistics.median(latencies), 4) if latencies else 0,
            "p95": round(percentile(latencies, 0.95), 4),
            "p99": round(percentile(latencies, 0.99), 4),
            "max": round(max(latencies), 4) if latencies else 0,
        },
        "detection": {
            "total_findings": sum(finding_counts),
            "avg_findings_per_contract": round(statistics.mean(finding_counts), 3) if finding_counts else 0,
            "median_findings_per_contract": statistics.median(finding_counts) if finding_counts else 0,
            "contracts_with_zero_findings": zero_finding,
            "contracts_with_zero_findings_pct": round(zero_finding / len(ok), 4) if ok else 0,
            "category_breakdown": dict(all_categories.most_common()),
            "severity_breakdown": dict(all_severities.most_common()),
        },
        "top_10_pragma_versions": dict(pragma_dist.most_common(10)),
    }

    with open(out_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)
    print(f"Contracts scanned:  {total}")
    print(f"Succeeded:          {len(ok)} ({summary['success_rate']*100:.1f}%)")
    print(f"Errored:            {len(errors)}")
    if error_by_class:
        print("\nError breakdown:")
        for cls, n in error_by_class.most_common():
            print(f"  {cls:30s} {n:6d}  ({n/total*100:.1f}%)")
    print(f"\nLatency (s): mean={summary['latency_seconds']['mean']} "
          f"median={summary['latency_seconds']['median']} "
          f"p95={summary['latency_seconds']['p95']} "
          f"p99={summary['latency_seconds']['p99']}")
    print(f"\nTotal findings:     {summary['detection']['total_findings']}")
    print(f"Avg findings/contract: {summary['detection']['avg_findings_per_contract']}")
    print(f"Contracts w/ zero findings: {summary['detection']['contracts_with_zero_findings']} "
          f"({summary['detection']['contracts_with_zero_findings_pct']*100:.1f}%)")
    if all_categories:
        print("\nTop categories:")
        for cat, n in all_categories.most_common(10):
            print(f"  {cat:35s} {n:6d}")
    print(f"\nFull details: {out_dir / 'summary.json'}")
    print(f"Raw per-contract records: {raw_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", required=True)
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--timeout", type=int, default=30, help="seconds per contract")
    ap.add_argument("--limit", type=int, default=None, help="cap number of contracts (for a quick pass)")
    ap.add_argument("--output", default="benchmark_results")
    args = ap.parse_args()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "raw.jsonl"

    print(f"Scanning {args.dataset_dir} for .sol files...")
    all_paths = find_contracts(args.dataset_dir, args.limit)
    print(f"Found {len(all_paths)} contracts.")

    already_done = load_already_done(raw_path)
    todo = [p for p in all_paths if p not in already_done]
    print(f"Already done: {len(already_done)}. Remaining: {len(todo)}.")

    if todo:
        with open(raw_path, "a") as raw_f, ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(_worker, p): p for p in todo}
            completed = 0
            for fut in list(futures):
                path = futures[fut]
                try:
                    record = fut.result(timeout=args.timeout)
                except FutTimeoutError:
                    record = {"path": path, "status": "error", "error_class": "timeout",
                              "error_msg": f"exceeded {args.timeout}s", "elapsed_s": args.timeout}
                except Exception as e:
                    record = {"path": path, "status": "error", "error_class": classify_exception(e),
                              "error_msg": str(e)[:300], "elapsed_s": 0}
                raw_f.write(json.dumps(record) + "\n")
                raw_f.flush()
                completed += 1
                if completed % 50 == 0:
                    print(f"  {completed}/{len(todo)} done...")

    summarize(raw_path, out_dir)


if __name__ == "__main__":
    main()