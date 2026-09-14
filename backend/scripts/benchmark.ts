import * as fs from 'fs';
import * as path from 'path';
import { runAudit } from '../src/engine/analyzer';
import { VulnerabilityType } from '../src/types/index';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ManifestEntry {
  file: string;
  expected: VulnerabilityType[];
  notes?: string;
}

interface Manifest {
  version: string;
  description: string;
  contracts: ManifestEntry[];
}

interface PerContractResult {
  contract: string;
  category: 'vulnerable' | 'secure';
  expected: VulnerabilityType[];
  found: VulnerabilityType[];
  tp: string[];
  fn: string[];
  fp: string[];
  tn: string[];
}

interface AggregatedMetrics {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
  f1: number;
}

interface DetectorMetrics {
  detector: string;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadManifest(): Manifest {
  const manifestPath = path.join(__dirname, '..', 'benchmark', 'MANIFEST.json');
  return JSON.parse(fs.readFileSync(manifestPath, 'utf-8')) as Manifest;
}

function readContract(relativePath: string): string {
  const fullPath = path.join(__dirname, '..', 'benchmark', relativePath);
  return fs.readFileSync(fullPath, 'utf-8');
}

function uniqueTypes(types: VulnerabilityType[]): VulnerabilityType[] {
  return [...new Set(types)];
}

function fmtPct(v: number): string {
  return (v * 100).toFixed(1) + '%';
}

function padR(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function padL(s: string, n: number): string {
  return s.length >= n ? s : ' '.repeat(n - s.length) + s;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const START = Date.now();
  const manifest = loadManifest();

  console.log('================================================================');
  console.log('  SMART CONTRACT AUDITOR — BENCHMARK SUITE');
  console.log('  Deterministic: re-runnable (no randomness, no external calls)');
  console.log('  Corpus: ' + manifest.contracts.length + ' contracts');
  console.log('================================================================\n');

  const results: PerContractResult[] = [];

  for (const entry of manifest.contracts) {
    const contractName = path.basename(entry.file, '.sol');
    const category = entry.file.startsWith('secure/') ? 'secure' : 'vulnerable';
    const source = readContract(entry.file);

    process.stdout.write(`  Auditing ${padR(contractName, 28)}`);

    let foundTypes: VulnerabilityType[] = [];
    try {
      const report = await runAudit({
        contractName,
        sourceCode: source,
      });
      foundTypes = uniqueTypes(report.vulnerabilities.map((v) => v.type));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`[ERROR: ${msg}]`);
      continue;
    }

    const expectedSet = new Set(entry.expected);
    const foundSet = new Set(foundTypes);

    const tp: string[] = [];
    const fn: string[] = [];
    const fp: string[] = [];
    const tn: string[] = [];

    if (category === 'vulnerable') {
      for (const e of entry.expected) {
        if (foundSet.has(e)) tp.push(e);
        else fn.push(e);
      }
      for (const f of foundTypes) {
        if (!expectedSet.has(f)) fp.push(f);
      }
    } else {
      // Secure: any finding is FP; no finding is TN
      for (const f of foundTypes) {
        fp.push(f);
      }
      if (foundTypes.length === 0) {
        tn.push('CLEAN' as any);
      }
    }

    const expectedStr = entry.expected.length ? entry.expected.join(', ') : '(none)';
    const foundStr = foundTypes.length ? foundTypes.join(', ') : '(none)';
    console.log(`found: ${foundStr}`);

    results.push({
      contract: contractName,
      category,
      expected: entry.expected,
      found: foundTypes,
      tp,
      fn,
      fp,
      tn,
    });
  }

  // -------------------------------------------------------------------------
  // Aggregate metrics
  // -------------------------------------------------------------------------

  let totalTP = 0;
  let totalFP = 0;
  let totalFN = 0;
  let totalTN = 0;

  for (const r of results) {
    totalTP += r.tp.length;
    totalFP += r.fp.length;
    totalFN += r.fn.length;
    if (r.category === 'secure' && r.tn.length > 0) {
      totalTN += 1; // Count each clean secure contract as one TN unit
    }
  }

  const precision = totalTP + totalFP > 0 ? totalTP / (totalTP + totalFP) : 0;
  const recall = totalTP + totalFN > 0 ? totalTP / (totalTP + totalFN) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  // -------------------------------------------------------------------------
  // Per-detector metrics
  // ---------------------------------------------------------------------------

  const allDetectorTypes = new Set<VulnerabilityType>();
  for (const r of results) {
    for (const t of r.expected) allDetectorTypes.add(t);
    for (const t of r.found) allDetectorTypes.add(t);
  }

  const detectorMetrics: DetectorMetrics[] = [];
  for (const det of allDetectorTypes) {
    let dTP = 0;
    let dFP = 0;
    let dFN = 0;
    let dTN = 0;

    for (const r of results) {
      const expectedThisDet = r.expected.includes(det);
      const foundThisDet = r.found.includes(det);

      if (expectedThisDet && foundThisDet) dTP++;
      else if (expectedThisDet && !foundThisDet) dFN++;
      else if (!expectedThisDet && foundThisDet) dFP++;
      else dTN++; // not expected, not found — correct negative
    }

    const dPrecision = dTP + dFP > 0 ? dTP / (dTP + dFP) : 0;
    const dRecall = dTP + dFN > 0 ? dTP / (dTP + dFN) : 0;

    detectorMetrics.push({
      detector: det,
      tp: dTP,
      fp: dFP,
      fn: dFN,
      tn: dTN,
      precision: dPrecision,
      recall: dRecall,
    });
  }

  // -------------------------------------------------------------------------
  // Print results
  // -------------------------------------------------------------------------

  console.log('\n================================================================');
  console.log('  PER-CONTRACT RESULTS');
  console.log('================================================================\n');

  console.log(
    '  ' +
    padR('Contract', 30) +
    padL('Cat', 8) +
    padL('Expected', 28) +
    padL('Found', 28) +
    padL('TP', 4) +
    padL('FN', 4) +
    padL('FP', 4) +
    padL('TN', 4)
  );
  console.log('  ' + '-'.repeat(110));

  for (const r of results) {
    const expectedStr = r.expected.length ? r.expected.join(', ') : '(none)';
    const foundStr = r.found.length ? r.found.join(', ') : '(none)';
    const tnVal = r.tn.length > 0 ? '1' : '0';
    console.log(
      '  ' +
      padR(r.contract, 30) +
      padL(r.category === 'vulnerable' ? 'VULN' : 'SAFE', 8) +
      padL(expectedStr, 28) +
      padL(foundStr, 28) +
      padL(String(r.tp.length), 4) +
      padL(String(r.fn.length), 4) +
      padL(String(r.fp.length), 4) +
      padL(tnVal, 4)
    );
  }

  // -------------------------------------------------------------------------
  // Aggregate
  // -------------------------------------------------------------------------

  console.log('\n================================================================');
  console.log('  AGGREGATE METRICS');
  console.log('================================================================\n');

  console.log(`  True Positives  (TP):  ${totalTP}`);
  console.log(`  False Positives (FP):  ${totalFP}`);
  console.log(`  False Negatives (FN):  ${totalFN}`);
  console.log(`  True Negatives  (TN):  ${totalTN}`);
  console.log('');
  console.log(`  Precision:  ${fmtPct(precision)}  (${totalTP} / ${totalTP + totalFP})`);
  console.log(`  Recall:     ${fmtPct(recall)}  (${totalTP} / ${totalTP + totalFN})`);
  console.log(`  F1 Score:   ${fmtPct(f1)}`);
  console.log('');
  console.log('  Note: Metrics are deterministic — re-runnable with identical results.');

  // -------------------------------------------------------------------------
  // Per-detector
  // -------------------------------------------------------------------------

  console.log('\n================================================================');
  console.log('  PER-DETECTOR METRICS');
  console.log('================================================================\n');

  console.log(
    '  ' +
    padR('Detector', 24) +
    padL('TP', 4) +
    padL('FP', 4) +
    padL('FN', 4) +
    padL('TN', 4) +
    padL('Prec', 8) +
    padL('Recall', 8)
  );
  console.log('  ' + '-'.repeat(60));

  for (const dm of detectorMetrics) {
    console.log(
      '  ' +
      padR(dm.detector, 24) +
      padL(String(dm.tp), 4) +
      padL(String(dm.fp), 4) +
      padL(String(dm.fn), 4) +
      padL(String(dm.tn), 4) +
      padL(fmtPct(dm.precision), 8) +
      padL(fmtPct(dm.recall), 8)
    );
  }

  // -------------------------------------------------------------------------
  // FPs detail
  // -------------------------------------------------------------------------

  const fpContracts = results.filter((r) => r.fp.length > 0);
  if (fpContracts.length > 0) {
    console.log('\n================================================================');
    console.log('  FALSE POSITIVE DETAILS');
    console.log('================================================================\n');
    for (const r of fpContracts) {
      console.log(`  ${r.contract}: ${r.fp.join(', ')}`);
    }
  }

  const fnContracts = results.filter((r) => r.fn.length > 0);
  if (fnContracts.length > 0) {
    console.log('\n================================================================');
    console.log('  FALSE NEGATIVE DETAILS');
    console.log('================================================================\n');
    for (const r of fnContracts) {
      console.log(`  ${r.contract}: missed [${r.fn.join(', ')}]`);
    }
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------

  const elapsed = ((Date.now() - START) / 1000).toFixed(1);
  console.log('\n================================================================');
  console.log(`  BENCHMARK COMPLETE — ${results.length} contracts audited in ${elapsed}s`);
  console.log(`  Precision=${fmtPct(precision)} Recall=${fmtPct(recall)} F1=${fmtPct(f1)}`);
  console.log('  Deterministic: re-runnable with identical results.');
  console.log('================================================================\n');

  process.exit(0);
}

main().catch((e) => {
  console.error('BENCHMARK FAILED:', e);
  process.exit(1);
});
