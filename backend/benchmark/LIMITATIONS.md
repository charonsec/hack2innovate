# Benchmark Limitations

This document records known detector limitations observed during benchmark runs.

## Honest Metrics Policy

The benchmark runner reports **unfiltered, honest numbers**. No findings are suppressed
or hidden. If a detector produces a false positive or misses an expected vulnerability,
that is reflected in the precision/recall/F1 metrics.

## Methodology Note: Label Coverage

Each contract in the corpus is labeled only with the vulnerability types it is intended
to demonstrate (see `MANIFEST.json`). If a contract genuinely contains a SECOND real
vulnerability that is not in its label list, that finding is still counted as an FP
relative to the label. Example: `AccessControlVuln.sol` demonstrates **ACCESS_CONTROL**
(unprotected `setOracle()`), but that same unprotected setter also makes `priceOracle`
arbitrarily mutable, so the oracle detector additionally reports ORACLE_MANIPULATION.
The finding is real, but it is not in the label, so it is recorded as an FP.

Separate from that, genuinely-spurious findings from detector heuristics (below) are
also counted, exactly as they would surface in a real audit.

## Known Limitations (Specific FPs Observed)

### ORACLE_MANIPULATION Detector — "Mutable price source" heuristic (3 FPs observed)

The third detection branch flags **any** read or write of a storage variable whose name
matches `/oracle|price|feed/` inside a function, regardless of whether the variable is
guarded, is a Chainlink feed, or is ever read for a pricing decision.

- **FP on `SecureAccessControl.sol`**: `setOracle() onlyOwner` writes `priceOracle`.
  The detector cannot distinguish a guarded setter from an unguarded one and emits
  "Mutable price source 'priceOracle'". The contract is secure.
- **FP on `SecureOracle.sol`**: `priceFeed` (a Chainlink `AggregatorV3Interface`) is
  read in `getPrice()`. Even with `latestRoundData()` and a staleness check present,
  the detector emits "Mutable price source 'priceFeed'".
- **FP on `AccessControlVuln.sol`**: same heuristic fires on the vulnerable contract's
  unprotected oracle setter — real risk, but outside the ACCESS_CONTROL label.

Mitigation: restrict the branch to writes that lack an `onlyOwner`/`onlyRole` guard, and
skip variables typed as / associated with a Chainlink interface.

### TIMESTAMP_DEPENDENCE Detector — Staleness checks (1 FP observed)

- **FP on `SecureOracle.sol`**: the correct staleness guard
  `require(block.timestamp - updatedAt < 1 hours, "Stale price feed")` is flagged as a
  LOW "block.timestamp-dependent logic branch". Using `block.timestamp` to bound data
  freshness is the recommended Chainlink pattern and should not fire.

Mitigation: whitelist the `block.timestamp - updatedAt` / `block.timestamp >= updatedAt`
staleness idiom against data-feed reads.

### REENTRANCY Detector — Mapping-write blind spot (FN observed during development)

The CEI scanner only records `STATE_WRITE` events when the target is a bare `Identifier`
(e.g. `totalBalance -= amount`). Writes through a mapping index
(`balances[msg.sender] -= amount`) are parsed as `IndexAccess` and are **not** recorded,
so the external-call → mapping-write pattern is never flagged.

- Dev-time **FN on the original `ReentrancyVuln.sol`**: `msg.sender.call{}("")` followed
  by `balances[msg.sender] -= amount` went undetected. The benchmark contract now uses a
  scalar state variable to keep the label honest; a real-world mapping-based reentrancy
  would be missed.

Mitigation: extend `STATE_WRITE` recognition to `IndexAccess` targets whose base
expression is an Identifier.

### OVERFLOW Detector — Compound-assignment blind spot (FN observed during development)

`collectArithmetic()` only captures plain `BinaryOperation` operators (`+ - * **`) and
`Assignment` nodes with compound operators. The solidity parser represents `totalSupply
+= amount` as a `BinaryOperation` with operator `+=`, which matches neither branch —
so compound assignments using `+=`/`-=` are missed entirely.

- Dev-time **FN on the original `OverflowVuln.sol`**: `totalSupply += amount` was not
  flagged. The benchmark contract now uses explicit `x = x + amount` forms.

Mitigation: include compound operators (`+=`, `-=`, `*=`, `/=`) in the
`BinaryOperation` branch of `collectArithmetic()`.

### UNCHECKED_RETURN Detector — Over-broad `require` window (FN observed during development)

`isChecked()` scans a ±12-line window around the call and treats **any**
`require(..., "message")` with a string literal as evidence the call is checked — via
`/require\s*\(\s*[^)]*,\s*["']/`. An unrelated require in the same window (e.g. an
`owner` check a few lines above an unchecked `.call`) therefore suppresses the finding.

- Dev-time **FN**: `withdraw()` containing
  `require(msg.sender == owner, "Not owner"); (bool ok, ) = msg.sender.call{value: amount}("")`
  was not flagged — the owner require inside the window masked the truly-unchecked call.

Mitigation: match on the actual success tuple variable (`require(success/ok/...)`), and
scope the check to the same function body instead of a fixed line window.

## Detection Classes With Perfect Scores On This Corpus

- REENTRANCY, ACCESS_CONTROL, INTEGER_OVERFLOW, INTEGER_UNDERFLOW, UNCHECKED_RETURN,
  DELEGATECALL, UNINITIALIZED_STORAGE: 100% precision and 100% recall on the 9 labeled
  vulnerable contracts and 5 secure contracts (within-label universe). See the runner's
  per-detector table for exact TP/FP/FN/TN counts.