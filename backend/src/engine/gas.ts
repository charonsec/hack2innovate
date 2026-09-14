import { GasOptimization } from '../types/index';

/**
 * Static gas-savings heuristics that operate on raw source lines.
 * Every item carries its line, description, estimated saving and
 * before/after code so the frontend can render them inline.
 */
export function detectGasOptimizations(
  sourceCode: string,
  lines: string[],
  isViewLikeLine: (line: string) => boolean
): GasOptimization[] {
  const results: GasOptimization[] = [];
  const add = (
    line: number,
    description: string,
    estimatedSaving: string,
    code: string,
    optimizedCode: string
  ) => results.push({ line, description, estimatedSaving, code, optimizedCode });

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = i + 1;
    const trimmed = raw.trim();

    if (!trimmed || trimmed.startsWith('//')) continue;

    // 1. `<x> = <x> + n` vs `+=`
    const addSelf = trimmed.match(/^(\s*\w[\w\[\]\.]*)\s*=\s*\1\s*\+\s*(.+);$/);
    if (addSelf) {
      const varName = addSelf[1].trim();
      const rhs = addSelf[2].trim();
      add(
        line,
        'Use += instead of assignment-plus: `X = X + n` costs extra SLOAD+arithmetic.',
        '~30 gas / occurrence',
        trimmed,
        `${varName} += ${rhs};`
      );
      continue;
    }

    // 2. Loop counter declared with uint256 — uint8 saves nothing but using
    //    local cache of the length is the big win.
    const forLoop = trimmed.match(/^for\s*\(uint256\s+(\w+)\s*=\s*0;\s*(\w+)\s*<(\s*\w+\.length|array\.length)\s*;/);
    if (forLoop) {
      const arr = (forLoop[3] || '').trim();
      add(
        line,
        `Cache loop bound. Reading ${arr} on each iteration repeatedly pays ` +
          'SLOAD/MLOAD. Cache it before the loop.',
        '~150 gas / iteration (array)',
        trimmed,
        `for (uint256 ${forLoop[1]} = 0; ${forLoop[1]} < ${arr}; ${forLoop[1]}++) {`
      );
      continue;
    }

    // 3. uint256 loop counters vs uint8
    const counter = trimmed.match(/\bfor\s*\(\s*uint(8|16|32|64|128)\s+(\w+)\s*=/);
    if (counter) {
      add(
        line,
        `Loop counter ${counter[2]} is uint${counter[1]}. Declare uint256 to avoid ` +
          'masking/cleanup ops inside the loop.',
        '~12 gas / iteration',
        trimmed,
        trimmed.replace(/\buint(8|16|32|64|128)\s+(\w+)\s*=/, 'uint256 $2 =')
      );
      continue;
    }

    // 4. Repeated storage reads inside the same function — hint to cache.
    if (
      /(\.balanceOf|\.getReserves|balances\[|vault\[|token\[)/.test(trimmed) &&
      i > 0 &&
      !isViewLikeLine(trimmed)
    ) {
      const stmt = trimmed.match(/(\w+)(\.balanceOf|\[[^\]]+\])/);
      if (stmt && !/require|if\(/.test(trimmed)) {
        add(
          line,
          `Repeated storage read of ${stmt[1]}${stmt[2]}. Cache into a memory local ` +
            'once and reuse — each SLOAD is ~100 gas.',
          '~100 gas / read',
          trimmed,
          `uint256 cached = ${stmt[1]}${stmt[2]};`
        );
      }
      continue;
    }

    // 5. `require(x) && f()` patterns / boolean refinement not needed.

    // 6. Custom errors replace string reverts.
    if (/require\s*\([^)]*,;\s*["']revert/.test(trimmed) || /require\([^)]*,\s*"Error/.test(trimmed)) {
      add(
        line,
        'String revert reason costs 32+ bytes of calldata+memory. Use custom errors ' +
          '(error MyError(); revert MyError());',
        '~15k gas (deploy) + ~30 gas / revert',
        trimmed,
        '        revert MyCustomError();'
      );
      continue;
    }

    // 7. `> 0` instead of `!= 0`
    if (/\w+\s*>\s*0\s*$/.test(trimmed) && /uint/.test(trimmed) && /require/.test(trimmed)) {
      add(
        line,
        'For unsigned integers `!= 0` is cheaper than `> 0`.',
        '~6 gas',
        trimmed,
        trimmed.replace(/\b>\s*0\b/, '!= 0')
      );
      continue;
    }

    // 8. Full-precision fixed-point constants.
    const powConst = trimmed.match(/(\w+)\s*=\s*10\s*\*\*\s*18\s*;|1e18/);
    if (powConst) {
      add(
        line,
        '1e18-style exponent computed at runtime. Use the literal constant for ' +
          'compile-time eval.',
        '~30 gas / reference',
        trimmed,
        trimmed.replace(/(\w+)\s*=\s*10\s*\*\*\s*18\s*;/, '$1 = 1e18;')
      );
      continue;
    }
  }

  return results;
}