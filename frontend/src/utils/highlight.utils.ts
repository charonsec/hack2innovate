import { Severity, Vulnerability } from '@/types';
import { SEVERITY_COLORS } from './severity.utils';

export interface LineDecoration {
  lineNumber: number;
  severity: Severity;
  message: string;
}

/** Converts vulnerabilities into per-line decorations keyed for Monaco. */
export function buildLineDecorations(
  vulnerabilities: Vulnerability[]
): LineDecoration[] {
  const map = new Map<number, LineDecoration>();
  for (const v of vulnerabilities) {
    for (let line = v.lineStart; line <= Math.max(v.lineStart, v.lineEnd); line++) {
      if (line < 1) continue;
      const existing = map.get(line);
      if (!existing) {
        map.set(line, {
          lineNumber: line,
          severity: v.severity,
          message: `${v.swcId} — ${v.title}`,
        });
      }
    }
  }
  return Array.from(map.values()).sort((a, b) => a.lineNumber - b.lineNumber);
}

export function severityDecorationCss(severity: Severity): {
  backgroundColor: string;
  isWholeLine: boolean;
} {
  const colors = SEVERITY_COLORS[severity];
  return {
    backgroundColor: colors.bg,
    isWholeLine: true,
  };
}

export function severityOptionCss(severity: Severity): {
  color: string;
  options: { fontWeight: string };
} {
  const colors = SEVERITY_COLORS[severity];
  return {
    color: colors.text,
    options: { fontWeight: '600' },
  };
}

export function hoverMessage(v: Vulnerability): string {
  return `[${v.severity}] ${v.swcId} ${v.title}\n${v.description.slice(0, 280)}`;
}

export const DEFAULT_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableDeFiPool {
    mapping(address => uint256) public balances;
    address public owner;
    address public priceOracle;
    uint256 public totalLiquidity;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABILITY 1: Reentrancy - state updated after external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call BEFORE state update - REENTRANCY RISK
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;  // State updated AFTER call
        totalLiquidity -= amount;
    }

    // VULNERABILITY 2: No access control on sensitive function
    function setOracle(address _oracle) external {
        priceOracle = _oracle;  // Anyone can change the oracle!
    }

    // VULNERABILITY 3: Oracle manipulation - using spot price
    function getTokenPrice() public view returns (uint256) {
        // Using balanceOf as price - easily manipulated via flash loan
        return IERC20(priceOracle).balanceOf(address(this));
    }

    // VULNERABILITY 4: Integer overflow (no SafeMath, solidity 0.7)
    function addLiquidity(uint256 amount) external payable {
        uint256 newTotal = totalLiquidity + amount;  // Potential overflow
        balances[msg.sender] += amount;
        totalLiquidity = newTotal;
    }

    // VULNERABILITY 5: Timestamp dependence for randomness
    function isLuckyDepositor() public view returns (bool) {
        return block.timestamp % 15 == 0;  // Manipulable by miners
    }

    // VULNERABILITY 6: Unchecked return value
    function emergencyTransfer(address token, address to, uint256 amount)
        external
    {
        require(msg.sender == owner, "Not owner");
        IERC20(token).transfer(to, amount);  // Return value ignored!
    }

    // VULNERABILITY 7: Flash loan attack vector
    function flashLoan(uint256 amount, address target) external {
        uint256 balanceBefore = address(this).balance;

        // No reentrancy guard, no callback validation
        (bool success,) = target.call{value: amount}(
            abi.encodeWithSignature("executeOperation(uint256)", amount)
        );

        require(address(this).balance >= balanceBefore, "Flash loan not repaid");
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
        totalLiquidity += msg.value;
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
`;

export const SOLIDITY_KEYWORDS = [
  'pragma', 'contract', 'library', 'interface', 'using', 'for', 'function',
  'mapping', 'struct', 'enum', 'event', 'modifier', 'error', 'revert',
  'public', 'private', 'internal', 'external', 'view', 'pure', 'payable',
  'returns', 'return', 'require', 'assert', 'emit', 'memory', 'storage',
  'calldata', 'if', 'else', 'while', 'do', 'for', 'break', 'continue',
  'new', 'delete', 'this', 'msg', 'tx', 'block', 'abi', 'selfdestruct',
  'immutable', 'constant', 'tuple', 'unchecked', 'try', 'catch',
];

export const SOLIDITY_TYPES = [
  'uint', 'uint8', 'uint16', 'uint24', 'uint32', 'uint40', 'uint48', 'uint56',
  'uint64', 'uint72', 'uint80', 'uint88', 'uint96', 'uint104', 'uint112',
  'uint120', 'uint128', 'uint136', 'uint144', 'uint152', 'uint160', 'uint168',
  'uint176', 'uint184', 'uint192', 'uint200', 'uint208', 'uint216', 'uint224',
  'uint232', 'uint240', 'uint248', 'uint256',
  'int', 'int8', 'int16', 'int24', 'int32', 'int64', 'int128', 'int256',
  'address', 'bool', 'string', 'bytes', 'bytes1', 'bytes4', 'bytes8',
  'bytes32', 'var', 'fixed', 'ufixed',
];