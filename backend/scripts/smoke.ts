import { runAudit } from '../src/engine/analyzer';

const source = `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableDeFiPool {
    mapping(address => uint256) public balances;
    address public owner;
    address public priceOracle;
    uint256 public totalLiquidity;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
        totalLiquidity -= amount;
    }

    function setOracle(address _oracle) external {
        priceOracle = _oracle;
    }

    function getTokenPrice() public view returns (uint256) {
        return IERC20(priceOracle).balanceOf(address(this));
    }

    function addLiquidity(uint256 amount) external payable {
        uint256 newTotal = totalLiquidity + amount;
        balances[msg.sender] += amount;
        totalLiquidity = newTotal;
    }

    function isLuckyDepositor() public view returns (bool) {
        return block.timestamp % 15 == 0;
    }

    function emergencyTransfer(address token, address to, uint256 amount)
        external
    {
        require(msg.sender == owner, "Not owner");
        IERC20(token).transfer(to, amount);
    }

    function flashLoan(uint256 amount, address target) external {
        uint256 balanceBefore = address(this).balance;
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

async function main(): Promise<void> {
  const events: string[] = [];
  const report = await runAudit({
    contractName: 'VulnerableDeFiPool',
    sourceCode: source,
    onProgress: (stage, progress, message) => {
      events.push(`${stage} ${progress}% ${message}`);
    },
  });

  console.log('=== PROGRESS ===');
  events.forEach((e) => console.log('  ', e));
  console.log('=== SUMMARY ===', JSON.stringify(report.summary));
  console.log('=== RISK ===', report.overallRiskScore, report.overallRiskLabel);
  console.log('=== AUDIT SCORE ===', report.auditScore);
  console.log('=== CFG NODES ===', report.cfg.length);
  console.log('=== GAS OPTS ===', report.gasOptimizations.length);
  console.log('=== FINDINGS ===');
  for (const v of report.vulnerabilities.slice(0, 25)) {
    console.log(
      `  [${v.severity}] ${v.swcId} ${v.type} L${v.lineStart}-${v.lineEnd} ${v.title}  cvss=${v.cvssScore}`
    );
  }
  console.log('=== TEMPLATE LENGTH ===', report.secureTemplate?.length ?? 0);
}

main().catch((e) => {
  console.error('FAILED:', e);
  process.exit(1);
});