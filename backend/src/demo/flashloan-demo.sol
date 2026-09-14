// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableFlashLoan
 * @notice VULNERABILITY: Flash loan with spot-price dependency and no callback guard.
 *         The flashLoan function uses a manipulable price oracle and does not
 *         verify the caller's intent or enforce repayment validation.
 *         Demonstrates an exploit chain: flash loan → price manipulation → unfair liquidation.
 *         SWC-113: Oracle manipulation, Flash Loan vulnerability.
 */
contract VulnerableFlashLoan {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;
    address public priceOracle; // points to VulnerableOracle-like contract

    constructor(address _oracle) {
        owner = msg.sender;
        priceOracle = _oracle;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    // VULNERABILITY: flash loan uses manipulable spot price (SWC-113)
    function flashLoan(uint256 amount) external {
        require(amount <= totalDeposits, "Exceeds pool");

        // VULNERABILITY: no reentrancy guard, no callback verification
        (bool sent, ) = msg.sender.call{ value: amount }("");
        require(sent, "Flash transfer failed");

        // VULNERABILITY: price check uses the same manipulable oracle
        uint256 price = IPriceOracle(priceOracle).getPrice();
        uint256 collateralValue = (deposits[msg.sender] * price) / 1e18;

        // Attacker can manipulate price before this check executes
        require(collateralValue >= amount, "Insufficient collateral");

        // Repayment expected in same transaction — but no enforcement
        // A malicious callback could manipulate price then skip repayment
    }

    function setOracle(address _oracle) external {
        // VULNERABILITY: no access control (SWC-105)
        priceOracle = _oracle;
    }

    receive() external payable {}
}

interface IPriceOracle {
    function getPrice() external view returns (uint256);
}
