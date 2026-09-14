// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SecureVault
 * @notice SECURE CONTRACT — demonstrates correct patterns:
 *         - Checks-Effects-Interactions (CEI) ordering
 *         - ReentrancyGuard on state-changing external functions
 *         - Checked arithmetic (built into Solidity ^0.8)
 *         - Ownable access control on admin functions
 *
 *         Running the auditor on this contract should produce NO reentrancy
 *         or overflow findings, demonstrating false-positive suppression.
 */
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() Ownable(msg.sender) {}

    function deposit() external payable nonReentrant {
        require(msg.value > 0, "Zero deposit");
        // EFFECTS before INTERACTIONS
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "Zero amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // EFFECTS before INTERACTIONS (CEI pattern)
        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        // INTERACTIONS last
        (bool success, ) = msg.sender.call{ value: amount }("");
        require(success, "Transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    function getTotalDeposits() external view returns (uint256) {
        return totalDeposits;
    }

    // Only owner can pause in emergency
    function emergencyWithdraw(address to) external onlyOwner nonReentrant {
        uint256 bal = address(this).balance;
        require(bal > 0, "No ETH");
        (bool success, ) = payable(to).call{ value: bal }("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}
