// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableReentrancy
 * @notice VULNERABILITY: Classic reentrancy — external call BEFORE state update.
 *         SWC-107: The withdraw() function sends ETH via call() before
 *         decrementing the caller's balance, enabling recursive re-entry.
 */
contract VulnerableReentrancy {
    mapping(address => uint256) public balances;

    // VULNERABILITY: no reentrancy guard
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: external call before state update (SWC-107)
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call happens BEFORE balance update
        (bool success, ) = msg.sender.call{ value: amount }("");
        require(success, "Transfer failed");

        // State update after external call — reentrant attacker drains funds
        balances[msg.sender] -= amount;
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    receive() external payable {}
}
