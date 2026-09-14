// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract ReentrancyVuln {
    uint256 public totalBalance;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        totalBalance += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(totalBalance >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        totalBalance -= amount;
    }

    receive() external payable {
        totalBalance += msg.value;
    }
}
