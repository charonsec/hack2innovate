// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract SecureArithmetic {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        balances[to] += amount;
        totalSupply += amount;
    }

    function burn(address from, uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        require(balances[from] >= amount, "Insufficient");
        balances[from] -= amount;
        totalSupply -= amount;
    }
}
