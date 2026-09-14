// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract OverflowVuln {
    uint256 public totalSupply;
    uint256 public reserve;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function mint(uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        totalSupply = totalSupply + amount;
        reserve = reserve + amount;
    }

    function burn(uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        require(reserve >= amount, "Insufficient");
        reserve = reserve - amount;
        totalSupply = totalSupply - amount;
    }
}