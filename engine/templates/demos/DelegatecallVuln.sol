// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DelegatecallVuln {
    address public owner;
    uint256 public balance;

    constructor() {
        owner = msg.sender;
    }

    function execute(address target, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}
