// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureCall {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function execute(address target, bytes memory data) external {
        require(msg.sender == owner, "Not owner");
        (bool success, ) = target.call(data);
        require(success, "Call failed");
    }
}
