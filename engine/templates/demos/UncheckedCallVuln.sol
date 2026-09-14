// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedCallVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function execute(address target, bytes memory data) external {
        target.call(data);
    }

    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
    }
}