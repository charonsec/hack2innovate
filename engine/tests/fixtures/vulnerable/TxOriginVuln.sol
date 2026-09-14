// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    function withdraw() external {
        require(tx.origin == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}
