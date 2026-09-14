// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlVuln {
    address public owner;
    address public priceOracle;

    constructor() {
        owner = msg.sender;
    }

    function setOracle(address _oracle) external {
        priceOracle = _oracle;
    }

    function withdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}
