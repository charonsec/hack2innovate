// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableAccessControl
 * @notice VULNERABILITY: Critical admin functions have no access control.
 *         setOracle(), setPrice(), and mint() are callable by any address.
 *         SWC-105: Missing access control on sensitive functions.
 */
contract VulnerableAccessControl {
    address public oracle;
    uint256 public price;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _oracle, uint256 _price) {
        oracle = _oracle;
        price = _price;
    }

    // VULNERABILITY: anyone can change the oracle (SWC-105)
    function setOracle(address _oracle) external {
        oracle = _oracle;
    }

    // VULNERABILITY: anyone can change the price (SWC-105)
    function setPrice(uint256 _price) external {
        price = _price;
    }

    // VULNERABILITY: anyone can mint tokens (SWC-105)
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }

    function getPrice() external view returns (uint256) {
        return price;
    }
}
