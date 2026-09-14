// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OracleVuln {
    address public owner;
    IERC20 public token;
    mapping(address => uint256) public collateralValue;

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    function updateCollateralValue(uint256 userBalance) external {
        uint256 poolBalance = token.balanceOf(address(this));
        uint256 price = poolBalance;
        collateralValue[msg.sender] = userBalance * price / 1e18;
    }
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}