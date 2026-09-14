// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract SecureOracle {
    AggregatorV3Interface public priceFeed;
    address public owner;

    constructor(address _priceFeed) {
        owner = msg.sender;
        priceFeed = AggregatorV3Interface(_priceFeed);
    }

    function getPrice() public view returns (uint256) {
        (, int256 answer, uint256 updatedAt, , ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 1 hours, "Stale price feed");
        require(answer > 0, "Invalid price");
        return uint256(answer);
    }

    function borrow(uint256 collateralAmount) external {
        uint256 price = getPrice();
        uint256 borrowAmount = collateralAmount * price / 1e18;
        require(borrowAmount <= address(this).balance, "Insufficient liquidity");
        payable(msg.sender).transfer(borrowAmount);
    }
}
