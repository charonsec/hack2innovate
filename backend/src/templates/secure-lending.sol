// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

/**
 * @title SecureLending
 * @notice A minimal overcollateralized lending pool that follows
 *         Checks-Effects-Interactions, uses nonReentrant guards and a
 *         Chainlink-backed price oracle with staleness checks.
 */
contract SecureLending is Ownable, ReentrancyGuard {
    struct Position {
        uint256 collateral;
        uint256 debt;
    }

    AggregatorV3Interface public priceFeed;
    IERC20 public immutable collateralToken;
    IERC20 public immutable debtToken;

    uint256 public constant LIQUIDATION_THRESHOLD_BPS = 300; // 3%
    uint256 public constant MAX_LTV_BPS = 7500; // 75%

    mapping(address => Position) public positions;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event Borrow(address indexed user, uint256 amount);
    event Repay(address indexed user, uint256 amount);

    constructor(
        address feed,
        address collateralToken_,
        address debtToken_
    ) Ownable(msg.sender) {
        priceFeed = AggregatorV3Interface(feed);
        collateralToken = IERC20(collateralToken_);
        debtToken = IERC20(debtToken_);
    }

    function _getCollateralPrice() internal view returns (uint256) {
        (, int256 answer, uint256 updatedAt, , ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 3 hours, "Stale price");
        require(answer > 0, "Invalid price");
        return uint256(answer);
    }

    function deposit(uint256 amount) external nonReentrant {
        require(
            collateralToken.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );
        positions[msg.sender].collateral += amount;
        emit Deposit(msg.sender, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        Position storage pos = positions[msg.sender];
        require(pos.collateral >= amount, "Insufficient collateral");

        // Effects first.
        pos.collateral -= amount;

        // Interactions last.
        require(
            collateralToken.transfer(msg.sender, amount),
            "Transfer failed"
        );
        emit Withdraw(msg.sender, amount);
    }

    function borrow(uint256 amount) external nonReentrant {
        Position storage pos = positions[msg.sender];
        uint256 price = _getCollateralPrice();
        uint256 maxBorrow = (pos.collateral * price * MAX_LTV_BPS) / (1e8 * 1e4);
        require(pos.debt + amount <= maxBorrow, "Borrow exceeds LTV");

        // Effects.
        pos.debt += amount;

        // Interactions.
        require(debtToken.transfer(msg.sender, amount), "Transfer failed");
        emit Borrow(msg.sender, amount);
    }

    function repay(uint256 amount) external nonReentrant {
        require(
            debtToken.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );
        positions[msg.sender].debt -= amount;
        emit Repay(msg.sender, amount);
    }
}