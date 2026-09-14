// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableOracle
 * @notice VULNERABILITY: Uses Uniswap spot price (balanceOf) as a price oracle
 *         without TWAP or time-weighted checks. An attacker can manipulate
 *         the spot price within a single transaction via flash loans.
 *         SWC-113: Oracle manipulation.
 */
contract VulnerableOracle {
    address public owner;
    address public immutable pool; // Uniswap-style pool
    uint256 public constant COLLATERAL_FACTOR = 150; // 150% collateral

    constructor(address _pool) {
        owner = msg.sender;
        pool = _pool;
    }

    // VULNERABILITY: spot price from balanceOf — trivially manipulable (SWC-113)
    function getPrice() public view returns (uint256) {
        uint256 reserveA = IERC20(pool).balanceOf(address(this));
        if (reserveA == 0) return 0;
        // Uses raw reserves as price — no TWAP, no oracle freshness check
        return reserveA;
    }

    function getCollateralValue(uint256 collateral) external view returns (uint256) {
        uint256 price = getPrice();
        // VULNERABILITY: no staleness check, no deviation threshold
        return (collateral * price) / 1e18;
    }

    function liquidatable(address user, uint256 debt) external view returns (bool) {
        uint256 colVal = getCollateralValue(debt);
        return colVal < (debt * COLLATERAL_FACTOR) / 100;
    }

    receive() external payable {}
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}
