// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableAMM
 * @notice VULNERABILITY: Constant-product AMM with manipulable price oracle
 *         (getAmountOut reads reserves directly) and no slippage protection.
 *         Attacker can sandwich every swap by manipulating reserves.
 *         SWC-113: Oracle manipulation, SWC-114: Front-running (no deadline).
 */
contract VulnerableAMM {
    address public tokenA;
    address public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public constant FEE = 3; // 0.3%

    constructor(address _tokenA, address _tokenB) {
        tokenA = _tokenA;
        tokenB = _tokenB;
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external {
        reserveA += amountA;
        reserveB += amountB;
    }

    // VULNERABILITY: getAmountOut uses raw reserves — manipulable via flash loans (SWC-113)
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        public pure returns (uint256)
    {
        uint256 amountInWithFee = amountIn * (1000 - FEE);
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        return numerator / denominator;
    }

    // VULNERABILITY: no deadline, no minimum output — sandwich attack (SWC-114)
    function swap(uint256 amountIn, address tokenIn) external {
        require(amountIn > 0, "Zero input");

        uint256 amountOut;
        if (tokenIn == tokenA) {
            amountOut = getAmountOut(amountIn, reserveA, reserveB);
            reserveA += amountIn;
            reserveB -= amountOut;
        } else {
            amountOut = getAmountOut(amountIn, reserveB, reserveA);
            reserveB += amountIn;
            reserveA -= amountOut;
        }

        // VULNERABILITY: no slippage check — attacker front-runs and back-runs
        // VULNERABILITY: no deadline parameter
        require(amountOut > 0, "Insufficient output");

        // Simplified: no actual token transfers for demo clarity
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserveA, reserveB);
    }
}
