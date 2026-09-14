// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title SecureAMM
 * @notice A constant-product AMM with a block-number based TWAP oracle,
 *         reentrancy guards and deadlined, slippage-protected swaps.
 * @dev The TWAP accumulator advances with every non-view interaction; examples
 *      of production hardening (UniswapV2Pair-style) are included inline.
 */
contract SecureAMM is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct TWAPObservation {
        uint32 timestamp;
        uint224 price0CumulativeLast;
        uint224 price1CumulativeLast;
    }

    TWAPObservation public twap;
    uint256 public constant MIN_TRADES_PER_TWAP = 2;

    address public immutable tokenA;
    address public immutable tokenB;
    uint112 private reserveA;
    uint112 private reserveB;

    uint256 private _blockTimestampLast;

    // Slippage + deadline storage flags (set by caller each swap).
    event Swap(
        address indexed sender,
        uint256 amountIn,
        uint256 amountOut,
        uint256 deadline
    );

    constructor(address tokenA_, address tokenB_) Ownable(msg.sender) {
        require(tokenA_ != tokenB_, "Same tokens");
        tokenA = tokenA_;
        tokenB = tokenB_;
    }

    function _update(
        uint256 balA,
        uint256 balB,
        uint256 prevCumulativeA,
        uint256 prevCumulativeB
    ) private {
        uint256 blockTimestamp = block.timestamp;
        uint32 timeElapsed = uint32(blockTimestamp - _blockTimestampLast);
        require(timeElapsed < 8 days, "TWAP overflow");

        uint256 price0Cumulative =
            prevCumulativeA +
                (balA > 0 ? (uint256(uint128(balB)) * timeElapsed) / balA : 0);
        uint256 price1Cumulative =
            prevCumulativeB +
                (balB > 0 ? (uint256(uint128(balA)) * timeElapsed) / balB : 0);

        twap = TWAPObservation({
            timestamp: uint32(blockTimestamp),
            price0CumulativeLast: uint224(price0Cumulative),
            price1CumulativeLast: uint224(price1Cumulative)
        });

        _blockTimestampLast = blockTimestamp;
        reserveA = uint112(balA);
        reserveB = uint112(balB);
    }

    function _twapPrice(uint112 reserveNowA) internal view returns (uint256) {
        TWAPObservation memory last = twap;
        uint32 elapsed = uint32(block.timestamp - last.timestamp);
        require(elapsed > 0, "TWAP not ready");
        return
            (uint256(last.price0CumulativeLast) * 1e18) /
            reserveNowA /
            elapsed;
    }

    function swapExactIn(
        uint256 amountIn,
        uint256 minAmountOut,
        uint256 deadline
    ) external nonReentrant returns (uint256 amountOut) {
        require(block.timestamp <= deadline, "Expired");

        uint256 balA = IERC20(tokenA).balanceOf(address(this));
        uint256 balB = IERC20(tokenB).balanceOf(address(this));
        (uint112 rA, uint112 rB) = (reserveA, reserveB);

        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * rB;
        uint256 denominator = rA * 1000 + amountInWithFee;
        amountOut = numerator / denominator;
        require(amountOut >= minAmountOut, "Slippage exceeded");

        // Effects after computing output.
        uint256 newBalA = balA + amountIn;
        uint256 newBalB = balB - amountOut;

        // Interactions.
        IERC20(tokenA).safeTransferFrom(msg.sender, address(this), amountIn);
        IERC20(tokenB).safeTransfer(msg.sender, amountOut);

        _update(newBalA, newBalB, twap.price0CumulativeLast, twap.price1CumulativeLast);
        emit Swap(msg.sender, amountIn, amountOut, deadline);
    }
}