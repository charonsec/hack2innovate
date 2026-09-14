// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/**
 * @title SecureERC20
 * @notice A hardened ERC-20 with no owner-token balance, safe mint/withdraw
 *         patterns and full EIP-2612 permit support.
 */
contract SecureERC20 is ERC20, ERC20Burnable, Ownable, ERC20Permit {
    constructor(
        string memory name_,
        string memory symbol_
    )
        ERC20(name_, symbol_)
        Ownable(msg.sender)
        ERC20Permit(name_)
    {}

    /**
     * @notice Mints new tokens. Only the contract owner may call.
     */
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /**
     * @notice Owner can recover tokens sent directly to this contract.
     */
    function recoverTokens(
        address token,
        address to,
        uint256 amount
    ) external onlyOwner {
        require(token != address(this), "Cannot recover own tokens");
        bool ok;
        if (token == address(0)) {
            (ok, ) = payable(to).call{ value: amount }("");
        } else {
            ok = IERC20(token).transfer(to, amount);
        }
        require(ok, "Recovery failed");
    }
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}