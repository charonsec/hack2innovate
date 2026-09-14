// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UninitStorageVuln {
    struct Config {
        uint256 fee;
        address admin;
    }

    mapping(address => Config) public configs;

    function updateConfig(address user, uint256 newFee) external {
        Config storage conf;
        conf.fee = newFee;
        conf.admin = msg.sender;
        configs[user] = conf;
    }
}
