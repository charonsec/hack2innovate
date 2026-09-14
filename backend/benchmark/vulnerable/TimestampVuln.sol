// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TimestampVuln {
    address public lastWinner;
    uint256 public prize;

    function enterLottery() external payable {
        require(msg.value >= prize, "Insufficient prize");
        if (block.timestamp % 10 == 0) {
            lastWinner = msg.sender;
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    function isWinner() public view returns (bool) {
        return block.timestamp % 7 == 0;
    }
}
