// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Simple Bank
/// @notice This contract allows deposits and withdrawals securely
contract SimpleBank {
    mapping(address => uint256) private balances;
    address public owner;

    /// @notice Sets the deployer as the owner
    constructor() {
        owner = msg.sender;
    }

    /// @notice Deposit ETH into your account
    function deposit() external payable {
        require(msg.value > 0, "Must deposit more than 0");
        balances[msg.sender] += msg.value;
    }

    /// @notice Withdraw your ETH safely
    function withdraw(uint256 amount) external {
        require(amount <= balances[msg.sender], "Insufficient balance");

        // ✅ Checks-Effects-Interactions pattern
        balances[msg.sender] -= amount;

        // ✅ Using call with reentrancy safety
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");
    }

    /// @notice Get your balance
    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }

    /// @notice Owner can destroy the contract
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        selfdestruct(payable(owner));
    }
}
