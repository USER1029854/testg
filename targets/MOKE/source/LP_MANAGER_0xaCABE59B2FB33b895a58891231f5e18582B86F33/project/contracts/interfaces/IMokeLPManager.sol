// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IMokeLPManager {
    function addLiquidityForUser(address user, uint256 mokeAmount, uint256 bnbAmount) external payable returns (uint256 lpAmount);
    function removeLiquidity(uint256 lpAmount, uint256 minBnbOut) external;
    function addLPWithReleasedMoke(uint256 mokeAmount) external payable;
}
