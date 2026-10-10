// SPDX-License-Identifier: MIT

pragma solidity 0.8.36;

/**
 * @title ISolvBTC
 * @custom:security-contact dev@solv.finance
 */
interface ISolvBTC {
    function mint(address to, uint256 amount) external;
}
