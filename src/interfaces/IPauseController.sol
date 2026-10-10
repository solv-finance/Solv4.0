// SPDX-License-Identifier: MIT

pragma solidity 0.8.36;

/**
 * @title IPauseController
 * @custom:security-contact dev@solv.finance
 */
interface IPauseController {
    function mintPaused() external view returns (bool);
    function burnPaused() external view returns (bool);
}
