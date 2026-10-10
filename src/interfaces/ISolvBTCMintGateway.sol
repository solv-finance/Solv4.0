// SPDX-License-Identifier: MIT

pragma solidity 0.8.36;

/**
 * @title ISolvBTCMintGateway
 *
 * @dev The surface a channel needs from the gateway. `SOLVBTC` is part of it because channels read the
 * token address back from the gateway instead of taking it as a constructor argument — two addresses that
 * are never passed separately can never disagree.
 *
 * @custom:security-contact dev@solv.finance
 */
interface ISolvBTCMintGateway {
    function SOLVBTC() external view returns (address);

    /**
     * @dev Mints SolvBTC to `to_` on behalf of the calling channel, after charging the call against that
     * channel's rate limit. Reverts when the caller is not a configured channel.
     */
    function mint(address to_, uint256 amount_) external;

    /**
     * @dev The amount `channel_` may still mint at the current block. Zero for unconfigured channels.
     */
    function remainingMintAmount(address channel_) external view returns (uint256);
}
