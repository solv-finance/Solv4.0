// SPDX-License-Identifier: MIT

pragma solidity 0.8.36;

/**
 * @title IBTCPlusDepositor
 *
 * @dev The surface a channel needs from the depositor. As with the gateway, `BTCPLUS` and `SOLVBTC` are
 * exposed so that channels can read them back rather than being handed a second, independently supplied
 * copy of the same addresses.
 *
 * @custom:security-contact dev@solv.finance
 */
interface IBTCPlusDepositor {
    function BTCPLUS() external view returns (address);

    function SOLVBTC() external view returns (address);

    /**
     * @dev Pulls `solvBTCAmount_` of SolvBTC from the caller into the vault and mints the equivalent
     * BTCPlus shares, priced at the realtime NAV, directly to `receiver_`.
     *
     * @param solvBTCAmount_ The amount of SolvBTC deposited.
     * @param receiver_ The address receiving the minted BTCPlus.
     * @param nav_ The NAV quoted by the caller's verifier. Bounds quote-to-execution drift only; it takes
     *        no part in the conversion.
     * @return btcPlusAmount The number of BTCPlus shares minted.
     * @return executionNav The realtime NAV the share conversion actually used, which is not the quoted
     *         `nav_` -- that one only bounds how far the two may differ. Returned so a caller can record
     *         the price the mint happened at rather than the price it was quoted at.
     */
    function deposit(uint256 solvBTCAmount_, address receiver_, uint256 nav_)
        external
        returns (uint256 btcPlusAmount, uint256 executionNav);

    /**
     * @dev The amount of SolvBTC `channel_` may still deposit at the current block. Zero for unconfigured
     * channels.
     */
    function remainingDepositAmount(address channel_) external view returns (uint256);
}
