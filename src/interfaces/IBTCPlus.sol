// SPDX-License-Identifier: MIT

pragma solidity 0.8.36;

/**
 * @title IBTCPlus
 * @custom:security-contact dev@solv.finance
 */
interface IBTCPlus {
    function decimals() external view returns (uint8);

    /**
     * @dev Converts an amount of shares into its underlying value, using the realtime NAV.
     */
    function getValueByShares(uint256 shares) external view returns (uint256);

    /// @dev The decimals the NAV is quoted in. The design assumes this equals SolvBTC's, and the
    /// deployment preflight now asserts it -- see {MainnetMintDeployment}.
    function getOracleDecimals() external view returns (uint8);

    /**
     * @dev Converts an amount of underlying value into shares, using the realtime NAV.
     *      Returns 0 when the NAV oracle reports a zero NAV.
     */
    function getSharesByValue(uint256 value) external view returns (uint256);

    function mint(address to, uint256 amount) external;
}
