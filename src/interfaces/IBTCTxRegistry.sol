// SPDX-License-Identifier: MIT

pragma solidity 0.8.36;

/**
 * @title IBTCTxRegistry
 *
 * @dev The surface a channel needs from the replay registry: read whether a bitcoin transaction has
 * already been consumed, and consume one. "Consumed" is what the registry knows; that a mint accompanied
 * it is true of the real channels and not something the registry checks (SOLV-7).
 *
 * @custom:security-contact dev@solv.finance
 */
interface IBTCTxRegistry {
    /**
     * @dev The receiver an authorised channel recorded for `btcTxHash_`, or the zero address if the
     * hash has never been consumed. Through the real channels that is who received tokens for it; the
     * registry itself does not verify a mint took place (SOLV-7). Named to match the mapping the baseline minter kept
     * in its own storage, so off-chain consumers read the same call on the same signature.
     */
    function txReceivers(bytes32 btcTxHash_) external view returns (address receiver);

    /**
     * @dev Records `btcTxHash_` as spent by `receiver_`. Callable only by an authorised channel, and
     * only once per hash — the second call for the same hash reverts, whichever channel makes it.
     */
    function consume(bytes32 btcTxHash_, address receiver_) external;
}
