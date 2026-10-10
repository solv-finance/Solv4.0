// SPDX-License-Identifier: MIT

pragma solidity 0.8.36;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "./interfaces/IBTCTxRegistry.sol";

/**
 * @title BTCTxRegistry
 *
 * @dev The one place a bitcoin deposit is recorded as spent. Every channel that turns a BTC deposit into
 * tokens on this chain consumes its `btcTxHash` here, so that "has this deposit already been consumed?"
 * has a single answer regardless of which channel is asking. The registry answers that question and no
 * other: it does not verify that a mint accompanied the consumption (SOLV-7).
 *
 * WHY THIS IS NOT A MAPPING INSIDE EACH CHANNEL. The baseline minter kept its own `txReceivers`, which is
 * sufficient for exactly as long as there is one minting contract and it lives forever. Two things break
 * that assumption, and neither is hypothetical:
 *
 *   1. More than one channel at a time. The rollout runs a small, automatically-signed channel alongside a
 *      large, manually-signed one. Both accept deposits into the same bitcoin reserve, so with
 *      per-contract storage the same deposit could be minted once through each.
 *   2. Redeployment. These contracts are not upgradeable, so changing anything in a channel means
 *      deploying a new one — which, with per-contract storage, starts life believing that no deposit has
 *      ever been minted, and will happily re-mint every historical one it is asked to.
 *
 * In both cases the only thing standing between a duplicate deposit and a duplicate mint would be the
 * off-chain verifier declining to sign twice. That is a real control and it stays in place, but it should
 * not be the only one.
 *
 * The registry is deliberately the smallest thing that can hold that invariant: one mapping, no external
 * calls, no token balance, no pause, not upgradeable. It is meant to outlive every contract that talks to
 * it, so the ways it could need replacing are kept to a minimum.
 *
 * IT STARTS EMPTY, AND THERE IS NO FUNCTION THAT IMPORTS, MODIFIES OR DELETES A RECORD. {consume} is the
 * only writer, one hash at a time.
 *
 * What the owner controls is who may call it, and that is the registry's real trust boundary rather than
 * bookkeeping around one: {setChannel} accepts any non-zero address, including the owner's own, and an
 * authorised address can consume any unused hash. The registry does not check that its caller is a
 * channel contract, and it does not check that a consumption accompanies a mint — so an incorrectly
 * authorised address can mark arbitrary hashes spent and make the corresponding deposits permanently
 * unmintable. The owner has no DIRECT write path; it decides who does. External audit, SOLV-7. That is a deliberate omission rather than a gap, and it is correct because this
 * registry is deployed before any bitcoin deposit has been minted on this chain: the previously deployed
 * `SolvBTCMainnetMinter` was never put into production and processed no deposits. Its EIP-712 domain name
 * differs from this system's as well, so even a signature it would have accepted is not replayable here —
 * re-minting anything from that era would require a fresh verifier signature, which is a question about
 * the off-chain verifier and not about this ledger.
 *
 * An import function would have been a power to mark arbitrary deposits spent, which is a permanent DoS
 * lever over specific user funds, in exchange for covering a history that does not exist. If a future
 * deployment ever does have records to carry over, the answer is not to add one here — it is to keep
 * using this registry, which is the entire reason it is a separate contract.
 *
 * WHAT IT DOES NOT DECIDE. Whether a mint is legitimate is settled before the call gets here — the calling
 * channel has already checked the verifier signature, the OP_RETURN binding, its minter caps and its rate
 * limit. The registry answers one question: has this bitcoin transaction been spent before.
 *
 * WHAT SHARING COSTS. Authorised channels share a namespace, so a fully compromised channel — one whose
 * minter key AND verifier are both in an attacker's hands — can burn hashes belonging to deposits routed
 * to a different channel, by minting a token amount against them. It cannot steal those deposits: the
 * amount it can mint is still bounded by its own rate limit and caps. The result is denial of service on
 * specific deposits, not loss, and the deposits themselves remain in the reserve. That is the right side
 * of the trade — an attacker who holds both keys of a channel can already mint up to its window limit, and
 * without a shared registry the same attacker could instead re-mint every deposit the system has ever
 * processed.
 *
 * @custom:security-contact dev@solv.finance
 */
contract BTCTxRegistry is IBTCTxRegistry, Ownable2Step {
    /**
     * @dev What a consumed btc tx hash resolves to: the receiver an authorised channel recorded for it,
     * and which channel. A non-zero receiver means the hash is spent and can never be consumed again.
     * It does not by itself prove tokens were minted: the registry records what an authorised caller
     * tells it and verifies nothing about a mint (SOLV-7). Through the real channels the two coincide,
     * because a channel consumes and mints in one transaction.
     *
     * The channel used to live only in {Consumed}. That made one getter quietly misleading: the registry
     * is shared, so `txReceivers()` called on the SolvBTC channel returns a receiver recorded by the BTC+
     * channel, with nothing in the return value to say so. An on-chain caller had no way to tell which
     * channel consumed a hash, and an off-chain one had to reconstruct it from logs. External audit, S1.
     */
    struct Consumption {
        address receiver;
        address channel;
    }

    mapping(bytes32 btcTxHash => Consumption consumption) internal _consumptions;

    /// @dev Kept in its original shape: this is what the channels forward and what integrators read.
    function txReceivers(bytes32 btcTxHash_) external view override returns (address) {
        return _consumptions[btcTxHash_].receiver;
    }

    /// @dev The whole record. Both zero for a hash that has never been consumed.
    function consumptions(bytes32 btcTxHash_) external view returns (address receiver, address channel) {
        Consumption storage c = _consumptions[btcTxHash_];
        return (c.receiver, c.channel);
    }

    /**
     * @dev The addresses allowed to call {consume}. Set by the owner, which is the timelock, so adding
     * one is a 72h decision — the same weight as authorising it at the gateway.
     *
     * "Channel" is the intended use, not a check: {setChannel} takes any non-zero address and this
     * contract verifies nothing about it. An authorised address can consume any unused hash, which makes
     * the corresponding deposit permanently unmintable — so the authorisation is the trust boundary
     * here, and it is worth reading that way rather than as bookkeeping. External audit, S2.8.
     */
    mapping(address channel => bool authorised) public authorisedChannels;

    error ChannelNotAuthorised(address caller);
    error InvalidChannel(address channel);
    error ChannelUnchanged(address channel);
    error InvalidBtcTxHash(bytes32 btcTxHash);
    error InvalidReceiver(address receiver);
    error BtcTxHashConsumed(bytes32 btcTxHash, address receiver);

    event Consumed(bytes32 indexed btcTxHash, address indexed receiver, address indexed channel);
    event SetChannel(address indexed channel, bool authorised);

    constructor(address owner_) Ownable(owner_) {}

    /**
     * @dev Records `btcTxHash_` as spent by `receiver_`.
     *
     * Reverts rather than returning false on a hash that is already recorded. A channel that has done its
     * own check will never see it; the point of it reverting is that a channel which forgot to check, or
     * checked against the wrong registry, cannot mint anyway. This is the authoritative guard, and the
     * channels' own early check is a convenience that fails faster and with a better error.
     *
     * Requirements:
     * - The caller must be an authorised channel.
     * - `btcTxHash_` must be non-zero and not already recorded.
     * - `receiver_` must be non-zero — the zero address is what "not recorded" means, so storing it would
     *   silently record nothing.
     *
     * @param btcTxHash_ The bitcoin transaction being spent.
     * @param receiver_ The address receiving tokens for it, as reported by the caller; not verified here.
     */
    function consume(bytes32 btcTxHash_, address receiver_) external override {
        if (!authorisedChannels[msg.sender]) {
            revert ChannelNotAuthorised(msg.sender);
        }
        if (btcTxHash_ == bytes32(0)) {
            revert InvalidBtcTxHash(btcTxHash_);
        }
        if (receiver_ == address(0)) {
            revert InvalidReceiver(receiver_);
        }
        address recorded = _consumptions[btcTxHash_].receiver;
        if (recorded != address(0)) {
            revert BtcTxHashConsumed(btcTxHash_, recorded);
        }

        _consumptions[btcTxHash_] = Consumption({receiver: receiver_, channel: msg.sender});
        emit Consumed(btcTxHash_, receiver_, msg.sender);
    }

    /**
     * @dev Authorises — or revokes — a channel's right to call {consume}.
     *
     * Revoking is the containment action for a channel believed to be compromised, and it composes with
     * the gateway's `setChannelRateLimit(channel, 0, 0, 0)`: either one alone stops that channel minting.
     * Both are timelocked, so neither is the emergency response — {PauseController} is. What revoking here
     * additionally does is stop a compromised channel from burning other channels' deposit hashes.
     *
     * @param channel_ The channel being authorised or revoked.
     * @param authorised_ True to authorise, false to revoke.
     */
    function setChannel(address channel_, bool authorised_) external onlyOwner {
        if (channel_ == address(0)) {
            revert InvalidChannel(channel_);
        }
        if (authorisedChannels[channel_] == authorised_) {
            revert ChannelUnchanged(channel_);
        }
        authorisedChannels[channel_] = authorised_;
        emit SetChannel(channel_, authorised_);
    }
}
