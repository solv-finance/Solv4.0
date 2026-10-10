// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import "@openzeppelin/contracts/utils/math/SafeCast.sol";

/**
 * @title ChannelRateLimiter
 *
 * @dev Per-channel rate limiting, shared by every contract that mints or takes custody on a channel's
 * behalf. Authorisation and metering are one mechanism here: `window == 0` means the channel is not
 * authorised at all, so there is no way to be authorised without a limit, or limited without being
 * authorised.
 *
 * The model is the linear decay from `BTCPlusRedeem`, reused so that operations reasons about one
 * mechanism rather than several. Allowance regenerates continuously instead of resetting on a boundary,
 * so an exhausted channel recovers smoothly rather than waiting for a cliff.
 *
 * Four details in here are load-bearing, and each one has to be right every time this logic is written
 * out — which is the reason it is written out once:
 *
 *   1. `maxSingleAmount` must be strictly below `maxWindowAmount`, or the per-transaction cap becomes
 *      unenforceable. The upstream implementation only checked this on one of its two setters and could
 *      be left in exactly that state.
 *   2. Changing the parameters must checkpoint the outstanding usage at the OLD decay rate first,
 *      otherwise time already elapsed gets measured against the new window and retroactively forgives
 *      usage a shortened window was never meant to forgive.
 *   3. The decay divisor guards against a zero window, which an unconfigured channel always has.
 *   4. Lowering the window allowance below the outstanding usage leaves the usage intact rather than
 *      truncating it. {_amountCanBeUsed} already reports zero available when the limit is under the
 *      recorded usage, so nothing underflows and nothing is forgiven.
 *   5. Outstanding usage expires in full once a whole window has passed since it was last
 *      checkpointed, however large it is relative to the current capacity. Linear decay alone
 *      recovers usage at `maxWindowAmount / window`, so usage carried into a smaller allowance would
 *      block the channel for `carried / maxWindowAmount` windows; the expiry bounds that wait to one
 *      window. This branch is in the LayerZero `RateLimiter` this model descends from and was dropped
 *      on the way through `BTCPlusRedeem`, which used a clamp instead — the clamp became SOLV-4, and
 *      removing it without restoring the expiry became SOLV-9.
 *
 * Deliberately free of any access-control dependency: this contract decides how much, never who. The
 * inheriting contract owns the authorisation around {_setChannelRateLimit}.
 *
 * "Channel" throughout this contract means the intended use rather than anything it verifies. Every
 * function here takes an address; none checks that it is a channel contract, or a contract at all. An
 * address given a non-zero window has that channel's authority regardless of what it is. External audit,
 * S2.8.
 *
 * @custom:security-contact dev@solv.finance
 */
abstract contract ChannelRateLimiter {
    /**
     * @dev Per-channel rate limit state, in two slots rather than five.
     *
     * The field order is the packing, and it is chosen around {_consume}, which reads every field and
     * writes two of them. `amountUsed` and `lastUsedAt` share a slot with `window` so that the write on
     * the minting path is one `SSTORE`; the two configured amounts share the other.
     *
     * The narrowed types are safe by construction rather than by hope, and every assignment goes through
     * a checked cast regardless:
     *
     *   - `amountUsed` and both amounts are bounded by {MAX_WINDOW_AMOUNT} = 100e18, and `uint128` holds
     *     about 3.4e38 -- eighteen orders of magnitude of headroom. {_consume} cannot leave `amountUsed` above the allowance
     *     it just checked against, and a reconfiguration carries a figure that was already bounded.
     *   - `lastUsedAt` is `block.timestamp`, and `uint48` runs to the year 8.9 million.
     *   - `window` has a floor of {MIN_WINDOW} and, from the cast, a ceiling of about 136 years. That
     *     ceiling is new, and it is the bound the narrowing requires: a window longer than a human
     *     lifetime is a typo, and it now reverts instead of being stored.
     *
     * External audit, S6.
     */
    struct RateLimit {
        uint128 amountUsed; // usage not yet decayed away; see _amountCanBeUsed
        uint48 lastUsedAt; // timestamp the usage was last checkpointed at
        uint32 window; // window duration in seconds; 0 means unauthorised
        uint128 maxSingleAmount; // max amount that can be consumed in a single transaction
        uint128 maxWindowAmount; // bucket capacity; it refills at maxWindowAmount / window per second
    }

    /**
     * @dev The hard ceiling on a SINGLE channel's window allowance, on any inheriting contract.
     *
     * Not an owner-tunable parameter and not upgradeable: no channel's window allowance can be
     * configured above 100 BTC, and a multisig cannot raise the ceiling either. Everything else about a
     * channel's limit is operational; this is structural.
     *
     * PER CHANNEL, NOT AGGREGATE — deliberately. It bounds the blast radius of any one client. There is
     * no global cap and none is intended: authorising a channel is a 72h timelocked decision, so the
     * aggregate is set by how many channels governance has approved. {ChannelRateLimiter} answers
     * "how much can this client draw", never "how much exists in total".
     *
     * On its own this constant bounds the BUCKET, not the RATE. Allowance refills at
     * `maxWindowAmount / window`, so without a floor on `window` a compliant `maxWindowAmount` still
     * permits an arbitrary issuance rate — 100 BTC per second at `window == 1`. The structural bound is
     * therefore `MAX_WINDOW_AMOUNT / MIN_WINDOW`, and it is structural only because both constants are.
     */
    uint256 public constant MAX_WINDOW_AMOUNT = 100e18;

    /**
     * @dev The floor on a channel's window, and the second half of the structural bound.
     *
     * Every amount in {RateLimit} is fail-closed in its dangerous direction: too large is rejected. The
     * window was the one parameter fail-OPEN in its dangerous direction, because the danger is it being
     * too SMALL. A window mistyped as `864` instead of `86400` is a hundredfold increase in the refill
     * rate that reads like a typo nobody would look twice at, and it passed every check this system
     * had — the contract's own, the deployment preflight, and the post-deployment read-back.
     *
     * One day, matching the shortest window any tier is intended to run with. Not owner-tunable, for the
     * same reason {MAX_WINDOW_AMOUNT} is not: a limit a compromised owner can widen is not a limit.
     *
     * External audit, SOLV-2.
     */
    uint256 public constant MIN_WINDOW = 1 days;

    mapping(address channel => RateLimit rateLimit) internal _rateLimits;

    /**
     * @dev Written out rather than generated, so that packing the struct did not change the interface.
     *
     * An automatic getter would return the narrowed types in the storage order, which is a different
     * tuple from the one every caller — the deployment scripts, the verification script, the operations
     * tooling — already destructures. The saving S6 asks for is in the storage layout; there is no
     * reason to spend an interface break on it.
     */
    function rateLimits(address channel_)
        external
        view
        returns (
            uint256 amountUsed,
            uint256 lastUsedAt,
            uint256 maxSingleAmount,
            uint256 maxWindowAmount,
            uint256 window
        )
    {
        RateLimit storage rl = _rateLimits[channel_];
        return (rl.amountUsed, rl.lastUsedAt, rl.maxSingleAmount, rl.maxWindowAmount, rl.window);
    }

    error InvalidChannel(address channel);
    error ChannelNotConfigured(address channel);
    error SingleAmountExceeded(uint256 maxSingleAmount, uint256 amount);
    error WindowAmountExceeded(uint256 availableAmount, uint256 amount);
    error SingleAmountNotBelowWindowAmount(uint256 maxSingleAmount, uint256 maxWindowAmount);
    error WindowAmountAboveHardCap(uint256 maxWindowAmount);
    error WindowBelowMinimum(uint256 window, uint256 minWindow);
    error RevokeMustClearAmounts();

    /// @dev The lifecycle transitions, distinguishable in a log from a parameter change that leaves a
    /// channel's ability to mint untouched. Each is emitted only when that ability actually changes:
    /// {ChannelAuthorised} when a channel's window goes from zero to non-zero, {ChannelRevoked} when it
    /// goes from non-zero to zero. {SetChannelRateLimit} is still emitted on every call, so anything
    /// already reading it keeps working. External audit, S4; the fix review noted that {ChannelRevoked}
    /// used to be emitted for a channel that had nothing to lose.
    event ChannelAuthorised(address indexed channel, uint256 maxSingleAmount, uint256 maxWindowAmount, uint256 window);
    event ChannelRevoked(address indexed channel);

    event SetChannelRateLimit(
        address indexed channel, uint256 maxSingleAmount, uint256 maxWindowAmount, uint256 window
    );

    /**
     * @dev Charges `amount_` against `channel_`'s allowance.
     *
     * Writes the new usage before returning, so that callers perform their external calls with the
     * allowance already spent and a callback cannot spend it twice.
     *
     * Requirements:
     * - `channel_` must be configured.
     * - `amount_` must not exceed the channel's single-transaction cap.
     * - `amount_` must fit within the channel's remaining window allowance.
     */
    function _consume(address channel_, uint256 amount_) internal {
        RateLimit storage rl = _rateLimits[channel_];
        if (rl.window == 0) {
            revert ChannelNotConfigured(channel_);
        }
        if (amount_ > rl.maxSingleAmount) {
            revert SingleAmountExceeded(rl.maxSingleAmount, amount_);
        }

        (uint256 currentAmountUsed, uint256 availableAmount) =
            _amountCanBeUsed(rl.amountUsed, rl.lastUsedAt, rl.maxWindowAmount, rl.window);
        if (availableAmount < amount_) {
            revert WindowAmountExceeded(availableAmount, amount_);
        }

        rl.amountUsed = SafeCast.toUint128(currentAmountUsed + amount_);
        rl.lastUsedAt = SafeCast.toUint48(block.timestamp);
    }

    /**
     * @dev Dispatches to the three things a caller can actually mean, chosen by the arguments AND the
     * channel's current state.
     *
     * Kept as the single entry point so the inheriting contracts' external setters and the deployment
     * tooling keep one ABI, while the transitions underneath say what they do. Combining them was how a
     * revocation came to clear a channel's usage: nobody wrote that rule, it fell out of a general
     * parameter update applying a new allowance of zero through a clamp. External audit, S4 and SOLV-4.
     *
     * The state decides which transition a call is. A non-zero window on an unauthorised channel is a
     * grant; on an authorised one it is an update. A zero window on an authorised channel is a
     * revocation. A zero window on a channel that is not authorised — never configured, or revoked
     * already — is none of the three: nothing is written and only {SetChannelRateLimit} is emitted, so
     * that {ChannelRevoked} always means a channel lost the ability to mint. The fix review of S4 noted
     * that the event used to be emitted regardless.
     *
     * Requirements:
     * - `channel_` must not be the zero address.
     * - Revoking (`window_ == 0`) must pass zero for both amounts, so that a revoked channel cannot be
     *   left holding a stale allowance behind a zero window.
     * - Otherwise: `maxSingleAmount_` strictly below `maxWindowAmount_`, `maxWindowAmount_` at most
     *   {MAX_WINDOW_AMOUNT}, and `window_` at least {MIN_WINDOW}.
     *
     * @param channel_ The channel being configured.
     * @param maxSingleAmount_ The per-transaction cap.
     * @param maxWindowAmount_ The bucket capacity, which also sets the refill rate: `maxWindowAmount_ / window_` per second.
     * @param window_ The window duration in seconds; zero revokes the channel.
     */
    function _setChannelRateLimit(address channel_, uint256 maxSingleAmount_, uint256 maxWindowAmount_, uint256 window_)
        internal
    {
        if (channel_ == address(0)) {
            revert InvalidChannel(channel_);
        }

        bool authorised = _rateLimits[channel_].window != 0;
        if (window_ == 0) {
            if (maxSingleAmount_ != 0 || maxWindowAmount_ != 0) {
                revert RevokeMustClearAmounts();
            }
            if (authorised) {
                _revokeChannel(channel_);
            } else {
                // Not a transition: the channel has no authorisation to withdraw. Its stored usage, if
                // any, is left exactly as it is, and the call is recorded as the parameter event alone.
                emit SetChannelRateLimit(channel_, 0, 0, 0);
            }
        } else if (!authorised) {
            _authoriseChannel(channel_, maxSingleAmount_, maxWindowAmount_, window_);
        } else {
            _updateChannelRateLimit(channel_, maxSingleAmount_, maxWindowAmount_, window_);
        }
    }

    /**
     * @dev Grants a channel an allowance it did not have. `window != 0` IS the authorisation.
     *
     * Emits {ChannelAuthorised} as well as {SetChannelRateLimit}, because this is the transition that
     * grants the ability to mint and it should be distinguishable in a log from a parameter change that
     * does not.
     *
     * Any usage the channel carried from a previous authorisation is preserved, not reset — see
     * {_checkpoint}.
     */
    function _authoriseChannel(address channel_, uint256 maxSingleAmount_, uint256 maxWindowAmount_, uint256 window_)
        private
    {
        _validateRateLimit(maxSingleAmount_, maxWindowAmount_, window_);
        _checkpoint(channel_);
        _writeRateLimit(channel_, maxSingleAmount_, maxWindowAmount_, window_);
        emit ChannelAuthorised(channel_, maxSingleAmount_, maxWindowAmount_, window_);
    }

    /**
     * @dev Changes the limits of a channel that is already authorised, leaving it authorised.
     *
     * The common case, and the only one that does not change whether the channel can mint — so it emits
     * only {SetChannelRateLimit}.
     */
    function _updateChannelRateLimit(
        address channel_,
        uint256 maxSingleAmount_,
        uint256 maxWindowAmount_,
        uint256 window_
    ) private {
        _validateRateLimit(maxSingleAmount_, maxWindowAmount_, window_);
        _checkpoint(channel_);
        _writeRateLimit(channel_, maxSingleAmount_, maxWindowAmount_, window_);
    }

    /**
     * @dev Withdraws a channel's authorisation. `window == 0` is what "unauthorised" means.
     *
     * Usage survives: the channel stops being able to mint, and nothing it already spent is forgiven.
     * That is the whole of SOLV-4, and stating it in a function whose name is `_revokeChannel` is what
     * S4 asks for — the previous shape left it as a side effect of clamping an allowance to zero.
     *
     * Reached only for a channel that is authorised. The dispatcher keeps the other case out, so the
     * {ChannelRevoked} emitted here is always a real transition.
     */
    function _revokeChannel(address channel_) private {
        _checkpoint(channel_);
        _writeRateLimit(channel_, 0, 0, 0);
        emit ChannelRevoked(channel_);
    }

    /* ------------------------------------------------------------------ */
    /*                        Shared by the three                         */
    /* ------------------------------------------------------------------ */

    function _validateRateLimit(uint256 maxSingleAmount_, uint256 maxWindowAmount_, uint256 window_) private pure {
        if (maxSingleAmount_ >= maxWindowAmount_) {
            revert SingleAmountNotBelowWindowAmount(maxSingleAmount_, maxWindowAmount_);
        }
        if (maxWindowAmount_ > MAX_WINDOW_AMOUNT) {
            revert WindowAmountAboveHardCap(maxWindowAmount_);
        }
        if (window_ < MIN_WINDOW) {
            revert WindowBelowMinimum(window_, MIN_WINDOW);
        }
    }

    /**
     * @dev Freezes the outstanding usage at the OLD decay rate, before new parameters land.
     *
     * Two properties, and both are load-bearing. Measuring the elapsed time against the NEW window would
     * retroactively forgive usage that a shortened window was never meant to forgive. And the figure is
     * carried across unchanged even when it exceeds the allowance about to be written — including a
     * revocation, whose allowance is zero — because truncating it is what used to let
     * revoke-then-reauthorise hand back a full bucket (SOLV-4). Nothing underflows:
     * {_amountCanBeUsed} reports nothing available when the limit is below the recorded usage.
     *
     * A channel revoked and later re-authorised therefore resumes with the usage it had, decaying from
     * the moment of re-authorisation under whatever window it is given. Usage does not decay while a
     * channel is revoked, because a revoked channel has no rate for it to decay at, and it does not
     * expire either: the expiry in {_amountCanBeUsed} needs a window to measure against.
     *
     * After re-authorisation, or after any change that leaves the usage above the new capacity, the
     * channel waits for the shorter of two things: linear decay bringing the usage below the new
     * capacity, at `maxWindowAmount / window` per second, or one full window since this checkpoint,
     * after which the usage expires outright. So the wait is at most one window of the new
     * configuration. Carrying 100 into a 10-per-window configuration gives nothing for one window and
     * the full 10 after it; carrying 15 gives the first allowance halfway through the window. The
     * fix review found the previous rule -- decay only, so nine windows for that first case -- and
     * reported it as SOLV-9.
     */
    function _checkpoint(address channel_) private {
        RateLimit storage rl = _rateLimits[channel_];
        (uint256 currentAmountUsed,) = _amountCanBeUsed(rl.amountUsed, rl.lastUsedAt, rl.maxWindowAmount, rl.window);
        rl.amountUsed = SafeCast.toUint128(currentAmountUsed);
        rl.lastUsedAt = SafeCast.toUint48(block.timestamp);
    }

    function _writeRateLimit(address channel_, uint256 maxSingleAmount_, uint256 maxWindowAmount_, uint256 window_)
        private
    {
        RateLimit storage rl = _rateLimits[channel_];
        rl.maxSingleAmount = SafeCast.toUint128(maxSingleAmount_);
        rl.maxWindowAmount = SafeCast.toUint128(maxWindowAmount_);
        rl.window = SafeCast.toUint32(window_);
        emit SetChannelRateLimit(channel_, maxSingleAmount_, maxWindowAmount_, window_);
    }

    /**
     * @dev The amount `channel_` may still consume at the current block, decay included. Zero for a
     * channel that is not configured.
     */
    function _remainingAmount(address channel_) internal view returns (uint256) {
        RateLimit storage rl = _rateLimits[channel_];
        if (rl.window == 0) {
            return 0;
        }
        (, uint256 availableAmount) = _amountCanBeUsed(rl.amountUsed, rl.lastUsedAt, rl.maxWindowAmount, rl.window);
        return availableAmount;
    }

    /**
     * @dev Computes the outstanding usage and the remaining allowance for a rate limit window,
     * presuming linear decay, with the usage expiring outright one window after `lastUsedAt_`.
     *
     * The expiry never changes the answer for a channel whose usage is within its capacity: linear
     * decay at `limit_ / window_` has already taken usage of at most `limit_` to zero by then. It
     * matters only when the usage exceeds the capacity, which only lowering the allowance below the
     * outstanding usage can cause, and then it bounds the wait to one window (SOLV-9). It is never
     * reached from a zero-time sequence of owner operations, because every reconfiguration and every
     * consumption moves `lastUsedAt_` to the present; and it is disabled for a channel with no window,
     * whose usage is frozen until it is re-authorised (SOLV-4).
     *
     * @param amountUsed_ The usage recorded at `lastUsedAt_`.
     * @param lastUsedAt_ Timestamp the usage was last checkpointed at.
     * @param limit_ The bucket capacity (`maxWindowAmount`), which is also the numerator of the refill rate.
     * @param window_ The window duration.
     * @return currentAmountUsed The usage still outstanding at the current block.
     * @return availableAmount The amount that may still be consumed.
     */
    function _amountCanBeUsed(uint256 amountUsed_, uint256 lastUsedAt_, uint256 limit_, uint256 window_)
        private
        view
        returns (uint256 currentAmountUsed, uint256 availableAmount)
    {
        uint256 timeSinceLastUse = block.timestamp - lastUsedAt_;
        if (window_ != 0 && timeSinceLastUse >= window_) {
            // @dev A full window since the last checkpoint: whatever was outstanding has expired.
            return (0, limit_);
        }
        // @dev Presumes linear decay. `window_ > 0 ? window_ : 1` prevents division by zero on a channel
        // that has never been configured; its allowance is zero either way.
        uint256 decay = (limit_ * timeSinceLastUse) / (window_ > 0 ? window_ : 1);
        currentAmountUsed = amountUsed_ <= decay ? 0 : amountUsed_ - decay;
        // @dev In the event the limit is lowered below the outstanding usage, nothing is available.
        availableAmount = limit_ <= currentAmountUsed ? 0 : limit_ - currentAmountUsed;
    }
}
