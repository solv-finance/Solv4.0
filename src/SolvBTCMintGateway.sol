// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import "./interfaces/IPauseController.sol";
import "./interfaces/ISolvBTC.sol";
import "./interfaces/ISolvBTCMintGateway.sol";
import "./utils/ChannelRateLimiter.sol";

/**
 * @title SolvBTCMintGateway
 *
 * @dev Intended to be the only holder of SolvBTC's minter role, standing between the channels that need
 * to mint and the token itself.
 *
 * "Intended" because this contract cannot enforce it. SolvBTC's own administrator decides who holds that
 * role and can grant it elsewhere at any time; the sole-holder property is a deployment configuration to
 * be verified on chain, not an invariant of this code. It was written here as a statement of fact, which
 * is the kind of claim that stops being checked because it reads as already settled. External audit,
 * S2.7.
 *
 * SolvBTC is a 1:1 hard-pegged asset accepted at face value across the whole ecosystem, so the blast
 * radius of a compromised minter is far larger than for any yield-bearing token downstream of it. This
 * contract exists to put a ceiling on that: every channel mints through a per-channel rate limit, and no
 * limit — not even one the owner sets — can exceed {MAX_WINDOW_AMOUNT}.
 *
 * The metering itself lives in {ChannelRateLimiter}, shared with {BTCPlusDepositor} so that the four
 * details it has to get right are written out once rather than once per contract.
 *
 * The contract is deliberately not upgradeable. A proxy admin over a contract holding a minter role is
 * equivalent to an unbounded minting right: a single `upgradeTo` would erase every check below.
 *
 * @custom:security-contact dev@solv.finance
 */
contract SolvBTCMintGateway is ISolvBTCMintGateway, ChannelRateLimiter, Ownable2Step, ReentrancyGuardTransient {
    /**
     * @dev The address of the SolvBTC token contract. Exposed so that channels read it back from here
     * instead of taking a second, independently supplied copy that could disagree with this one.
     */
    address public immutable override SOLVBTC;

    /**
     * @dev The pause controller this contract reads, fixed at construction.
     *
     * Immutable because a replaceable reference was a way for the emergency topology to drift. Every
     * consumer stored its own and exposed its own setter, so re-pointing "the" controller was several
     * independent updates -- and performing them incompletely left the system looking paused while a
     * route through it was not. Repointing the gateway alone was enough: a fast channel would check its
     * own unpaused controller, the gateway would check its newly configured one, and the mint would go
     * through while operators believed everything had stopped.
     *
     * Nothing operational is lost. Rotating the emergency signer set is `transferOwnership` on the
     * {PauseController} itself, which this reference does not touch, and the deployment scripts already
     * carry a controller across an upgrade rather than replacing it. What is lost is the ability of a
     * compromised owner to point the emergency stop at a controller it owns -- an attack this repository
     * had already written down without removing.
     *
     * External audit, SOLV-5, first of the two remedies offered.
     */
    address public immutable PAUSE_CONTROLLER;

    error InvalidSolvBTC(address solvBTC);
    error InvalidAmount(uint256 amount);
    error InvalidReceiver(address receiver);
    error InvalidPauseController(address pauseController);
    error MintPaused();

    event Minted(address indexed channel, address indexed to, uint256 amount);

    /**
     * @dev Modifier to check if minting is not paused.
     */
    modifier whenMintNotPaused() {
        if (IPauseController(PAUSE_CONTROLLER).mintPaused()) {
            revert MintPaused();
        }
        _;
    }

    constructor(address solvBTC_, address owner_, address pauseController_) Ownable(owner_) ReentrancyGuardTransient() {
        if (solvBTC_ == address(0)) {
            revert InvalidSolvBTC(solvBTC_);
        }
        SOLVBTC = solvBTC_;
        if (pauseController_ == address(0)) {
            revert InvalidPauseController(pauseController_);
        }
        PAUSE_CONTROLLER = pauseController_;
    }

    /**
     * @dev Mints SolvBTC on behalf of the calling channel.
     *
     * The allowance is charged before the token is touched, so a callback from anywhere downstream
     * cannot mint against an allowance this call has already spent.
     *
     * Requirements:
     * - The caller must be a configured channel.
     * - `amount_` must be non-zero.
     * - `amount_` must not exceed the channel's single-transaction cap.
     * - `amount_` must fit within the channel's remaining window allowance.
     * - Minting must not be paused.
     *
     * @param to_ The address receiving the minted SolvBTC.
     * @param amount_ The amount to mint.
     */
    function mint(address to_, uint256 amount_) external override nonReentrant whenMintNotPaused {
        // The channels reject a zero recipient before they get here, but an address authorised directly
        // through {setChannelRateLimit} is not subject to any channel's checks — and authorising one is
        // exactly what granting SolvBTC minting authority means at this contract. Relying on the external
        // token to refuse makes this contract's behaviour depend on an implementation it does not own.
        // External audit, S2.1.
        if (to_ == address(0)) {
            revert InvalidReceiver(to_);
        }

        // Both current channels reject a zero amount before reaching here, so this guards the next one
        // rather than either of them. A zero mint consumes no allowance and moves nothing, but it emits
        // a `Minted` event indistinguishable from a real one to anything reading the log — and the
        // channel that could emit them is by definition an authorised one.
        if (amount_ == 0) {
            revert InvalidAmount(amount_);
        }
        _consume(msg.sender, amount_);
        ISolvBTC(SOLVBTC).mint(to_, amount_);
        emit Minted(msg.sender, to_, amount_);
    }

    /**
     * @dev Configures — or, with `window_ == 0`, revokes — a channel's authorisation and mint limit.
     * See {ChannelRateLimiter-_setChannelRateLimit} for the constraints it enforces.
     *
     * @param channel_ The channel being configured.
     * @param maxSingleAmount_ The per-transaction cap.
     * @param maxWindowAmount_ The bucket capacity, which also sets the refill rate: `maxWindowAmount_ / window_` per second.
     * @param window_ The window duration in seconds; zero revokes the channel.
     */
    function setChannelRateLimit(address channel_, uint256 maxSingleAmount_, uint256 maxWindowAmount_, uint256 window_)
        external
        onlyOwner
    {
        _setChannelRateLimit(channel_, maxSingleAmount_, maxWindowAmount_, window_);
    }

    /**
     * @dev The amount `channel_` may still mint at the current block, decay included.
     */
    function remainingMintAmount(address channel_) external view override returns (uint256) {
        return _remainingAmount(channel_);
    }
}
