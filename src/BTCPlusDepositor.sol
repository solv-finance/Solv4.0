// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./interfaces/IPauseController.sol";
import "./interfaces/IBTCPlus.sol";
import "./interfaces/IBTCPlusDepositor.sol";
import "./utils/ChannelRateLimiter.sol";

/**
 * @title BTCPlusDepositor
 *
 * @dev Intended to be the only holder of BTCPlus' minter role. Takes SolvBTC from an authorised caller,
 * settles it into the Safe vault, and issues the BTCPlus those assets are worth at the realtime NAV.
 *
 * "Intended" because this contract cannot enforce it: BTCPlus' administrator decides who holds that role.
 * The sole-holder property is a deployment configuration to be verified on chain rather than an invariant
 * of this code (external audit, S2.7).
 *
 * The invariant this contract exists to hold:
 *
 *   I1 — every {Deposited} event corresponds to an equal amount of SolvBTC arriving in `vault`, and to a
 *   BTCPlus issuance converted at the same block's NAV. Issuance without a matching asset inflow is
 *   impossible.
 *
 * Assets move straight from the caller to the vault, never through this contract, so its balance is zero
 * at every point between transactions. That is also why it has no rescue function: it is designed never
 * to custody anything, and a rescue entry point would widen the owner's reach for no benefit.
 *
 * Pricing is deliberately the audited baseline's, moved here unchanged. `nav_` is a quote-staleness
 * bound, not an oracle safeguard, and it takes no part in the conversion — see {MAX_NAV_DEVIATION_BPS}.
 *
 * There is no NAV risk control beyond that band, by design. A contract cannot tell "the NAV really fell"
 * from "the NAV is wrong". Minting at a genuinely lower NAV preserves value; minting at a falsely low one
 * issues more shares than the deposit is worth and dilutes existing holders (SOLV-3) -- and nothing on
 * chain can tell the two apart, so halting on that signal would trade availability for a guess. Oracle
 * correctness is the oracle's
 * responsibility, and freshness and abnormal movement are checked where the NAV's timestamp and history
 * can actually be read: in the verifier, before it signs. An on-chain movement limit was tried and
 * withdrawn — sampled only at deposits, it blocked the oracle's ordinary daily step after a recent
 * deposit and still passed a stale, unchanged value (external audit, SOLV-3). Note that the rate limit
 * ceilings apply to the SolvBTC coming in and not to the BTCPlus going out.
 *
 * The contract is deliberately not upgradeable, for the same reason the gateway is not.
 *
 * @custom:security-contact dev@solv.finance
 */
contract BTCPlusDepositor is IBTCPlusDepositor, ChannelRateLimiter, Ownable2Step, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /**
     * @dev The address of the BTCPlus token contract. Exposed so that channels read it back from here.
     */
    address public immutable override BTCPLUS;

    /**
     * @dev The address of the SolvBTC token contract.
     */
    address public immutable override SOLVBTC;

    /**
     * @dev The Safe multisig holding the SolvBTC reserves backing every BTCPlus issued here.
     */
    address public vault;

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

    /**
     * @dev The maximum NAV movement, in basis points, tolerated between the moment the verifier quotes a
     * NAV and the moment the transaction executes.
     *
     * This is a QUOTE-TIME CHECK, not an oracle safeguard. The verifier obtains its quote by reading this
     * same on-chain oracle, so both compared values share one source: an oracle reporting an implausible
     * NAV would be quoted implausibly, read back implausibly, and pass with `navDiff == 0`. Oracle
     * correctness is an external trust assumption, deliberately out of scope here.
     *
     * What the band does enforce is that a signature has not gone stale: beyond this much drift the quote
     * no longer represents the current price and must be re-issued. The quoted NAV never participates in
     * the share conversion, so widening or narrowing the band has no economic consequence, only an
     * availability one.
     */
    uint256 public constant MAX_NAV_DEVIATION_BPS = 100; // 1%

    /// @dev Basis-point denominator. Named so the two comparisons below read as proportions rather
    /// than as arithmetic with a magic number in it. External audit, S2.5.
    uint256 public constant BPS_DENOMINATOR = 10000;

    error InvalidBTCPlus(address btcplus);
    error InvalidSolvBTC(address solvBTC);
    error InvalidVault(address vault);
    error VaultUnchanged();
    error InvalidPauseController(address pauseController);
    error DepositPaused();
    error InvalidReceiver(address receiver);
    error InvalidAmount(uint256 amount);
    error InvalidNav(uint256 nav);
    /// @dev Carry the values that failed. A rejected deposit is read after the fact, from a receipt,
    /// by someone who cannot re-run the call at that block. External audit, S2.3.
    error NavDiffOutOfRange(uint256 quotedNav, uint256 executionNav, uint256 maxDeviationBps);
    /// @dev Raised only when the conversion returns zero, so the old `mintedAmount` argument always
    /// reported zero and told the reader nothing. Carries the inputs that produced it instead.
    /// External audit, S2.2.
    error InvalidMintedAmount(uint256 solvBTCAmount, uint256 executionNav);
    error VaultUnderfunded(uint256 amount);

    /**
     * @dev Carries both NAVs, because they are different numbers with different meanings.
     *
     * `quotedNav` is what the verifier signed; it is used only to bound how far the price may have moved
     * between quote and execution. `executionNav` is what `getSharesByValue` actually converted at. The
     * event used to carry only the first, so off-chain reconciliation computed the expected share count
     * from a price the conversion never used -- and BTC+ reprices daily, which made every mint spanning a
     * repricing reconcile as a mismatch. External audit, SOLV-6.
     */
    event Deposited(
        address indexed channel,
        address indexed receiver,
        uint256 solvBTCAmount,
        uint256 btcPlusAmount,
        uint256 quotedNav,
        uint256 executionNav,
        address vault
    );
    event SetVault(address indexed previousVault, address indexed newVault);

    /**
     * @dev Modifier to check if depositing is not paused. Reads the MAIN pause controller, which is the
     * one the gateway and the manual-tier channels also read -- so pausing it stops every BTC+ deposit,
     * whichever channel it came through. The fast-tier channels read a separate controller of their own:
     * pausing that stops the fast tier and nothing else, and does not reach this modifier. The reference
     * is immutable; see {PAUSE_CONTROLLER}. External audit, SOLV-5.
     */
    modifier whenDepositNotPaused() {
        if (IPauseController(PAUSE_CONTROLLER).mintPaused()) {
            revert DepositPaused();
        }
        _;
    }

    constructor(address btcplus_, address solvBTC_, address vault_, address owner_, address pauseController_)
        Ownable(owner_)
        ReentrancyGuardTransient()
    {
        if (btcplus_ == address(0)) {
            revert InvalidBTCPlus(btcplus_);
        }
        if (solvBTC_ == address(0)) {
            revert InvalidSolvBTC(solvBTC_);
        }
        BTCPLUS = btcplus_;
        SOLVBTC = solvBTC_;
        _setVault(vault_);
        if (pauseController_ == address(0)) {
            revert InvalidPauseController(pauseController_);
        }
        PAUSE_CONTROLLER = pauseController_;
    }

    /**
     * @dev Deposits SolvBTC and mints the equivalent BTCPlus to `receiver_`.
     *
     * `nav_` is trusted to have been verified by the calling channel. That is not a new trust
     * assumption: only whitelisted channels can reach this function at all, and the quote check it
     * enables is a staleness bound rather than a pricing input.
     *
     * Order of operations is asset-first: the allowance is charged, the SolvBTC is moved into the vault
     * and the arrival verified, and only then is BTCPlus issued. Invariant I1 holds because the issuance
     * is unreachable from any path where the transfer did not land.
     *
     * Requirements:
     * - The caller must be a configured channel with sufficient allowance.
     * - Depositing must not be paused.
     * - `receiver_`, `solvBTCAmount_` and `nav_` must all be non-zero.
     * - `nav_` must be within {MAX_NAV_DEVIATION_BPS} of the realtime NAV.
     * - The conversion must yield a non-zero number of shares.
     * - The vault must end up holding at least `solvBTCAmount_` more SolvBTC than it did.
     *
     * @param solvBTCAmount_ The amount of SolvBTC deposited.
     * @param receiver_ The address receiving the minted BTCPlus.
     * @param nav_ The NAV quoted by the caller's verifier. Bounds quote-to-execution drift only.
     * @return btcPlusAmount The number of BTCPlus shares minted.
     */
    function deposit(uint256 solvBTCAmount_, address receiver_, uint256 nav_)
        external
        override
        nonReentrant
        whenDepositNotPaused
        returns (uint256 btcPlusAmount, uint256 executionNav)
    {
        if (receiver_ == address(0)) {
            revert InvalidReceiver(receiver_);
        }
        if (solvBTCAmount_ == 0) {
            revert InvalidAmount(solvBTCAmount_);
        }
        if (nav_ == 0) {
            revert InvalidNav(nav_);
        }

        _consume(msg.sender, solvBTCAmount_);

        (btcPlusAmount, executionNav) = _checkNavAndConvertToShares(solvBTCAmount_, nav_);

        // Assets first, shares second. The vault's balance is checked with `<` and not `!=` because
        // anyone can transfer SolvBTC to the vault: under strict equality a one wei transfer landing in
        // the same block would revert every deposit.
        address vaultAddress = vault;
        uint256 vaultBalanceBefore = IERC20(SOLVBTC).balanceOf(vaultAddress);
        IERC20(SOLVBTC).safeTransferFrom(msg.sender, vaultAddress, solvBTCAmount_);
        if (IERC20(SOLVBTC).balanceOf(vaultAddress) - vaultBalanceBefore < solvBTCAmount_) {
            revert VaultUnderfunded(solvBTCAmount_);
        }

        IBTCPlus(BTCPLUS).mint(receiver_, btcPlusAmount);

        emit Deposited(msg.sender, receiver_, solvBTCAmount_, btcPlusAmount, nav_, executionNav, vaultAddress);
    }

    /**
     * @dev Sets the vault address.
     *
     * The highest-risk entry point on this contract: a vault pointed at an attacker turns every
     * subsequent deposit into a donation. It is why the owner is a 72h timelock and why the rate limit
     * exists on an otherwise asset-driven contract.
     *
     * @param vault_ The address of the new vault.
     */
    function setVault(address vault_) external onlyOwner {
        _setVault(vault_);
    }

    /**
     * @dev Configures — or, with `window_ == 0`, revokes — a channel's authorisation and deposit limit.
     * See {ChannelRateLimiter-_setChannelRateLimit} for the constraints it enforces.
     *
     * A depositor is asset-driven and in principle needs no limit at all: nothing is issued that was not
     * paid for. It has one anyway, because {setVault} exists — if the vault is ever repointed at an
     * attacker, this is the only brake between that moment and the emergency pause. The limit must also
     * stay per-channel: a shared bucket would let a future public channel drain the allowance and starve
     * the mainnet one.
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
     * @dev The amount `channel_` may still deposit at the current block, decay included.
     */
    function remainingDepositAmount(address channel_) external view override returns (uint256) {
        return _remainingAmount(channel_);
    }

    /**
     * @dev Internal function bounding quote-time NAV drift, then converting the deposited value into
     * BTCPlus shares at the realtime NAV.
     *
     * The pricing logic of the audited `BTCPlusMainnetMinter`, with the execution NAV also returned (SOLV-6)
     * and the errors given arguments (S2).
     *
     * The deviation check bounds staleness only — it does NOT protect against a malfunctioning or
     * manipulated oracle, because the quote is itself derived from that oracle. See
     * {MAX_NAV_DEVIATION_BPS}.
     *
     * The `mintedAmount != 0` check below is a separate concern and IS load-bearing: BTCPlus returns zero
     * shares rather than reverting when its NAV oracle reports zero, so without it a deposit could be
     * consumed for nothing.
     *
     * @return mintedAmount The number of BTCPlus shares worth `amount_` at the realtime NAV.
     */
    function _checkNavAndConvertToShares(uint256 amount_, uint256 nav_)
        private
        view
        returns (uint256 mintedAmount, uint256 realtimeNav)
    {
        uint8 decimals = IBTCPlus(BTCPLUS).decimals();
        realtimeNav = IBTCPlus(BTCPLUS).getValueByShares(10 ** decimals);
        uint256 navDiff = nav_ >= realtimeNav ? nav_ - realtimeNav : realtimeNav - nav_;
        if (navDiff * BPS_DENOMINATOR > realtimeNav * MAX_NAV_DEVIATION_BPS) {
            revert NavDiffOutOfRange(nav_, realtimeNav, MAX_NAV_DEVIATION_BPS);
        }

        mintedAmount = IBTCPlus(BTCPLUS).getSharesByValue(amount_);

        if (mintedAmount == 0) revert InvalidMintedAmount(amount_, realtimeNav);
    }

    /**
     * @dev Internal function to update the vault address.
     *
     * Rejects this contract itself as the vault: deposits would still "succeed" — the balance check
     * passes when the depositor pays itself — but every reserve would silently strand in a contract
     * that, by design, has no rescue path. The zero check catches the obvious mistake; this catches
     * the one that would not revert.
     *
     * @param vault_ The address of the new vault.
     */
    function _setVault(address vault_) private {
        // The two token addresses are excluded for the same reason `address(this)` is: a transfer to any
        // of them succeeds, the balance-difference check passes, and the reserve sits at an address with
        // no withdrawal path. Nothing reverts and nothing looks wrong until someone counts the vault.
        // Both are known at construction — `BTCPLUS` and `SOLVBTC` are assigned before this runs — so the
        // whole class of silent-loss destinations that this contract can recognise costs one comparison.
        if (vault_ == address(0) || vault_ == address(this) || vault_ == SOLVBTC || vault_ == BTCPLUS) {
            revert InvalidVault(vault_);
        }
        if (vault_ == vault) {
            revert VaultUnchanged();
        }
        address previousVault = vault;
        vault = vault_;
        emit SetVault(previousVault, vault_);
    }
}
