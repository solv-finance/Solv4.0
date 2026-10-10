// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./interfaces/IPauseController.sol";
import "./interfaces/ISolvBTCMintGateway.sol";
import "./interfaces/IBTCPlusDepositor.sol";
import "./interfaces/IBTCTxRegistry.sol";

/**
 * @title BTCPlusMainnetChannel
 *
 * @dev Turns a verified Bitcoin deposit into BTCPlus for the depositor.
 *
 * Derived from `BTCPlusMainnetMinter`, itself the NAV-bearing variant of the audited
 * `SolvBTCMainnetMinter`, whose authoritative source is
 * https://github.com/solv-finance/mainnet-minter-contracts/blob/main/contracts/SolvBTCMainnetMinter.sol
 * — the shared authorisation half diffs cleanly against that file; what BTCPlus adds on top of it is
 * the NAV quote band and the share conversion, which now live in {BTCPlusDepositor}.
 *
 * The authorisation half is carried over, with three September 2026 departures: the signed struct drops
 * `chainId`/`token` and binds `minter` to `msg.sender` (S3, SOLV-8), `mint()` no longer takes `chainId_`,
 * and the pause reference is immutable with no setter (SOLV-5). Otherwise as the baseline:
 * - Role-based minting: Only authorized minters can trigger the mint process.
 * - Minting Caps: Each minter is assigned a maximum minting capacity.
 * - Signature Verification: Ensures all minting requests are approved by an off-chain verifier.
 * - Pause Mechanism: Allows pausing minting operations in case of emergencies.
 *
 * Double-minting protection is carried over in substance but moved out of this contract's storage. BTC
 * transaction hashes are recorded in the shared {BTCTxRegistry} instead, so that a deposit spent here can
 * never be spent again through a second channel or through a redeployment of this one. See that
 * contract's header for why per-contract storage is not sufficient once more than one channel exists.
 *
 * What changed is the settlement half. Where the baseline minted BTCPlus directly, this contract holds
 * no minting rights at all and executes in two legs:
 *
 *   leg 1 — {SolvBTCMintGateway} mints SolvBTC against the bitcoin deposit, into this contract;
 *   leg 2 — {BTCPlusDepositor} takes that SolvBTC into the Safe vault and issues BTCPlus straight to the
 *           recipient.
 *
 * Each layer holds exactly one minter role and enforces its own per-channel rate limit, so the reserve
 * behind each issuance is a single asset with a matching, on-chain visible inflow. Pricing lives in the
 * depositor alone; this contract quotes nothing and re-derives nothing.
 *
 * The gateway, depositor and registry addresses are immutable. Making them settable would turn "redeploy
 * and re-authorise" into a single multisig call, which is not a trade worth making for a contract in this
 * position — and for the registry in particular, one such call would point the channel at an empty replay
 * store and make every deposit the system has ever processed mintable again.
 *
 * @custom:security-contact dev@solv.finance
 */
contract BTCPlusMainnetChannel is EIP712, Ownable2Step, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /**
     * @dev The gateway holding SolvBTC's minter role. Leg 1 runs through it.
     */
    address public immutable GATEWAY;

    /**
     * @dev The depositor holding BTCPlus' minter role. Leg 2 runs through it.
     */
    address public immutable DEPOSITOR;

    /**
     * @dev The shared replay registry. Every channel in the system consumes BTC transaction hashes here.
     */
    address public immutable REGISTRY;

    /**
     * @dev The address of the SolvBTC token contract, read back from {GATEWAY} at construction.
     */
    address public immutable SOLVBTC;

    /**
     * @dev The address of the BTCPlus token contract, read back from {DEPOSITOR} at construction.
     */
    address public immutable BTCPLUS;

    /**
     * @dev The address of the verifier contract.
     */
    address public verifier;

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
     * @dev The minter caps.
     */
    mapping(address minter => uint256 cap) public minterCaps;

    // EIP712
    /**
     * @dev The submitting minter is part of the signed structure, bound to `msg.sender`.
     *
     * Without it a signature authorised one mint but not one submitter: any address with a sufficient
     * cap on this channel could take a signature from operational infrastructure or from pending
     * calldata and execute it. It could not redirect anything -- receiver, amount, token, hash, expiry
     * and NAV are all signed -- but it chose when the mint happened, front-ran the intended submitter,
     * and consumed the replay record and the channel's allowance, leaving the real request to revert as
     * already processed.
     *
     * `msg.sender` goes into the hash rather than a parameter that has to equal it. A parameter would be
     * calldata carrying a value the contract already knows, which is the redundancy S3 removes
     * elsewhere; binding the caller directly makes the requirement unbreakable rather than checked.
     *
     * External audit, SOLV-8.
     */
    /**
     * @dev The chain and the token are no longer signed members: the domain already binds both.
     *
     * OpenZeppelin's EIP-712 domain carries `chainId` and `verifyingContract`, so a signature was
     * already unusable on another chain or against another channel before either field was read. This
     * channel's token is immutable, which makes `token` a restatement of `verifyingContract`. Carrying
     * them cost calldata and gave integrations two ways to be internally inconsistent — a `chainId_`
     * argument disagreeing with `block.chainid` was a rejection the caller had to be taught about, for
     * a value the contract can read itself.
     *
     * They still appear in the OP_RETURN payload, which is data from Bitcoin rather than a parameter:
     * the depositor committed to a chain and a token when they made the deposit, and that commitment is
     * still checked. External audit, S3.
     */
    bytes32 public constant MINT_TYPEHASH = keccak256(
        "Mint(address to,uint256 amount,uint256 nav,bytes32 btcTxHash,bytes32 opReturnHash,uint256 expireTime,address minter)"
    );

    /**
     * @dev Distinct from the baseline minter's domain, so that a signature issued for one contract can
     * never be replayed against the other.
     */
    string private constant MINT_DOMAIN_SEPARATOR_NAME = "BTCPlus Mainnet Channel";
    string private constant MINT_DOMAIN_SEPARATOR_VERSION = "1.0";

    /**
     * @dev The maximum lifetime a verifier signature may declare, counted from the moment it is executed.
     *
     * COUPLED TO {BTCPlusDepositor-MAX_NAV_DEVIATION_BPS}, and this is the constraint that actually
     * bounds it. A signature carries the NAV quoted when it was issued; BTCPlus accrues yield in the
     * meantime; if the drift crosses the band before the signature expires, the mint reverts while the
     * signature is still nominally valid. The band binds at an APR of `1% x 365 / validityDays`:
     * 52.1% at 7 days, 26.1% at 14. Raising this value lowers that ceiling proportionally — check it
     * against BTCPlus' realistic yield before doing so. `test_Fork_Mint_FullValidityNavDriftStaysInBand`
     * derives the check from this constant, so it re-verifies the coupling rather than a fixed number.
     */
    uint256 public constant MAX_SIGNATURE_VALIDITY = 14 days;

    error InvalidGateway(address gateway);
    error InvalidDepositor(address depositor);
    error InvalidRegistry(address registry);
    error InvalidSolvBTC(address solvBTC);
    error InvalidBTCPlus(address btcplus);
    error SolvBTCMismatch(address gatewayToken, address depositorToken);
    error MintPaused();
    error MinterCapExceeded(uint256 minterCap, uint256 mintAmount);
    error InvalidReceiver(address receiver);
    error InvalidMintAmount(uint256 amount);
    error InvalidBtcTxHash(bytes32 btcTxHash);
    error InvalidOpReturn(bytes opReturn);
    error BtcTxHashMinted(bytes32 btcTxHash);
    error SignatureExpired(uint256 expireTime);
    error SignatureVerificationFailed();
    error InvalidMinter(address minter);
    error MinterCannotBeVerifier();
    error InvalidVerifier(address verifier);
    error VerifierUnchanged();
    error VerifierCannotBeMinter();
    error InvalidPauseController(address pauseController);
    error InvalidNav(uint256 nav);
    error SignatureValidityTooLong(uint256 expireTime);
    error SolvBTCNotReceived(uint256 expected, uint256 received);

    event SetVerifier(address indexed previousVerifier, address indexed newVerifier);
    event SetMinterCap(address indexed minter, uint256 previousCap, uint256 newCap);
    /**
     * @dev `quotedNav` is what the verifier signed and bounds the permitted drift; `executionNav` is what
     * the depositor's conversion actually used. See {BTCPlusDepositor-Deposited}. External audit, SOLV-6.
     */
    event Minted(
        bytes32 indexed btcTxHash,
        address indexed to,
        uint256 amount,
        uint256 quotedNav,
        uint256 executionNav,
        uint256 mintedAmount,
        uint256 chainId,
        bytes opReturn,
        uint256 expireTime
    );
    event Rescued(address indexed token, address indexed to, uint256 amount);

    /**
     * @dev Modifier to check if minting is not paused.
     */
    modifier whenMintNotPaused() {
        if (IPauseController(PAUSE_CONTROLLER).mintPaused()) {
            revert MintPaused();
        }
        _;
    }

    /**
     * @dev Modifier to check if the caller is an authorized minter with enough cap.
     */
    modifier onlyMinter(uint256 mintAmount_) {
        _checkMinterCap(mintAmount_);
        _;
    }

    /**
     * @dev Internal function backing {onlyMinter}. Kept out of the modifier body so that `cap` does not
     * occupy a stack slot for the entire duration of the modified function.
     */
    function _checkMinterCap(uint256 mintAmount_) private view {
        uint256 cap = minterCaps[msg.sender];
        if (cap < mintAmount_) {
            revert MinterCapExceeded(cap, mintAmount_);
        }
    }

    /**
     * @dev The token addresses are read back from the gateway and the depositor rather than supplied
     * separately: two addresses that are never passed twice cannot disagree. What still has to be
     * checked is that the two downstream contracts agree with each other about SolvBTC — leg 1 mints the
     * gateway's token and leg 2 spends the depositor's, and a mismatch would strand every deposit.
     *
     * `registry_` cannot be checked the same way. This contract has to be authorised at the registry, at
     * the gateway and at the depositor, and all three take its address — which does not exist until this
     * constructor returns. Those three authorisations are deployment steps, and every one of them is load
     * bearing: a channel missing any of them reverts on its first mint.
     */
    constructor(
        address gateway_,
        address depositor_,
        address registry_,
        address owner_,
        address verifier_,
        address pauseController_
    ) EIP712(MINT_DOMAIN_SEPARATOR_NAME, MINT_DOMAIN_SEPARATOR_VERSION) Ownable(owner_) ReentrancyGuardTransient() {
        if (gateway_ == address(0)) {
            revert InvalidGateway(gateway_);
        }
        if (depositor_ == address(0)) {
            revert InvalidDepositor(depositor_);
        }
        if (registry_ == address(0)) {
            revert InvalidRegistry(registry_);
        }
        GATEWAY = gateway_;
        DEPOSITOR = depositor_;
        REGISTRY = registry_;

        address solvBTC = ISolvBTCMintGateway(gateway_).SOLVBTC();
        if (solvBTC == address(0)) {
            revert InvalidSolvBTC(solvBTC);
        }
        address btcplus = IBTCPlusDepositor(depositor_).BTCPLUS();
        if (btcplus == address(0)) {
            revert InvalidBTCPlus(btcplus);
        }
        address depositorSolvBTC = IBTCPlusDepositor(depositor_).SOLVBTC();
        if (depositorSolvBTC != solvBTC) {
            revert SolvBTCMismatch(solvBTC, depositorSolvBTC);
        }
        SOLVBTC = solvBTC;
        BTCPLUS = btcplus;

        _setVerifier(verifier_);
        if (pauseController_ == address(0)) {
            revert InvalidPauseController(pauseController_);
        }
        PAUSE_CONTROLLER = pauseController_;
    }

    /**
     * @dev Mints BTCPlus tokens to a specified recipient after verifying the transaction details and signature.
     *
     * This function is intended to be called by authorized minters. It ensures that the minting process
     * is authorized by a trusted verifier through an EIP-712 signature.
     *
     * The share conversion is priced with the REALTIME NAV read from BTCPlus at execution time, not with
     * the NAV quoted in the signature. The deposited bitcoin does not earn yield between the moment the
     * verifier quotes a NAV and the moment this transaction lands, so pricing at the quoted (older, lower)
     * NAV would hand the recipient more value than was deposited, at the expense of existing BTCPlus
     * holders. Pricing at the realtime NAV makes the operation value-preserving: the recipient always
     * receives exactly `amount_` worth of BTCPlus, and the settlement delay costs them nothing.
     *
     * `nav_` is still signed and checked, but only to bound how far the NAV has moved between the quote
     * and this execution — it is not an oracle safeguard. The check itself now lives in
     * {BTCPlusDepositor}, along with the conversion.
     *
     * Requirements:
     * - The caller must be an authorized minter with a sufficient minting cap.
     * - Minting must not be paused.
     * - `to_` must be a valid non-zero address.
     * - `amount_` must be greater than zero.
     * - `nav_` must be greater than zero and, at the depositor, within its tolerated deviation band.
     * - `opReturn_` must match the OP_RETURN data of the BTC transaction (chainId, token address, recipient).
     * - `btcTxHash_` must not have been used for minting before, by this or by ANY other channel sharing
     *   the registry (prevents double-minting).
     * - `verifierSignature_` must be a valid signature from the `verifier` address, covering all transaction details.
     * - `expireTime_` must be in the range [`block.timestamp`, `block.timestamp` + {MAX_SIGNATURE_VALIDITY}].
     * - This channel must have enough allowance left at both the gateway and the depositor. When it does
     *   not, the whole transaction reverts and `btcTxHash_` stays unspent, so the deposit can be minted
     *   once the allowance has recovered.
     *
     * @param to_ The address that will receive the minted BTCPlus tokens.
     * @param amount_ The deposited bitcoin value to be converted into BTCPlus shares. Denominated in the
     *        decimals of the NAV's underlying currency (see `getOracleDecimals()` on BTCPlus), which is
     *        the same unit `minterCaps` is expressed in — NOT necessarily BTCPlus' own decimals.
     * @param nav_ The net asset value quoted by the verifier. Used only to bound quote-to-execution
     *        drift; it does not take part in the share conversion.
     * @param btcTxHash_ The unique identifier of the Bitcoin transaction that triggered this minting.
     * @param opReturn_ The OP_RETURN data of the BTC transaction, used for verification.
     * @param verifierSignature_ The cryptographic signature provided by the authorized verifier.
     * @param expireTime_ The expiration timestamp for the verifier signature.
     *
     */
    function mint(
        address to_,
        uint256 amount_,
        uint256 nav_,
        bytes32 btcTxHash_,
        bytes calldata opReturn_,
        bytes calldata verifierSignature_,
        uint256 expireTime_
    ) external nonReentrant whenMintNotPaused onlyMinter(amount_) {
        _validateMintParams(to_, amount_, nav_, btcTxHash_, expireTime_);
        _verifyOpReturnAndSignature(to_, amount_, nav_, btcTxHash_, opReturn_, verifierSignature_, expireTime_);

        // State before value: the replay record is committed while the two legs are still ahead.
        _setTxReceiver(btcTxHash_, to_);
        (uint256 mintedAmount, uint256 executionNav) = _mintThroughDepositor(amount_, to_, nav_);

        emit Minted(btcTxHash_, to_, amount_, nav_, executionNav, mintedAmount, block.chainid, opReturn_, expireTime_);
    }

    /**
     * @dev Internal function running the two settlement legs.
     *
     * Split out of {mint} for the same reason the validation helpers are: with viaIR off, folding it back
     * in would push {mint} past the legacy code generator's reachable stack window.
     *
     * @return mintedAmount The number of BTCPlus shares the depositor issued to `to_`.
     */
    function _mintThroughDepositor(uint256 amount_, address to_, uint256 nav_)
        private
        returns (uint256 mintedAmount, uint256 executionNav)
    {
        // Leg 1 — mint the matching SolvBTC into this contract through the gateway.
        //
        // The arrival is checked with `<` rather than `!=`: anyone can transfer SolvBTC to this contract
        // at any time, and strict equality would let a one wei transfer deny service to every mint. A
        // surplus simply stays here and is recoverable with {rescueToken}.
        uint256 balanceBefore = IERC20(SOLVBTC).balanceOf(address(this));
        ISolvBTCMintGateway(GATEWAY).mint(address(this), amount_);
        uint256 received = IERC20(SOLVBTC).balanceOf(address(this)) - balanceBefore;
        if (received < amount_) {
            revert SolvBTCNotReceived(amount_, received);
        }

        // Leg 2 — hand that SolvBTC to the depositor, which settles it into the vault and issues BTCPlus
        // straight to the recipient.
        //
        // The result is taken from the return value rather than from a balance delta on `to_`: `to_` is
        // an external address anyone can credit between the two readings, so a delta there is not a
        // measurement of what this transaction did. The depositor is a non-upgradeable contract of our
        // own, and its return value is the exact local it minted.
        IERC20(SOLVBTC).forceApprove(DEPOSITOR, amount_);
        (mintedAmount, executionNav) = IBTCPlusDepositor(DEPOSITOR).deposit(amount_, to_, nav_);
        if (IERC20(SOLVBTC).allowance(address(this), DEPOSITOR) != 0) {
            IERC20(SOLVBTC).forceApprove(DEPOSITOR, 0);
        }
    }

    /**
     * @dev Internal function checking every mint parameter that needs no external call.
     *
     * Split out of {mint} so that it gets its own stack frame; inlining it back would push {mint}
     * past the 16-slot reachable window of the legacy code generator.
     */
    function _validateMintParams(address to_, uint256 amount_, uint256 nav_, bytes32 btcTxHash_, uint256 expireTime_)
        private
        view
    {
        if (to_ == address(0)) revert InvalidReceiver(to_);
        if (amount_ == 0) revert InvalidMintAmount(amount_);
        if (nav_ == 0) revert InvalidNav(nav_);
        if (btcTxHash_ == bytes32(0)) revert InvalidBtcTxHash(btcTxHash_);
        // Read from the shared registry, so a deposit already spent by ANY channel is rejected here. The
        // registry re-checks this on write; this call exists to fail before the signature work, and with
        // the error the caller expects.
        if (IBTCTxRegistry(REGISTRY).txReceivers(btcTxHash_) != address(0)) revert BtcTxHashMinted(btcTxHash_);
        if (expireTime_ < block.timestamp) revert SignatureExpired(expireTime_);
        if (expireTime_ > block.timestamp + MAX_SIGNATURE_VALIDITY) revert SignatureValidityTooLong(expireTime_);
    }

    /**
     * @dev Internal function checking the OP_RETURN payload against the destination it encodes, then
     * verifying the EIP-712 signature covering the whole transaction.
     *
     * Both live in the same helper so that `opReturnHash` never occupies a slot in {mint}'s own frame,
     * which the three modifiers already crowd.
     */
    function _verifyOpReturnAndSignature(
        address to_,
        uint256 amount_,
        uint256 nav_,
        bytes32 btcTxHash_,
        bytes calldata opReturn_,
        bytes calldata verifierSignature_,
        uint256 expireTime_
    ) private view {
        bytes32 opReturnHash = keccak256(opReturn_);
        if (opReturnHash != keccak256(abi.encodePacked(block.chainid, BTCPLUS, to_))) {
            revert InvalidOpReturn(opReturn_);
        }

        // hash tx data for verification
        bytes32 messageHash = _hashTypedDataV4(
            keccak256(abi.encode(MINT_TYPEHASH, to_, amount_, nav_, btcTxHash_, opReturnHash, expireTime_, msg.sender))
        );

        bool isValidSignature = SignatureChecker.isValidSignatureNow(verifier, messageHash, verifierSignature_);
        if (!isValidSignature) {
            revert SignatureVerificationFailed();
        }
    }

    /**
     * @dev Sets the verifier address.
     * @param verifier_ The address of the new verifier.
     */
    function setVerifier(address verifier_) external onlyOwner {
        _setVerifier(verifier_);
    }

    /**
     * @dev Sets the minting cap for a specific minter.
     * @param minter_ The address of the minter.
     * @param cap_ The minting cap amount.
     */
    function setMinterCap(address minter_, uint256 cap_) external onlyOwner {
        if (minter_ == address(0)) {
            revert InvalidMinter(minter_);
        }
        if (minter_ == verifier) {
            revert MinterCannotBeVerifier();
        }
        uint256 previousCap = minterCaps[minter_];
        minterCaps[minter_] = cap_;
        emit SetMinterCap(minter_, previousCap, cap_);
    }

    /**
     * @dev Recovers tokens stranded in this contract.
     *
     * Nothing is meant to accumulate here — the two legs are atomic and leave a zero balance behind — but
     * SolvBTC sent in by a third party, or a surplus from an over-delivering leg 1, would otherwise sit
     * here forever. The depositor deliberately has no equivalent: it never holds a balance at all.
     *
     * @param token_ The token to sweep.
     * @param to_ The recipient of the swept balance.
     */
    function rescueToken(address token_, address to_) external onlyOwner {
        if (to_ == address(0)) {
            revert InvalidReceiver(to_);
        }
        uint256 amount = IERC20(token_).balanceOf(address(this));
        IERC20(token_).safeTransfer(to_, amount);
        emit Rescued(token_, to_, amount);
    }

    /**
     * @dev Internal function to update the verifier address.
     * @param verifier_ The address of the new verifier.
     */
    function _setVerifier(address verifier_) private {
        if (verifier_ == address(0)) {
            revert InvalidVerifier(verifier_);
        }
        if (verifier_ == verifier) {
            revert VerifierUnchanged();
        }
        if (minterCaps[verifier_] > 0) {
            revert VerifierCannotBeMinter();
        }
        address previousVerifier = verifier;
        verifier = verifier_;
        emit SetVerifier(previousVerifier, verifier_);
    }

    /**
     * @dev The receiver the shared registry holds for `btcTxHash_`, or zero if the hash has never been
     * consumed. Through the real channels that is who received tokens for it; the registry itself records
     * what an authorised caller reports and verifies no mint (SOLV-7).
     *
     * Forwards to the shared registry. Kept on this contract so that the ABI the baseline exposed still
     * answers, and because the answer is the one a caller wants: not "did this channel consume it" but "has
     * this deposit been consumed by any channel".
     */
    function txReceivers(bytes32 btcTxHash_) external view returns (address) {
        return IBTCTxRegistry(REGISTRY).txReceivers(btcTxHash_);
    }

    /**
     * @dev Internal function to record the recipient of a BTC transaction.
     *
     * The write now lands in the shared {BTCTxRegistry} rather than in this contract's storage. That makes
     * it an external call, which is worth being precise about: it is the ONLY external call {mint} makes
     * before the two settlement legs, the registry makes no calls of its own and has no callback surface,
     * and {mint} is `nonReentrant` regardless. The CEI property the baseline had — the replay record is
     * committed before anything of value moves — is unchanged.
     *
     * @param btcTxHash_ The hash of the Bitcoin transaction.
     * @param to_ The address that received the BTCPlus tokens.
     */
    function _setTxReceiver(bytes32 btcTxHash_, address to_) private {
        IBTCTxRegistry(REGISTRY).consume(btcTxHash_, to_);
    }
}
