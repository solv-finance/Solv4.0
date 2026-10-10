// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import "./interfaces/IPauseController.sol";
import "./interfaces/ISolvBTCMintGateway.sol";
import "./interfaces/IBTCTxRegistry.sol";

/**
 * @title SolvBTCMainnetChannel
 *
 * @dev Turns a verified Bitcoin deposit into SolvBTC for the depositor.
 *
 * Derived from the audited `SolvBTCMainnetMinter`, whose authoritative source is
 * https://github.com/solv-finance/mainnet-minter-contracts/blob/main/contracts/SolvBTCMainnetMinter.sol
 * — diff against that file to verify the claims below. The authorisation half is carried over, with three
 * September 2026 departures: the signed struct drops `chainId`/`token` and binds `minter` to `msg.sender`
 * (S3, SOLV-8), `mint()` no longer takes `chainId_`, and the pause reference is immutable with no setter
 * (SOLV-5). Otherwise as the baseline:
 * - Role-based minting: Only authorized minters can trigger the mint process.
 * - Minting Caps: Each minter is assigned a maximum minting capacity.
 * - Signature Verification: Ensures all minting requests are approved by an off-chain verifier.
 * - Pause Mechanism: Allows pausing minting operations in case of emergencies.
 *
 * Double-minting protection is carried over in substance but moved out of this contract's storage. BTC
 * transaction hashes are recorded in the shared {BTCTxRegistry} instead, so that a deposit spent here can
 * never be spent again through a second channel or through a redeployment of this one. That matters
 * concretely here: this contract replaces a minter that is already live, and the registry is what stops a
 * deposit the old one processed from being mintable a second time through this one.
 *
 * What changed is where the minting right lives. The baseline held SolvBTC's minter role directly; this
 * contract holds none and mints through {SolvBTCMintGateway}, which meters every channel against a
 * per-channel rate limit capped at {SolvBTCMintGateway-MAX_WINDOW_AMOUNT}. SolvBTC is a 1:1 hard-pegged
 * asset accepted at face value across the ecosystem, so bounding how fast any one channel can issue it
 * matters more here than anywhere downstream.
 *
 * Unlike {BTCPlusMainnetChannel} this path is single-legged. SolvBTC is the destination asset, so there
 * is nothing to convert, no NAV anywhere in the flow, and no depositor to route through: the gateway
 * mints straight to the recipient. `amount_` means the same quantity at every layer.
 *
 * Because the channel is never in the custody path it holds no balance at any point, and so — like
 * {BTCPlusDepositor}, and unlike {BTCPlusMainnetChannel}, which can be left holding SolvBTC between its
 * two legs — it deliberately has no rescue function. There is nothing for one to recover, and adding it
 * would widen the owner's reach for no benefit.
 *
 * The gateway and registry addresses are immutable. Making them settable would turn "redeploy and
 * re-authorise" into a single multisig call, which is not a trade worth making for a contract in this
 * position — and for the registry in particular, one such call would point the channel at an empty replay
 * store and make every deposit the system has ever processed mintable again.
 *
 * @custom:security-contact dev@solv.finance
 */
contract SolvBTCMainnetChannel is EIP712, Ownable2Step, ReentrancyGuardTransient {
    /**
     * @dev The gateway holding SolvBTC's minter role. Every mint runs through it.
     */
    address public immutable GATEWAY;

    /**
     * @dev The address of the SolvBTC token contract, read back from {GATEWAY} at construction rather
     * than supplied separately: two addresses that are never passed twice cannot disagree.
     */
    address public immutable SOLVBTC;

    /**
     * @dev The shared replay registry. Every channel in the system consumes BTC transaction hashes here.
     */
    address public immutable REGISTRY;

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
     * already unusable on another chain or against another channel before either field was read. Each
     * channel's token is immutable, which makes `token` a restatement of `verifyingContract`. Carrying
     * them cost calldata and gave integrations two ways to be internally inconsistent -- a `chainId_`
     * argument that disagreed with `block.chainid` was a rejection the caller had to be taught about,
     * for a value the contract could read itself.
     *
     * They still appear in the OP_RETURN payload, which is data from Bitcoin rather than a parameter:
     * the depositor committed to a chain and a token when they made the deposit, and that commitment is
     * still checked. External audit, S3.
     */
    bytes32 public constant MINT_TYPEHASH = keccak256(
        "Mint(address to,uint256 amount,bytes32 btcTxHash,bytes32 opReturnHash,uint256 expireTime,address minter)"
    );

    /**
     * @dev Distinct from the baseline minter's domain, so that a signature issued for one contract can
     * never be replayed against the other.
     */
    string private constant MINT_DOMAIN_SEPARATOR_NAME = "SolvBTC Mainnet Channel";
    string private constant MINT_DOMAIN_SEPARATOR_VERSION = "1.0";

    /**
     * @dev The maximum lifetime a verifier signature may declare, counted from the moment it is executed.
     *
     * NEW relative to `SolvBTCMainnetMinter`, which bounded `expireTime` from below only. Without an
     * upper bound the validity window is entirely the verifier's to choose and the contract has no
     * backstop: a compromised verifier service could issue signatures that stay live indefinitely, and
     * they would remain so until the verifier address itself was rotated. The value matches
     * {BTCPlusMainnetChannel}, so both contracts in this audit bound signature lifetime identically.
     */
    uint256 public constant MAX_SIGNATURE_VALIDITY = 14 days;

    error InvalidGateway(address gateway);
    error InvalidRegistry(address registry);
    error InvalidSolvBTC(address solvbtc);
    error MintPaused();
    error MinterCapExceeded(uint256 minterCap, uint256 mintAmount);
    error InvalidReceiver(address receiver);
    error InvalidMintAmount(uint256 amount);
    error InvalidBtcTxHash(bytes32 btcTxHash);
    error InvalidOpReturn(bytes opReturn);
    error BtcTxHashMinted(bytes32 btcTxHash);
    error SignatureExpired(uint256 expireTime);
    error SignatureValidityTooLong(uint256 expireTime);
    error SignatureVerificationFailed();
    error InvalidMinter(address minter);
    error MinterCannotBeVerifier();
    error InvalidVerifier(address verifier);
    error VerifierUnchanged();
    error VerifierCannotBeMinter();
    error InvalidPauseController(address pauseController);

    event SetVerifier(address indexed previousVerifier, address indexed newVerifier);
    event SetMinterCap(address indexed minter, uint256 previousCap, uint256 newCap);
    event Minted(
        bytes32 indexed btcTxHash,
        address indexed to,
        uint256 amount,
        uint256 chainId,
        bytes opReturn,
        uint256 expireTime
    );

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
        uint256 cap = minterCaps[msg.sender];
        if (cap < mintAmount_) {
            revert MinterCapExceeded(cap, mintAmount_);
        }
        _;
    }

    /**
     * @dev `registry_` gets a non-zero check and nothing more. This contract has to be authorised at the
     * registry and at the gateway, and both take its address — which does not exist until this constructor
     * returns. Those two authorisations are deployment steps, and both are load bearing: a channel missing
     * either one reverts on its first mint.
     */
    constructor(address gateway_, address registry_, address owner_, address verifier_, address pauseController_)
        EIP712(MINT_DOMAIN_SEPARATOR_NAME, MINT_DOMAIN_SEPARATOR_VERSION)
        Ownable(owner_)
        ReentrancyGuardTransient()
    {
        if (gateway_ == address(0)) {
            revert InvalidGateway(gateway_);
        }
        if (registry_ == address(0)) {
            revert InvalidRegistry(registry_);
        }
        GATEWAY = gateway_;
        REGISTRY = registry_;

        address solvbtc = ISolvBTCMintGateway(gateway_).SOLVBTC();
        if (solvbtc == address(0)) {
            revert InvalidSolvBTC(solvbtc);
        }
        SOLVBTC = solvbtc;

        _setVerifier(verifier_);
        if (pauseController_ == address(0)) {
            revert InvalidPauseController(pauseController_);
        }
        PAUSE_CONTROLLER = pauseController_;
    }

    /**
     * @dev Mints SolvBTC tokens to a specified recipient after verifying the transaction details and signature.
     *
     * This function is intended to be called by authorized minters. It ensures that the minting process
     * is authorized by a trusted verifier through an EIP-712 signature.
     *
     * The mint is executed through {GATEWAY} rather than against the token directly, so it is additionally
     * subject to this channel's rate limit there. When that allowance is exhausted the whole transaction
     * reverts and `btcTxHash_` is left unspent, so the deposit stays mintable once the window has decayed.
     *
     * Requirements:
     * - The caller must be an authorized minter with a sufficient minting cap.
     * - Minting must not be paused.
     * - `to_` must be a valid non-zero address.
     * - `amount_` must be greater than zero.
     * - `opReturn_` must match the OP_RETURN data of the BTC transaction (chainId, token address, recipient).
     * - `btcTxHash_` must not have been used for minting before, by this or by ANY other channel sharing
     *   the registry (prevents double-minting).
     * - `verifierSignature_` must be a valid signature from the `verifier` address, covering all transaction details.
     * - `expireTime_` must be in the range [`block.timestamp`, `block.timestamp` + {MAX_SIGNATURE_VALIDITY}].
     * - This channel must have enough allowance left at the gateway.
     *
     * @param to_ The address that will receive the minted SolvBTC tokens.
     * @param amount_ The number of SolvBTC tokens to be minted. SolvBTC is pegged 1:1, so this is both
     *        the deposited bitcoin value and the quantity issued.
     * @param btcTxHash_ The unique identifier of the Bitcoin transaction that triggered this minting.
     * @param opReturn_ The OP_RETURN data of the BTC transaction, used for verification.
     * @param verifierSignature_ The cryptographic signature provided by the authorized verifier.
     * @param expireTime_ The expiration timestamp for the verifier signature.
     *
     */
    function mint(
        address to_,
        uint256 amount_,
        bytes32 btcTxHash_,
        bytes calldata opReturn_,
        bytes calldata verifierSignature_,
        uint256 expireTime_
    ) external nonReentrant whenMintNotPaused onlyMinter(amount_) {
        if (to_ == address(0)) revert InvalidReceiver(to_);
        if (amount_ == 0) revert InvalidMintAmount(amount_);
        if (btcTxHash_ == bytes32(0)) revert InvalidBtcTxHash(btcTxHash_);
        // Read from the shared registry, so a deposit already spent by ANY channel is rejected here. The
        // registry re-checks this on write; this call exists to fail before the signature work, and with
        // the error the caller expects.
        if (IBTCTxRegistry(REGISTRY).txReceivers(btcTxHash_) != address(0)) revert BtcTxHashMinted(btcTxHash_);
        if (expireTime_ < block.timestamp) revert SignatureExpired(expireTime_);
        if (expireTime_ > block.timestamp + MAX_SIGNATURE_VALIDITY) revert SignatureValidityTooLong(expireTime_);

        {
            bytes32 opReturnHash = keccak256(opReturn_);
            if (opReturnHash != keccak256(abi.encodePacked(block.chainid, SOLVBTC, to_))) {
                revert InvalidOpReturn(opReturn_);
            }

            // hash tx data for verification
            bytes32 messageHash = _hashTypedDataV4(
                keccak256(abi.encode(MINT_TYPEHASH, to_, amount_, btcTxHash_, opReturnHash, expireTime_, msg.sender))
            );

            bool isValidSignature = SignatureChecker.isValidSignatureNow(verifier, messageHash, verifierSignature_);
            if (!isValidSignature) {
                revert SignatureVerificationFailed();
            }
        }

        // State before value: the replay record is committed while the mint is still ahead.
        _setTxReceiver(btcTxHash_, to_);

        // Straight to the recipient. The channel is never in the custody path, so there is no balance to
        // measure and nothing to check afterwards — the gateway either minted or the call reverted.
        ISolvBTCMintGateway(GATEWAY).mint(to_, amount_);

        emit Minted(btcTxHash_, to_, amount_, block.chainid, opReturn_, expireTime_);
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
     * before the mint itself, the registry makes no calls of its own and has no callback surface, and
     * {mint} is `nonReentrant` regardless. The CEI property the baseline had — the replay record is
     * committed before anything of value moves — is unchanged.
     *
     * @param btcTxHash_ The hash of the Bitcoin transaction.
     * @param to_ The address that received the SolvBTC tokens.
     */
    function _setTxReceiver(bytes32 btcTxHash_, address to_) private {
        IBTCTxRegistry(REGISTRY).consume(btcTxHash_, to_);
    }
}
