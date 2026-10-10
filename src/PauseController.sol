// SPDX-License-Identifier: MIT

pragma solidity 0.8.36;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "./interfaces/IPauseController.sol";

/**
 * @title PauseController
 *
 * @dev The emergency stop for this system. Deployed fresh and dedicated rather than reusing an existing
 * instance, so that its owner can be an emergency signer set chosen for this system alone; two instances
 * are deployed, one governing the gateway, depositor and manual channels and one governing only the
 * automated tier.
 *
 * The source is the component the deployed SolvBTC and BTC+ systems already use, which is where the burn
 * half comes from: `burnPaused` / `pauseBurn` / `unpauseBurn` have no reader in THIS system, because
 * nothing here burns. They are kept deliberately — wave two is expected to add a redemption path, and
 * that path may well reuse these very instances, at which point the flag becomes live.
 *
 * ⚠️ THAT IS EXACTLY WHY THE BURN HALF MUST NOT BE EXERCISED NOW. `pauseBurn()` succeeds and emits
 * `BurnPaused` while stopping nothing, so today it is a trap in two directions. During an incident it
 * reads as a control that was exercised when nothing was paused. And the bit it sets PERSISTS: a burn
 * path wired to this instance later would start out paused, silently, because of a call made months
 * earlier against a contract that then had no burn path at all. Whoever adds that path must read
 * `burnPaused()` before relying on it rather than assuming a fresh instance starts unpaused.
 *
 * Until then, `mintPaused()` is the entire emergency surface of this deployment.
 *
 * @custom:security-contact dev@solv.finance
 */
contract PauseController is Ownable2Step, IPauseController {
    /**
     * @dev Mint paused status. Public rather than private with a hand-written getter: the compiler
     * generates the identical external function, and two fewer lines cannot drift from the interface.
     * External audit, S2.6.
     */
    bool public override mintPaused;

    /**
     * @dev Burn paused status. Nothing in this system reads it — see the contract header.
     */
    bool public override burnPaused;

    error MintAlreadyPaused();
    error MintNotPaused();
    error BurnAlreadyPaused();
    error BurnNotPaused();

    /**
     * @dev Emitted when the pause is triggered for mint.
     */
    event MintPaused();

    /**
     * @dev Emitted when the pause is lifted for mint.
     */
    event MintUnpaused();

    /**
     * @dev Emitted when the pause is triggered for burn.
     */
    event BurnPaused();

    /**
     * @dev Emitted when the pause is lifted for burn.
     */
    event BurnUnpaused();

    constructor(address owner_) Ownable(owner_) {}

    /**
     * @dev Pauses minting.
     *
     * Requirements:
     *
     * - Minting must not be paused.
     */
    function pauseMint() external onlyOwner {
        if (mintPaused) {
            revert MintAlreadyPaused();
        }
        mintPaused = true;
        emit MintPaused();
    }

    /**
     * @dev Unpauses minting.
     *
     * Requirements:
     *
     * - Minting must be paused.
     */
    function unpauseMint() external onlyOwner {
        if (!mintPaused) {
            revert MintNotPaused();
        }
        mintPaused = false;
        emit MintUnpaused();
    }

    /**
     * @dev Pauses burning.
     *
     * ⚠️ NO EFFECT IN THIS SYSTEM, AND MUST NOT BE CALLED. Nothing reads `burnPaused()` here, so this
     * succeeds and emits while stopping nothing — and the bit it sets persists into wave two, where a
     * redemption path reusing this instance would find itself paused for no reason anyone remembers.
     * See the contract header.
     *
     * Requirements:
     *
     * - Burning must not be paused.
     */
    function pauseBurn() external onlyOwner {
        if (burnPaused) {
            revert BurnAlreadyPaused();
        }
        burnPaused = true;
        emit BurnPaused();
    }

    /**
     * @dev Unpauses burning.
     *
     * ⚠️ NO EFFECT IN THIS SYSTEM; see {pauseBurn}.
     *
     * Requirements:
     *
     * - Burning must be paused.
     */
    function unpauseBurn() external onlyOwner {
        if (!burnPaused) {
            revert BurnNotPaused();
        }
        burnPaused = false;
        emit BurnUnpaused();
    }
}
