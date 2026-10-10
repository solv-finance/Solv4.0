# SolvBTC / BTC+ Minting Architecture

The design of the minting system in this repository: what each contract is for, why it is shaped the way it
is, which alternatives were rejected, and what the security argument rests on. Deployment and operations are
described at the level of design in §10.

---

## 1. The whole picture: three layers

```
  Authorisation-driven channels          Asset-driven channels (designed, not built)
  (BTC mainnet deposits)                 (on-chain deposits, each with its own fees and caps)
  ┌──────────────────────────────┐       ┌──────────────────────────────┐
  │ BTCPlusMainnetChannel        │       │ BTCPlusXXXChannel            │
  │ SolvBTCMainnetChannel        │       │ SolvBTCXXChannel             │
  └──────────────┬───────────────┘       └──────────────┬───────────────┘
                 │                                      │
  ───────────────┼──────────────────────────────────────┼────────────────
  Minting layer  ▼                                      ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ SolvBTCMintGateway   BTCPlusDepositor   SolvBTCDepositor (design)│
  └──────────────┬───────────────────────────────────┬───────────────┘
                 │                                   │
  ───────────────┼───────────────────────────────────┼────────────────
  Asset layer    ▼                                   ▼
        SolvBTC + its Safe vault            BTC+ + its Safe vault
```

**This is a matrix, not a chain:**

- **Vertically**: two assets (SolvBTC, BTC+), each with one depositor as its minting entry point.
- **Horizontally**: each asset has several funding sources, each with one channel as its authorisation
  entry point.

The horizontal axis splits into two families, and that distinction runs through the whole design:

| | **Authorisation-driven** (mainnet channels) | **Asset-driven** (XXX channels) |
| :--- | :--- | :--- |
| Contracts | **Two**: `SolvBTCMainnetChannel`, `BTCPlusMainnetChannel`, each deployed as any number of named channels (§5.4) | Several, and growing |
| Funding source | A BTC mainnet deposit (the asset is on the Bitcoin chain) | ERC20 the user already holds |
| Minting credential | A verifier's EIP-712 signature | The tokens actually transferred in |
| Natural upper bound on minting | **None** | The user's balance |
| Per-instance parameters | Keys, `minterCaps` and rate limits (security parameters) | **Fees and subscription caps** (product parameters, §6) |
| Needs an allowance layer | **Yes, necessarily** | No |

### 1.1 Layer responsibilities

| Layer | Answers | Stateful? | Holds token privileges? |
| :--- | :--- | :--- | :--- |
| **Channel** | "Is this mint authorised?" — verifier signature, OP_RETURN binding, per-minter cap; spends the `btcTxHash` at the shared registry (§5.3) | Keys and caps; its replay records live in the registry | **No** |
| **Depositor / Gateway** | "How much, and where do the assets go?" — NAV conversion, assets into the vault, allowance metering | A little (vault, per-channel allowances) | **Yes** |
| **Token** | Bookkeeping | — | — |

Their authorities do not overlap, and pausing follows tiers rather than layers (§7). **No channel holds any
token's minter role** — the most important structural property in this architecture.

### 1.2 The nicest property: one reserve asset per layer

```
BTC (custodied)  ──→ the reserve behind SolvBTC
SolvBTC          ──→ the reserve behind BTC+
```

What this system feeds into each layer's reserve is a **single asset type**. The depositor's vault receives
only SolvBTC, and every issuance through it corresponds to an on-chain asset transfer, so the `Deposited`
events and the vault balance can be reconciled against each other.

This produces one counter-intuitive but correct effect: when `BTCPlusMainnetChannel` processes a BTC
deposit, SolvBTC's `totalSupply` increases, and that new SolvBTC sits in BTC+'s vault. That is not "extra
SolvBTC printed" — it is **the correct representation of that BTC deposit at the SolvBTC layer**. The BTC
really did enter SolvBTC's custody, and it really did become BTC+'s reserve.

### 1.3 Scope

| Component | Status | Note |
| :--- | :--- | :--- |
| `SolvBTCMintGateway` | **Built** | The intended sole holder of SolvBTC's minter role; every SolvBTC mint in this system goes through it (§3) |
| `BTCPlusDepositor` | **Built** | The intended sole holder of BTC+'s minter role (§4) |
| `BTCPlusMainnetChannel` | **Built** | Derived from `BTCPlusMainnetMinter`; §5.1 |
| `SolvBTCMainnetChannel` | **Built** | Derived from `SolvBTCMainnetMinter`; §3.3 |
| `BTCTxRegistry` | **Built** | The shared replay ledger; §5.3 |
| `PauseController` × 2 | **Built** | Main and fast tier; §7 |
| `SolvBTCDepositor` | Design only | Multi-asset; constraints in §4.4 |
| `BTCPlusXXXChannel` / `SolvBTCXXChannel` | Design only | The fee and cap layering is §6 |

---

## 2. The one asymmetry, and why it is unavoidable

> Both mainnet channels **mint SolvBTC directly**, through the gateway, bypassing `SolvBTCDepositor`.

That breaks the symmetry of "the depositor is the only entry point for minting". It is not an oversight but
a physical constraint:

**A depositor's model is "receive an ERC20, mint a token". A Bitcoin mainnet deposit has no EVM asset to
receive.** The deposit sits in a custody address on the Bitcoin chain, and the only thing on the EVM side
that can attest to its existence is a verifier's signature.

**Conclusion: the allowance layer only needs to constrain the authorisation-driven entry points.** Putting an
allowance inside each channel would scatter it; one gateway in front of SolvBTC meters every channel in one
place.

The authorisation-driven entry points are two contract types, and the gateway meters per address rather than
per type. Adding a channel is configuration — an entry at the gateway, at the registry and, for BTC+, at
the depositor — with no change to any contract and no second grant on the token.

---

## 3. SolvBTCMintGateway

### 3.1 Why it exists

SolvBTC is hard-pegged 1:1 and accepted at face value across the whole ecosystem — bridges, LP pools,
lending markets. Its `SOLVBTC_MINTER_ROLE` is the most valuable authority in the system, and the loss
surface if it is compromised is far larger than BTC+'s.

**So: converge SolvBTC's minter role into exactly one contract.**

```
BTCPlusMainnetChannel ─┐  authorisation-driven → strict per-channel allowance
SolvBTCMainnetChannel ─┼─→ SolvBTCMintGateway ──→ SolvBTC
SolvBTCDepositor ──────┘  asset-driven (designed, not built)
```

The gateway cannot enforce that it is the only holder: SolvBTC's own administrator decides who holds that
role. Sole holding is a deployment property to be verified on chain, not an invariant of the code (S2.7).

Even though the asset-driven `SolvBTCDepositor` needs no allowance of its own, bringing it in behind the
gateway is still recommended, for **external observability**: watching one contract shows every SolvBTC
issuance. Spread across several contracts, monitoring needs several subscriptions and an update every time
an entry point is added.

> ⚠️ One more contract is one more thing to audit, and that is a real cost. It is still worth paying,
> because a channel's allowance layer is **safety-critical infrastructure rather than an optional
> optimisation**. Separating it means future entry points need no change to the channel code and — more
> importantly — no second `grantRole` on the SolvBTC token. **Granting a minter role on the token is the
> most sensitive operation in the whole system; do it as few times as possible.**

### 3.2 The rate-limit model: a per-transaction cap plus a token bucket with linear refill

The model descends from `sft-wrapped-token/contracts/BTCPlusRedeem.sol` (itself from LayerZero's
`RateLimiter`), with the field names rewritten for minting semantics. It is written once, in
`ChannelRateLimiter`, and inherited by both the gateway and the depositor. Two reasons for that lineage:

1. **Symmetry with the redemption side** — the same limiting semantics and the same operational mental model
   on the way in and the way out, so the parameters need no re-explanation.
2. **Linear refill beats a fixed window** — the allowance recovers continuously, and no instant ever offers
   more than one bucket, where a fixed window offers twice the allowance in a single block at its boundary.
   It costs two stored variables and is far simpler than a bucketed window.

Two levels of limit:

| | Purpose | Defends against |
| :--- | :--- | :--- |
| `maxSingleAmount` | Per-transaction cap | One abnormally large mint, leaving monitoring a window to react |
| `maxWindowAmount` + `window` | Bucket capacity, refilling linearly at `maxWindowAmount / window` — a full bucket allows `maxWindowAmount × (1 + Δt / window)` over an interval Δt (SOLV-1) | Many small mints accumulating past the per-transaction cap |

**Authorisation and metering are one mapping.** `window == 0` means unauthorised; there is no way to be
authorised without a limit, or limited without being authorised.

**Where it departs from `BTCPlusRedeem`**, and why:

- **One setter, validated in both directions.** `BTCPlusRedeem` checked `single < window` on one of its two
  setters and not the other, so the window allowance could be set below the per-transaction cap, making the
  latter meaningless. Here a single setter requires `maxSingleAmount < maxWindowAmount`, and also
  `maxWindowAmount ≤ MAX_WINDOW_AMOUNT` and `window ≥ MIN_WINDOW` (§9.6).
- **Usage is carried over, never clamped.** Lowering an allowance below the outstanding usage, or revoking
  the channel, leaves that usage on record, so revoking and re-authorising cannot hand back a full bucket
  (SOLV-4).
- **Usage above a lowered allowance expires.** It expires in full one window after the channel's most recent
  checkpoint; any reconfiguration in between, including re-setting identical values, restarts that clock.
  While a channel is revoked, its usage neither decays nor expires (SOLV-9). This is the expiry branch of
  LayerZero's `RateLimiter`, which `BTCPlusRedeem` replaced with the clamp.

**Kept from `BTCPlusRedeem`: the checkpoint.** Every reconfiguration first settles the outstanding usage at
the **old** decay rate and only then writes the new parameters, or the new rate would be applied
retroactively to historical usage.

### 3.3 SolvBTC's own mainnet channel

`SolvBTCMainnetChannel` is derived from the audited `SolvBTCMainnetMinter` and keeps its authorisation half
— the verifier signature, the OP_RETURN binding, per-minter caps, and the forced exclusion of verifier and
minter — with these departures: the signed structure drops `chainId` and `token`, which the EIP-712 domain
already binds (S3), and binds the submitting minter to `msg.sender` (SOLV-8); `expireTime` is bounded from
above by `MAX_SIGNATURE_VALIDITY` = 14 days; the pause reference is immutable (SOLV-5); and the replay
record lives in the shared registry rather than in the channel (§5.3).

What changes is where the minting right lives. The channel holds no role: it mints through the gateway,
straight to the recipient, in a single leg. SolvBTC is the destination asset, so there is no NAV and no
depositor in the path, and because the channel is never in the custody path it holds no balance and has no
rescue function.

**The earlier minters.** The registry starts empty and nothing is imported into it (§5.3). The earlier
`SolvBTCMainnetMinter` deployment never held a minter role; the contracts that actually paid out deposits are
the V1 minter on SolvBTC and NavMinter on BTC+. Their signatures cannot be replayed on the new channels: the
EIP-712 domain binds the verifying contract, and the typehash differs. A deposit they already paid could be
minted again only if the verifier signed a fresh request for it, and the signing service's own deduplication
prevents that.

---

## 4. BTCPlusDepositor

### 4.1 Four implementation choices, each with a reason

**(a) `safeTransferFrom(msg.sender → vault)`, never through the contract itself.**
Assets move straight from the channel to the vault, so the depositor never custodies anything. There is no
pending balance, no sweep procedure, and therefore no attack surface around one. **This is why it has no
`rescueToken`** — adding one would widen the owner's authority for nothing.

**(b) Assets first, shares second.**
Inside an atomic transaction the order does not change the result, but it makes "assets received → shares
issued" an inseparable pair:

> **Invariant I1**: every `Deposited` corresponds to an equal amount of SolvBTC arriving in `vault` and to
> BTC+ issued at the same block's NAV. BTC+ cannot be issued without assets having moved.

**(c) The NAV check lives here in its entirety; the channel does not recompute it.**
`_checkNavAndConvertToShares` is `BTCPlusMainnetMinter`'s pricing logic, returning the execution NAV
alongside the shares (SOLV-6), with errors that carry the values that failed (S2). The channel verifies the
signature and passes the signed `nav_` down; it does not read the oracle or compute shares.

That is what makes the layering clean: **pricing logic exists in exactly one place.** Having the channel
compute an `expectedAmount` independently and compare it against the depositor's output would maintain the
same pricing logic in two contracts — not a check (the same logic run twice), and a lockstep upgrade forever.
For the same reason there is no `minBTCPlusAmount_` parameter.

**(d) The depositor is rate-limited too, even though it is asset-driven.**
§2 argued that asset-driven entry points need no allowance layer — but that argument assumes **the
depositor's code executes correctly**. The rate limit defends against that assumption failing, for three
independent reasons:

1. **When `setVault` is repointed at an attacker, the rate limit is the only speed bump.** This is the most
   dangerous single operation in the system: afterwards, every subsequent deposit's SolvBTC goes straight to
   the attacker while BTC+ is issued as usual, and BTC+ instantly becomes an unbacked asset. The rate limit
   turns "one transaction drains everything" into "each channel's bucket plus its refill", leaving time for
   monitoring and for the pause.
2. **Symmetry with redemption.** `BTCPlusRedeem` limits outflow but not inflow; that asymmetry is itself
   something an auditor would raise.
3. **It must be per channel, or a public channel creates a DoS.** With a shared allowance, anyone could
   repeatedly make small deposits through a public `BTCPlusXXXChannel` to exhaust it and **starve the BTC
   mainnet deposit path**. Metering per caller keeps channels independent.

The limit is denominated in **SolvBTC deposited**, not BTC+ shares issued: the same unit as the gateway's,
and it does not drift with the NAV — otherwise a rising NAV would let an equally valuable deposit consume
progressively less allowance.

### 4.2 Dimensions

`getSharesByValue(value)` takes its argument in **the NAV's underlying currency decimals**
(`getOracleDecimals()`, from the SFT slot's currency), which is not necessarily SolvBTC's 18 and not
necessarily BTC+'s own decimals either.

The design requires the oracle's decimals to equal SolvBTC's, so that `getSharesByValue(solvBTCAmount)` is
dimensionally sound with no conversion — and `minterCaps`, both rate limits and the NAV band are all
denominated in that unit. It is a property of a particular BTC+ deployment, not of the code, so it is checked
rather than assumed: deployment preflight refuses a BTC+ whose `getOracleDecimals()` differs from SolvBTC's
`decimals()`. On another chain BTC+ is a different deployment and the check runs again.

### 4.3 One vault per depositor

Each depositor has **one** Safe multisig — one for BTC+, one for SolvBTC. Deposits are not split by input
asset, so `vault` stays a single `address` with a single setter.

### 4.4 `SolvBTCDepositor` (designed, not built)

Structurally symmetric to `BTCPlusDepositor`, with three substantive differences:

| | `BTCPlusDepositor` (built) | `SolvBTCDepositor` (designed) |
| :--- | :--- | :--- |
| Input asset | **One**: SolvBTC | **Several**: wBTC / cbBTC / FBTC…, added and removed dynamically |
| Conversion | Realtime NAV, `getSharesByValue` | **1:1**, decimals alignment only |
| Target token | BTC+ (NAV-bearing) | SolvBTC (no NAV) |
| Vault | BTC+'s Safe | SolvBTC's Safe (a different one) |

Two things multi-asset support must get right:

1. **The direction of decimals conversion.** wBTC has 8 decimals, SolvBTC has 18. `8 → 18` is a
   multiplication and loses nothing; an asset with more than 18 decimals would mean division, which
   truncates. Where the remainder goes must be stated, and `amount` must not be allowed to round to zero.
2. **What disabling an asset means.** It affects future deposits only; assets already in the vault are
   untouched. Write that down, or it will be read as "can be withdrawn".

**The two depositors stay separate contracts and are not generalised.** The number of input assets, the
conversion logic and the risk level (SolvBTC is a hard ecosystem-wide asset) all differ; forcing an
abstraction would complicate both and blur the audit boundary.

---

## 5. The mainnet channels

### 5.1 `BTCPlusMainnetChannel`: BTC+ goes straight to the user, not via the channel

The channel runs two legs: the gateway mints SolvBTC into the channel, then the depositor takes that SolvBTC
into the vault and issues BTC+. The depositor's interface takes a `receiver_` and mints BTC+ directly to the
final recipient. Benefits: one fewer ERC20 transfer; the channel never holds BTC+; and minting and delivery
become one step with no intermediate state where BTC+ sits in the channel. The channel can still be left
holding SolvBTC that a third party sent it, which is why this channel — and only this one — has
`rescueToken`.

The cost is that `mintedAmount` must come from the depositor's return value rather than a balance
difference — `to_` is an external address and anyone can transfer 1 wei of BTC+ between the two reads to
knock the transaction out. That cost is acceptable here: the depositor is our own contract, is not
upgradeable, and its return value is exactly the local variable it minted, so there is no room to
misreport. (If the downstream contract were external, the balance difference would be the correct choice.)

### 5.2 No common base class

`SolvBTCMainnetChannel` and `BTCPlusMainnetChannel` share their whole authorisation half, and a
`MainnetChannelBase` was considered. **Rejected, for three reasons:**

1. **There are two authorisation-driven channel contracts, and that number does not grow with the number of
   channels** — a new channel is another deployment of one of them (§5.4). A base class's value grows with
   the number of subclasses; two is where it pays least.
2. **Each is read as a diff against its own audited baseline**, `SolvBTCMainnetMinter` and
   `BTCPlusMainnetMinter`. A base class would trade two short diffs for a new hierarchy to audit from
   scratch.
3. **What differs is not small.** The `nav` field makes the TYPEHASH and the verification arguments differ,
   and the settlement halves have nothing in common: one leg straight to the recipient and no balance,
   against two legs, a balance check and a rescue function. A base class would either have to make signature
   verification virtual (leaving only replay protection and caps shared) or force a single signature
   structure, which changes the off-chain side.

> The asset-driven XXX channels are a different matter — they will grow in number and share fee and cap
> logic (§6), so **that family is worth a base class**.

### 5.3 Replay protection: one shared registry

Every mainnet channel spends its deposit's `btcTxHash` at a single `BTCTxRegistry`, not in a mapping of its
own. Per-contract storage is sufficient for exactly as long as there is one minting contract and it lives
forever, and neither holds here:

1. **More than one channel at a time.** Several channels accept deposits into the same bitcoin reserve, so
   with per-contract storage the same deposit could be minted once through each.
2. **Redeployment.** These contracts are not upgradeable, so changing anything in a channel means deploying
   a new one — which, with per-contract storage, would start life believing no deposit had ever been minted.

The registry is deliberately the smallest thing that can hold that invariant: one mapping, no external
calls, no token balance, no pause, not upgradeable. **It starts empty, and no function imports, modifies or
deletes a record**; `consume` is the only writer, one hash at a time, and it records which channel consumed
the hash as well as the receiver (S1). An import function would be a power to mark arbitrary deposits spent
— a permanent denial-of-service lever over specific user funds — and a release function would make replay
protection revocable by the owner, which is the same as not having it.

**The owner has no direct write path; it decides who does** (SOLV-7). `setChannel` accepts any non-zero
address, and an authorised address can consume any unused hash, making that deposit permanently unmintable.
The registry verifies neither that its caller is a channel nor that a mint accompanies the consumption, so
the authorisation is the trust boundary, not bookkeeping around one.

**What sharing costs.** A channel whose minter and verifier are both compromised can burn hashes belonging to
deposits routed to another channel, by minting against them. It cannot steal those deposits — what it mints
is still bounded by its own limits — so the result is denial of service on specific deposits, not loss.
Withdrawing its registry authorisation stops it. That is the right side of the trade: without a shared
registry the same attacker could re-mint every deposit the system had ever processed.

**The registry is never replaced.** Its ledger is the replay protection; a fresh registry would treat every
spent deposit as unspent.

### 5.4 Channels and tiers

A channel is a named deployment of one of the two channel contracts, with its own verifier, minter, minter
cap, rate limits and pause tier. Any number of channels may share a token and a tier. Two tiers exist, and a
tier is the same contract configured differently:

| | Fast tier (`fast`) | Manual tier (`main`) |
| :--- | :--- | :--- |
| verifier | An automated signing service's key (KMS) | A Fordefi MPC vault with a multi-approver policy (off chain) |
| minter | The automation's address | A Safe multisig |
| Limits | Small | Large |
| PauseController | **Its own instance** | The main controller, shared with the gateway and depositor |

The fast tier is the one whose keys live in a service, so "the automation may be compromised" is the scenario
it is shaped around: it can be paused on its own while the manual tier keeps settling (§7). The multi-approver
step of the manual tier happens inside Fordefi's policy engine and is not verifiable on chain; to the
contract, that verifier is an ordinary EOA.

The tiers are separate deployments rather than one contract with two parameter sets. One contract would share
a verifier, the owner entry points and a pause switch between them, leaving rate limiting as the only layer
of separation.

Every channel has a bucket of its own at each limiter, so **the system-wide issuance bound is the sum across
channels** (§9.6), and authorising a channel raises it.

---

## 6. Fees and caps, and why they belong at the channel layer

### 6.1 The layering principle

"Different channels have different fees and caps" already decides where they go: **any parameter that varies
per channel must live at the channel layer.** The depositor is a singleton shared by every channel, so a fee
rate placed in it becomes a global fee rate.

From which a hard rule follows:

> **The depositor never charges a fee.** It mints shares for whatever it receives, at the NAV, all of them
> to `receiver_`. Fees are taken at the channel layer, so what reaches the depositor is already net.

That rule is enforced by **non-upgradeability** (§9.2), not by a runtime check on the channel side: the
depositor's logic is fixed once deployed, and adding a fee would require redeploying it, which drags in
redeploying the channels and another audit. A fee change therefore cannot ship quietly.

### 6.2 Charge on the way in, not on the way out

| | How | Assessment |
| :--- | :--- | :--- |
| **Input side (chosen)** | User deposits 100 SolvBTC → the channel takes 0.1 for the treasury → 99.9 goes to the depositor → the user gets `99.9/NAV` in BTC+ | The fee is denominated in SolvBTC and does not involve the NAV; invariant I1 holds strictly |
| Output side | All 100 goes to the depositor → `100/NAV` is minted → the channel takes 0.1% of the BTC+ for the treasury | The fee is denominated in shares and floats with the NAV; part of what the depositor minted does not belong to `receiver`, which breaks the clarity of "value received = value deposited" |

Charging on the way in has a practical benefit too: the treasury receives SolvBTC rather than BTC+, so it
does not have to redeem to realise it.

### 6.3 Three kinds of "cap" that must not be conflated

| Cap | Where | Nature | Reason to change it |
| :--- | :--- | :--- | :--- |
| `minterCaps` | Mainnet channel | **Security** — the per-transaction cap for one minter address (a mint needs `amount ≤ cap`; it is not cumulative) | Key risk |
| Gateway / depositor allowance | Gateway, depositor | **Security** — the blast radius if an authorisation-driven entry point is compromised | Contract risk |
| Subscription cap | XXX channel | **Product** — strategy capacity, pacing | Business capacity |

Tightening the first two is loss mitigation; tightening the third closes the business. Confusing them means
that in an incident the wrong one gets closed and the right one does not.

### 6.4 No on-chain fees in the mainnet channels

The mainnet channels implement no fee rate, keeping the diff against their baselines minimal. If fees are
wanted, **deploy a new channel contract** rather than adding upgradeability to this one — which pairs with
the non-upgradeability decision in §9.2: a channel holds no historical assets and no replay state, so it can
be replaced smoothly, and trading redeployment for the stronger property of immutable logic is a good deal.

---

## 7. Settled decisions

- **Channels hold no token privileges; SolvBTC minting converges on the gateway** (§2, §3).
- **The depositor is open only to authorised channels.** It is not a public subscription entry point. **The
  whitelist and the rate limit are one mapping**: `window == 0` means unauthorised — one less piece of state
  and one less pair of settings that can fall out of sync. Revoking is setting `window` back to 0, which is
  the same action as setting the allowance to zero, at a different intensity.
- **The minting side adds no NAV logic of its own.** The depositor converts at BTC+'s realtime NAV, the
  same one BTC+ itself reports (§9.5).
- **Two pause controllers, split by tier.** The main controller is read by the gateway, the depositor and
  the manual-tier channels; the fast controller only by the fast-tier channels. Every channel mints SolvBTC
  through the gateway, so pausing the main controller stops every mint in the system; pausing the fast one
  stops the fast tier and nothing else. Both belong to the emergency multisig (§8.3). There is no meaningful
  scenario for "pause the depositor but keep its channels running", so the depositor shares the main
  controller rather than having one of its own.
- **Every pause reference is immutable** (SOLV-5). There is no setter through which an owner could point a
  contract at a controller that never reports "paused", and no way for the topology to drift by updating some
  consumers and not others. Rotating the emergency signers is `transferOwnership` on the controller itself.
  `pauseBurn()` has no reader in this system: it stops nothing, and the flag it sets persists, so it is not
  to be used. `pauseMint()` is the entire emergency surface.
- **Channel references are immutable too.** A channel's gateway, depositor and registry are fixed at
  construction. Making them settable would turn "redeploy and re-authorise" into a single multisig call — and
  for the registry, one such call would point the channel at an empty replay store.

---

## 8. Governance: zero delay at launch, a timelock later, never for the emergency stop

At launch the governance Safe owns every contract except the two pause controllers, **with zero delay**: its
threshold signature is the control, and every owner operation takes effect when the Safe executes it.
Migrating that ownership to a 72-hour OpenZeppelin `TimelockController` is planned for later. The emergency
multisig owns both pause controllers from the first block, and keeps them across the migration.

### 8.1 How the migration works: change nothing in the contracts, only who the owner is

```
                    ┌── governance path after the migration (delayed) ──┐
Governance Safe ─(propose)─→ TimelockController ─owner─→ Channels / Depositor / Gateway / Registry
Emergency multisig ── owner ──→ PauseController × 2 ──→ read by the gateway, depositor and channels
```

At launch the Safe is the owner directly, and the timelock is not yet in the path.

The benefit is that **not one line of code changes**: once the timelock is the owner, every `onlyOwner`
operation gets the delay automatically, and `pauseMint()` keeps zero delay because it hangs off a different
contract with a different owner. No hand-written propose/execute in each setter, and therefore no bugs in a
home-made two-phase mechanism.

> ⚠️ Handing ownership to the timelock is the watershed: after it, every configuration change waits out
> the delay, including one that would undo it. Complete all configuration and verify it item by item first,
> and verify the timelock's role configuration before transferring — **getting it wrong means permanently
> losing control of every contract.** The migration moves the system contracts and **not** the pause
> controllers, or pausing would inherit the governance delay.

### 8.2 Containment, before and after the migration

At launch the Safe's own containment is immediate: it can stop a channel — revoke its rate limit at the
gateway and, for a BTC+ channel, the depositor, and withdraw its registry authorisation — zero a minter's
cap, or lower a limit, all in the block it executes.

After the migration that changes. `setChannelRateLimit` is one function whether it loosens or tightens, so
*lowering* an allowance — a loss mitigation — also waits out the delay. That is acceptable because
`pauseMint()` has zero delay and is more thorough. The correct action on spotting something wrong is to pause
first (stopping all minting immediately), then adjust parameters at leisure. **"Lower the allowance" is not
the emergency action; "stop" is.**

A guardian role that can only lower and never raise is not built: another role is another chance to
misconfigure something.

### 8.3 Why the emergency multisig is independent

**The emergency multisig is a separate multisig, independent of governance.** Deployment requires
`emergencyOwner ≠ owner`, and refuses a pause controller owner with an execution delay. Because every pause
reference is immutable and the controllers belong to the emergency multisig, a compromised governance Safe can
neither lift a pause nor route a mint around one.

That independence is what the response to a governance compromise rests on:

| | At launch (zero-delay Safe) | After the timelock migration |
| :--- | :--- | :--- |
| A malicious owner action | Takes effect when the Safe executes it, visibly on chain | Is queued for 72 hours, visibly on chain |
| The response | `pauseMint()` by the emergency multisig: no mint after it, but what was already minted stays minted | `pauseMint()` inside the delay, so that nothing mints when the action takes effect |
| Until the response | **Not bounded on chain in aggregate**: the owner can authorise any number of addresses, each with a full bucket (§9.6) | The delay |

After the migration the proposer and canceller are both driven by the governance Safe. That matters: **if the
Safe is fully controlled, the timelock provides delay but not interception** — an attacker will not cancel
their own proposal. The canceller protects only against mistakes or misdirection inside the Safe, and the
emergency multisig remains the only response that does not depend on governance.

> ⚠️ Independence is a property of people, not addresses. Whether the two multisigs' members overlap cannot
> be checked on chain, and membership changes routinely, so "no overlap" can quietly stop being true as
> people move. It belongs on a periodic security review.

---

## 9. Security analysis

### 9.1 Trust model

| Role / dependency | Trusted to | Constrained by |
| :--- | :--- | :--- |
| **Owner** (the governance Safe; a 72h `TimelockController` after the planned migration) | Authorise addresses at the gateway, depositor and registry; set the verifier, minter caps, vault and rate-limit parameters. Not the pause controllers: their references are immutable (SOLV-5) and they belong to the emergency multisig | `Ownable2Step`; the Safe's threshold. At launch every operation takes effect immediately; after the migration every operation is delayed and cancellable. `MAX_WINDOW_AMOUNT` bounds each limit it sets, not the owner: it can authorise any number of addresses (§9.6) |
| **Emergency multisig** | Emergency stop | Pause and unpause only, **zero delay**; cannot change any parameter or mint. Independent of governance (§8.3) |
| **Verifier** | Attest that a BTC deposit happened, its value, and (for BTC+) a NAV quote | `minterCaps`; `expireTime ≤ now + 14d` (**this bounds the window remaining at submission, not the age of the signature**); **mutually exclusive with the minter**. Checked with OpenZeppelin's `SignatureChecker`, which dispatches on `code.length` (since OZ 5.1.0): a verifier address that gains code (EIP-7702 delegation) is checked through ERC-1271 only, so its ECDSA signatures stop validating unless the delegate's `isValidSignature` accepts them |
| **Minter** (a Safe multisig on the manual tier; the automation's address on the fast tier) | Submit already-authorised mints | Per-transaction `minterCaps`; cannot mint without a verifier signature, and the signature names the minter that may submit it (SOLV-8) |
| **Channel contract** | Execute delivery correctly | No token privileges; bounded by its rate limit at the gateway and, for a BTC+ channel, at the depositor |
| **Gateway contract** | Meter per channel, then mint SolvBTC | ⚠️ Holds SolvBTC's minter role; blast radius = the sum over authorised addresses of `maxWindowAmount × (1 + Δt / window)` — capacity plus refill (SOLV-1) |
| **Depositor contract** | Convert at the realtime NAV, send assets to the vault | ⚠️ Holds BTC+'s minter role; callable only by authorised channels; the vault is changeable |
| **Registry** | Record each `btcTxHash` once | The owner decides who may consume; an authorised address can mark any unused hash spent (§5.3, SOLV-7) |
| **NAV oracle** | Report the realtime NAV | See §9.5 — **this is an external trust assumption, not something the contracts verify** |
| **Safe vault** | Hold the reserve | The multisig threshold; **the contracts cannot verify it is still under control** |

### 9.2 Nothing is upgradeable

Every contract in the system — the channels, the gateway, the depositor, the registry and the pause
controllers — is non-upgradeable. For the contracts that hold minting rights the reason is direct: **a
contract that holds minting rights and is upgradeable makes its proxy admin equivalent to unlimited minting
authority.** One `upgradeTo` erases every rate limit and every check, in one transaction.

The cost is that changing anything means redeploying and re-authorising. For a channel that cost is low: it
holds no assets on the normal path and no replay state (that is the registry's), so replacing one is
deployment gas, configuration, and coordinating the off-chain switch of `verifyingContract`. **No funds are
at risk in replacing one.** What else has to move when a contract changes, and why the registry never
does, is in §10.

### 9.3 Privileged operations and their worst outcomes

Every row but the last is an owner operation: it takes effect immediately at launch, and after the timelock
migration it waits out the 72-hour delay.

| Operation | Contract | Worst outcome | Mitigation |
| :--- | :--- | :--- | :--- |
| `setVault` | Depositor | Every subsequent deposit's SolvBTC goes to the attacker; BTC+ becomes unbacked | The depositor's per-channel rate limit, `SetVault` alerting, `pauseMint` |
| `setChannelRateLimit` (grant, loosen) | Gateway / Depositor | Authorises an address to mint, or raises a channel's allowance up to the ceiling | `MAX_WINDOW_AMOUNT` and the `MIN_WINDOW` floor (SOLV-2) bound each address's limit, not how many addresses there are; outstanding usage is carried over, not forgiven (SOLV-4). Metering cannot be removed, only the channel revoked |
| `setChannelRateLimit` (tighten, revoke) | Gateway / Depositor | — (this is the mitigation) | Usage left above a lowered allowance expires in full one window after the channel's most recent checkpoint; any reconfiguration in between, including re-setting identical values, restarts that clock. While revoked, usage neither decays nor expires (SOLV-9). After the migration, use `pauseMint` in an emergency (§8.2) |
| `setChannel` | Registry | Authorises an address that marks arbitrary deposits spent, making them permanently unmintable (denial of service, not theft) | Revoking it is part of stopping a channel |
| `setVerifier` | Channel | Forge any BTC deposit attestation | A minter must still submit, and the signature names it |
| `setMinterCap` | Channel | Grant submission rights to an attacker's address | A verifier signature naming that minter is still required |
| `transferOwnership` | Every governance-owned contract | Everything above | `Ownable2Step`'s two-step acceptance |
| `renounceOwnership` | Every governance-owned contract | Configuration frozen for good: no limit, key or vault can change again | Not overridden. Renouncing needs the owning multisig's threshold signature, and the multisig is the control |
| `rescueToken` | `BTCPlusMainnetChannel` only | Take stray tokens off the channel | No balance on the normal path |
| **`pauseMint`** | PauseController | Stops minting (availability, not loss of funds) | Emergency multisig, **zero delay**, never behind a timelock |

### 9.4 Single-point compromise

| Compromised | What the attacker can do | Loss bound |
| :--- | :--- | :--- |
| **Minter** (alone) | **Nothing** — there is no verifier signature | 0 |
| **Verifier key** (alone) | **Nothing** — it cannot submit, and it is forcibly exclusive with the minter | 0 |
| **Verifier + minter** of one channel | Forge a BTC deposit and mint; burn other channels' deposit hashes (§5.3) | That channel's bucket at each of its limiters, `maxWindowAmount × (1 + Δt / window)`, the tighter one binding: up to twice the capacity across the first window, the capacity per window thereafter. `minterCap` and `maxSingleAmount` are per-transaction and do not bound the total. See §9.6 |
| **A bug in the channel** | Bypass the verification logic and mint | The same — the rate limits are outside the channel and still apply |
| **A bug in the gateway** | Mint SolvBTC without limit | **Unbounded** — the rate limit lives inside the gateway |
| **A bug in the depositor** | Mint BTC+ without limit | **Unbounded** — likewise |
| **Owner** | Everything in §9.3; at launch, immediately | **Unbounded on chain**: it can authorise any number of addresses at the gateway, each with a full bucket. Contained by the emergency multisig's `pauseMint`, which it can neither lift nor route around (§8.3) |
| **Emergency multisig** | Pause, or lift a pause | Availability only: it can change no parameter and mint nothing |
| **NAV oracle** | Report a low NAV and over-mint BTC+ | **Not bounded on chain** — the rate limit meters SolvBTC in, not BTC+ out (SOLV-3). Contained off chain by the verifier's NAV checks, and by pausing; see §9.5 |

**The most important row is "minter alone = zero loss."** The forced mutual exclusion of verifier and minter
(`MinterCannotBeVerifier` / `VerifierCannotBeMinter`) makes minting a two-person control. That property is
inherited from `SolvBTCMainnetMinter` and kept unchanged in both channels.

> ❗ **The signer sets must be genuinely independent.** If the governance Safe, the emergency multisig, the
> minter and the verifier share signers, two-person control degenerates into one-person control. The
> contracts cannot detect it: `setMinterCap` only blocks "minter and verifier are the same address", and
> deployment preflight extends that to the owner, emergency owner and vault — still addresses, not "the same
> people are behind both". Put every signer set in the deployment checklist and review them periodically.

**The two middle rows show the structural limit of rate limiting**: it protects what is **downstream** of
it, never itself. The gateway's and depositor's correctness rests on minimal code, audit, and
non-upgradeability — which is exactly why they are small, single-purpose, and have no upgrade entry point.

### 9.5 The NAV oracle: a responsibility boundary

**The verifier's `nav_` is not an independent observation.** It is read from the same on-chain oracle the
depositor reads at execution:

```
When the verifier signs:   nav_        = oracle.getNav()
When the channel executes: realtimeNav = oracle.getNav()
The band check:            |nav_ - realtimeNav| <= 1% * realtimeNav
```

Both compared values come from the same source. If the oracle reports an extremely low NAV, the verifier
reads it, signs it, execution reads the same value, `navDiff == 0`, the check passes perfectly, and
`getSharesByValue` mints an inflated number of shares at the low NAV.

> ❗ **`MAX_NAV_DEVIATION_BPS` provides zero protection against an oracle that fails or is manipulated.** All
> it detects is how far the NAV drifted between quote and execution.

**The oracle's correctness is the oracle's responsibility; the minting side adds no second on-chain layer of
risk control.** On-chain NAV controls — a high-water ratchet, bidirectional rate-of-change limits, absolute
floors and ceilings — are rejected. The root reason is that **minting conserves value at a true NAV**: a user
deposits X of value and receives X of value in shares. If the NAV genuinely fell, continuing to mint means
newcomers buy at the current value and existing holders are not diluted — **nobody is harmed.**

So halting minting is only meaningful when the NAV is *wrong*, and a contract cannot tell wrong from real. It
can only guess, by speed or by absolute value, and every guess trades **business downtime** for a margin it
cannot quantify. A movement limit sampled at deposits shows the problem concretely: it blocks the oracle's
ordinary daily step after a recent deposit and still passes a stale, unchanged value. And the rate limit is
no substitute (SOLV-3): it meters the SolvBTC deposited, and a falsely low NAV changes how many BTC+ shares
that deposit mints without touching the meter.

**What the deviation check is retained for** is one thing only:

> Guarantee that the NAV has not moved materially between the **quote** and the **execution**.

For a mainnet channel that means **signature freshness** — if the NAV has drifted a lot since signing,
refuse and require re-signing. For an asset-driven channel the same check would mean **slippage protection**,
with the quote moment becoming when the frontend read the NAV. Neither claims to defend against oracle
manipulation.

1% is appropriate for that job: at 5% annualised the NAV moves about **0.0137% per day**, far below the band,
so ordinary business is almost never caught by it — while a 1% move is a material price difference for the
user and worth refusing and re-quoting. The band and `MAX_SIGNATURE_VALIDITY` are coupled: a signature valid
for 14 days stays inside a 1% band only while BTC+ yields less than about 26% a year.

**BTC+'s NAV can go down; it is not monotonic.** The design does not depend on monotonicity (the deviation
check is bidirectional). It is also why shares are priced at the realtime NAV rather than the quoted one:
pricing at the quote would be wrong whichever way the NAV moved — a rise dilutes existing holders, a fall
harms the new depositor.

The residual exposure, stated explicitly:

| | |
| :--- | :--- |
| **Trust assumption** | The NAV reported by BTC+'s oracle is correct. External; the minting side does not verify it |
| **Loss bound if the oracle or the calculation system is compromised** | **None on chain** (SOLV-3). `maxWindowAmount × (1 + Δt / window)` per channel bounds the SolvBTC deposited, not the BTC+ minted from it |
| **Containment** | Off chain: the verifier refuses to sign against a zero, future-dated, stale or abnormally moved NAV. That is the signing service's responsibility (§9.9) |
| **Emergency measure** | `pauseMint()`, zero delay, the emergency multisig |

### 9.6 The hard ceiling: `MAX_WINDOW_AMOUNT = 100 BTC`

Governance and the emergency multisig give people **the chance to intervene**; the hard ceiling bounds a
channel **without anyone intervening**. The first depends on monitoring quality and response speed; the
second is a pure code guarantee — and it is precisely a guarantee about **one channel at one limiter**.

**One constant is enough; there is no `MAX_SINGLE_AMOUNT`.** The contract enforces
`maxSingleAmount < maxWindowAmount` and `maxWindowAmount ≤ MAX_WINDOW_AMOUNT`, so the per-transaction cap is
bounded automatically. One less constant is one less place to misconfigure. Its companion is `MIN_WINDOW` =
1 day (SOLV-2): the constant bounds the bucket, and without a floor on `window` a compliant bucket would
still permit any refill rate.

**What the number bounds, precisely.** The limiter is a **token bucket**: capacity `maxWindowAmount`,
refilling continuously at `maxWindowAmount / window`. Cumulative issuance on one channel over an elapsed
`Δt`, with the parameters unchanged and the bucket starting full, is bounded by

```text
issuance ≤ maxWindowAmount × (1 + Δt / window)
```

and that ceiling is *reached*, not merely respected:

| Elapsed | Ceiling |
| :--- | ---: |
| one block | 1 × `maxWindowAmount` |
| half a window | 1.5 × `maxWindowAmount` |
| one window | 2 × `maxWindowAmount` |
| three windows | 4 × `maxWindowAmount` |
| each further window | + 1 × `maxWindowAmount` |

So the guarantee that depends on no human response at all is: **whatever happens to a channel's keys, and
with nobody pausing, that channel cannot issue more than its bucket plus one window's refill per window** —
across the first window, twice its capacity, not once. It is **not** a bound on the owner, which can
authorise more addresses, each with a full bucket of its own. Nor is it a system bound: the system-wide bound
is the sum over the channels governance has authorised, at each limiter.

This is what a token bucket is rather than a defect in it, and linear refill remains the right choice over a
fixed window (§3.2): a fixed window permits twice the allowance **in a single block** at the boundary,
whereas here no instant ever offers more than one bucket, so reaching 2× requires spending steadily across a
whole window.

> ⚠️ Three usage notes:
> 1. **`maxWindowAmount` is a burst capacity, not a per-window allowance.** If a flat "≤ X per window" is
>    what is wanted, configure `maxWindowAmount = X/2`. That is the only lever: `MAX_WINDOW_AMOUNT` cannot be
>    changed after deployment, and the bucket cannot be made to start empty — configuring a low limit and
>    raising it later hands over a full bucket at the new level in the same block.
> 2. **The hard ceiling is a ceiling, not a default.** Day-to-day `maxWindowAmount` should sit well below
>    it. A channel configured at the ceiling leaves no margin between its operating limit and the structural
>    one, and the ceiling then bounds nothing the configuration does not already bound. How close any tier
>    runs to the ceiling is a decision taken per channel, in its configuration, with that trade in view.
> 3. **It cannot be changed after deployment.** Raising it means redeploying the gateway and depositor, which
>    drags in redeploying the channels (§10). Set it with one or two years of growth in mind.

### 9.7 External calls, reentrancy, and DoS

```
BTCPlusMainnetChannel.mint  [nonReentrant]
  ├── PauseController.mintPaused                          (view; the channel's tier)
  ├── minterCaps[msg.sender] ≥ amount
  ├── Registry.txReceivers(btcTxHash)                     (view; early replay check)
  ├── SignatureChecker → verifier.isValidSignature        (staticcall, only if the verifier has code)
  ├── Registry.consume(btcTxHash, to)                     replay record, before either leg
  ├── Gateway.mint(channel, amount)  [nonReentrant]        leg 1
  │     ├── PauseController.mintPaused                    (view; main)
  │     ├── allowance charged
  │     └── SolvBTC.mint(channel, amount)
  ├── SolvBTC.balanceOf(channel)                          (view, before and after leg 1; received ≥ amount)
  ├── SolvBTC.forceApprove(depositor, amount)
  ├── Depositor.deposit(amount, to, nav)  [nonReentrant]   leg 2
  │     ├── PauseController.mintPaused                    (view; main)
  │     ├── allowance charged
  │     ├── BTC+.decimals / getValueByShares / getSharesByValue   (view; NAV band, conversion)
  │     ├── SolvBTC.safeTransferFrom(channel → vault)     (vault balance read before and after)
  │     └── BTC+.mint(to, shares)
  ├── SolvBTC.allowance(channel, depositor)               (view)
  └── SolvBTC.forceApprove(depositor, 0)                  only if anything is left approved

SolvBTCMainnetChannel.mint  [nonReentrant]
  ├── PauseController.mintPaused                          (view; the channel's tier)
  ├── minterCaps[msg.sender] ≥ amount
  ├── Registry.txReceivers(btcTxHash)                     (view; early replay check)
  ├── SignatureChecker → verifier.isValidSignature        (staticcall, only if the verifier has code)
  ├── Registry.consume(btcTxHash, to)                     replay record, before the mint
  └── Gateway.mint(to, amount)  [nonReentrant]
        ├── PauseController.mintPaused                    (view; main)
        ├── allowance charged
        └── SolvBTC.mint(to, amount)
```

Every layer commits its state before anything of value moves, and every layer is `nonReentrant`. The channel
writes the replay record before either leg; the gateway and depositor charge the allowance before touching a
token. The registry makes no external calls of its own. The only call to a contract outside the system before
the replay record is written is the ERC-1271 check, and it is a `staticcall`.

The DoS vector that recurs throughout is a **balance difference compared with strict equality**. Whenever a
balance difference is used as a check, ask whether anyone else can change that balance — for the channel's
own balance, the recipient's, and the vault's, the answer is yes in all three cases, so all three use `<` or
a return value rather than `!=`.

If either token refuses a mint — paused, or the minter role missing — the whole transaction reverts, the
replay record with it: minting fails closed, and the deposit stays mintable.

### 9.8 Dependent token misbehaviour

The assumptions are that SolvBTC is not fee-on-transfer and that neither token has transfer hooks. The first
is checked at runtime anyway: the channel verifies what leg 1 delivered (`SolvBTCNotReceived`) and the
depositor verifies the vault's actual receipt (`VaultUnderfunded`), so a short transfer mints nothing. The
second is covered by CEI plus `nonReentrant` regardless of the answer.

### 9.9 What the contracts rely on off chain

These are responsibilities of the signing service and of operations. The contracts do not enforce them, and
none is a gate on deployment.

- **NAV checks.** The verifier refuses to sign against a zero, future-dated, stale or abnormally moved NAV
  (§9.5).
- **One encoding of `btcTxHash`.** The registry compares 32-byte values and nothing else, so one deposit
  encoded two ways would be two different keys. The encoding is fixed by the signing service and shared by
  both tiers.
- **The verifier key never signs an EIP-7702 authorisation.** A delegated verifier is checked through
  ERC-1271 only (§9.1), which hands signature validity to the delegate. Custody is a Fordefi MPC vault on the
  manual tier and KMS on the fast tier.
- **Monitoring and reconciliation.** The registry's `Consumed`, the gateway's `Minted` and the depositor's
  `Deposited` events, reconciled against the vault's reserves and BTC+ issuance. The vault must stay inside
  the asset aggregation BTC+'s NAV is computed from: a `SetVault` event means the off-chain configuration
  follows, or the new vault's balance drops out of the numerator and dilution reappears.
- **Deposits above a channel's single-transaction limit.** A deposit is minted in one transaction — its
  `btcTxHash` is spent once — so a deposit larger than `maxSingleAmount` or the minter's cap cannot be minted
  through that channel at all. Such deposits need an operational procedure.

---

## 10. Deployment and operations

### Deployment

**The deploying key holds no authority.** Every constructor names the governance Safe as owner, and the
emergency multisig as the pause controllers' owner, from the first block. A channel that is deployed but not
yet configured has `window == 0` and cannot mint, so nothing is live until the Safe acts.

**The Safe brings a channel to life in one batch:** its registry authorisation, its rate limit at the gateway
and, for a BTC+ channel, at the depositor, and its minter's cap. The minter roles on the two tokens are
granted by each token's admin; SolvBTC's admin is a timelock. Before anything is authorised, every contract
the batch touches is checked to be running the code in this repository.

**One core, any number of channels.** The first deployment creates the core — the gateway, the depositor, the
registry and the two pause controllers — and one manual-tier BTC+ channel. Later channels are added to the same
core, never beside a second one: a second gateway would hold SolvBTC's minter role with a limit nothing caps
against the first's, and a second registry would treat every spent deposit as unspent. Channels are named, and
any number may share a token and a tier.

### Operations

**Every change goes through the governance Safe and is read back from the chain before it is recorded:** a
minter or verifier rotated, a rate limit or minter cap changed, a channel stopped or restarted. A retired
minter or verifier is never reused.

**Incidents.** `pauseMint()` comes first: it needs no batch. A suspected verifier is then replaced with
`setVerifier`, which works while minting is paused. A suspected minter is stopped at once with
`setMinterCap(minter, 0)` and then replaced. A channel taken out of service has its rate limits revoked at the
gateway and the depositor and its registry authorisation withdrawn, in one batch: either one stops a mint,
and a channel retired at one and not the other is an authorisation that outlives its purpose.

### Upgrades

**The contracts are not upgradeable, so an upgrade is a redeployment.** What must move depends on which
contract changed: immutable wiring means a new gateway takes every channel with it and a new depositor every
BTC+ channel, and everything replaced has to be retired — its minter roles revoked, its channels deauthorised
at the registry and given a zero window. **The registry is never replaced**: its ledger is the replay
protection.

---

## 11. Designs that were considered and rejected

If the question is "why didn't they do X", the answer is usually one of these.

| Rejected | The reason |
| :--- | :--- |
| NAV risk controls in the depositor — rate-of-change or movement limits, absolute floors and ceilings, a high-water ratchet, `navFloor`/`navCeiling` | §9.5. A contract cannot distinguish "the NAV really fell" from "the NAV is wrong"; minting conserves value in the first case and dilutes holders in the second (SOLV-3). Halting on an unverifiable signal trades availability for a margin the limiter does not bound — it meters SolvBTC in, not BTC+ out. The checks live in the verifier |
| A `minBTCPlusAmount_` parameter, or expected-value comparison inside the channel | §4.1(c). Pricing converged into the depositor; recomputing it in the channel is the same logic run twice, which is not a check, and forces lockstep upgrades |
| A common base class for the mainnet channels | §5.2. Two contracts is where a base class pays least, each is read as a diff against its own audited baseline, and their settlement halves have nothing in common |
| Per-channel replay tables | §5.3. Several channels share one reserve, and a redeployed channel would start empty |
| An import function on the registry | §5.3. A power to mark arbitrary deposits spent — a permanent DoS lever — in exchange for a history the registry does not need |
| A "release this hash" function on the registry | §5.3. It would make replay protection revocable by the owner, which is the same as not having it |
| Settable gateway, depositor, registry or pause references | §7. "Redeploy and re-authorise" would become one multisig call, and a repointed registry would make every processed deposit mintable again |
| Implementing the two tiers as one contract with two parameter sets | §5.4. They would share a verifier, owner entry points and a pause switch, leaving rate limiting as the only layer of separation |
| On-chain fees in the mainnet channels | §6.4. Deploy a new channel instead; that pairs with non-upgradeability |
| Making any contract upgradeable | §9.2. A minting contract that is upgradeable makes its proxy admin equivalent to unlimited minting authority |
| `rescueToken` on the depositor or the SolvBTC channel | §4.1(a), §3.3. Neither ever holds tokens, so the function would only widen the owner's authority |
| A second constant, `MAX_SINGLE_AMOUNT` | §9.6. `single < window ≤ MAX_WINDOW_AMOUNT` already bounds it |
| A guardian role that can only lower limits | §8.2. Another role is another chance to misconfigure; the emergency action is the pause |

---

*Security contact: dev@solv.finance*
