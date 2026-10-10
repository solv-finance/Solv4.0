# Solv 4.0 — BTC+ / SolvBTC Mainnet Minting

Contracts that turn a deposit on the Bitcoin mainnet into **BTC+** or **SolvBTC** on BSC. A channel verifies
an EIP-712 request signed by its verifier, binds it to the deposit's OP_RETURN, records the Bitcoin
transaction in a shared replay ledger, and mints SolvBTC through a gateway that meters every channel; a BTC+
channel then converts that SolvBTC into BTC+ at the realtime NAV. The channels' authorisation layer (EIP-712
verification, the OP_RETURN binding, replay protection, `minterCaps`) derives from the audited
`SolvBTCMainnetMinter` in
[solv-finance/mainnet-minter-contracts](https://github.com/solv-finance/mainnet-minter-contracts).

## Contracts

| Contract | Responsibility |
| :--- | :--- |
| `SolvBTCMintGateway` | Holds SolvBTC's `SOLVBTC_MINTER_ROLE`; mints SolvBTC for authorised channels and meters each one |
| `BTCPlusDepositor` | Holds BTC+'s `SOLVBTC_MINTER_ROLE`; takes SolvBTC, mints BTC+ at the realtime NAV, forwards the SolvBTC to a Safe vault |
| `BTCTxRegistry` | The single replay ledger for Bitcoin transactions, shared by every channel |
| `BTCPlusMainnetChannel` | Verifies the signed request, mints SolvBTC through the gateway and converts it to BTC+ through the depositor |
| `SolvBTCMainnetChannel` | Verifies the signed request and mints SolvBTC to the user through the gateway, 1:1 |
| `PauseController` | The emergency stop: one instance shared by the gateway, the depositor and the main-tier channels, one for the fast tier |
| `utils/ChannelRateLimiter` | The per-channel rate limit the gateway and the depositor share |

None of them is upgradeable.

## Trust model

At launch a governance Safe owns every contract with no execution delay; moving that ownership to a 72h
`TimelockController` is planned for later. Both PauseControllers are owned by an independent emergency
multisig, separate from governance, so pausing never waits on governance and governance cannot undo a pause.
Each channel has a **verifier**, whose signature authorises a mint, and a **minter**, the address that
submits it and is bound into the signed request; `minterCaps` caps each minter per transaction.

## Rate limit

Each channel is metered at the gateway and, for a BTC+ channel, again at the depositor. The limiter is a
**token bucket** with linear refill: capacity `maxWindowAmount`, refilling at `maxWindowAmount / window`, so
issuance over any interval Δt is at most `maxWindowAmount × (1 + Δt / window)` — up to twice the capacity
across the first window. `maxSingleAmount` caps one transaction and must be strictly below
`maxWindowAmount`. Two constants bound the configuration: `MAX_WINDOW_AMOUNT` = 100 BTC per channel per
limiter, and `MIN_WINDOW` = 1 day.

When an allowance is lowered below a channel's outstanding usage, that usage expires in full one window after
the channel's most recent checkpoint; any reconfiguration in between, including re-setting identical values,
restarts that clock (SOLV-9). While a channel's rate limit is revoked, its usage neither decays nor expires.

## Layout

```
src/            the contracts; utils/ChannelRateLimiter.sol; interfaces/
docs/           MainnetMint-Architecture.md: the design and its security analysis
lib/            OpenZeppelin Contracts and forge-std, as git submodules pinned in foundry.lock
```

## Building

```bash
git clone --recurse-submodules <this repository>
forge build
```

`solc` 0.8.36, `evm_version` `cancun` and the optimizer at 200 runs are pinned in `foundry.toml`, together
with the submodule commits in `foundry.lock`: they decide the deployed bytecode, so building this tree
reproduces it. The target chain must support EIP-1153 transient storage: every guarded entry point uses
`ReentrancyGuardTransient`.

## Further reading

[`docs/MainnetMint-Architecture.md`](docs/MainnetMint-Architecture.md) — what each contract is for, why it is
shaped the way it is, and what the security argument rests on.

---

*Security contact: dev@solv.finance*
