# Full-suite deployer + launch cost

`deploy-suite.sh` deploys the **14 contracts** that make up the dendritic network, in
dependency order, and reports the gas each used. The `AxonTLD` source lives in this
repo (`../tld`); the other 13 live in the sibling `dendritic` checkout
(`proof-of-facilitation/contracts/`). This is a Foundry project; vendor OpenZeppelin
v5 and gather the sources per the header of `deploy-suite.sh`, then:

```sh
RPC=<rpc-url> KEY=<deployer-privkey> OWNER=<deployer-address> ./deploy-suite.sh
```

The constructor args in the script are **placeholders** that deploy cleanly so gas is
measured accurately. For a real launch, replace them with production values (a real
governor/guardian multisig, the fee schedule, the canonical `.axon` TLD node, term/
price/bond parameters), then run the sibling's Hardhat role-wiring
(`deploy/00_phase0` → `01_phase1` → `02_channels`) and the `AxonToken` genesis mint.

## What each contract is

| Contract | Role |
| --- | --- |
| `AxonTLD` | the working `.axon` alias registry the node resolver reads (names → AXON identities, typed records, subdomains, fees, DAO/ICANN TLD admission) |
| `TLDRegistry` | the governed root: namespaces created by vote, each with its own registrar |
| `AxonRegistry` | per-namespace name ownership (commit-reveal, bonds) |
| `NodeRegistry` | wallet ↔ node identity + capability bitmap (CAP_DHT…CAP_EXIT) |
| `AxonToken` | the network ERC-20 (vote weight + pays for names); minted at genesis |
| `Treasury` | holds/mints token under governance |
| `StakeVault` | operators stake AXON to participate/earn |
| `EpochManager` | divides time into reward epochs |
| `ServicePolicyRegistry` | per-service reward split + witness thresholds |
| `RewardDistributor` | pays epoch rewards from receipts |
| `AxonChannels` | off-chain payment channels (needed by the channels + watchtower nodes) |
| `DisputeManager` / `SettlementKeeper` | channel dispute resolution + settlement automation |
| `AxonGovernance` | the on-chain DAO |

## Measured deployment gas (one fresh anvil run)

Total for all 14: **22,267,111 gas**. Largest: `AxonTLD` 4.67M, `TLDRegistry` 4.08M,
`AxonRegistry` 2.52M, `AxonChannels` 2.06M. Add ~2M for role-wiring + token genesis
→ **~24.3M gas** for a full launch.

## Launch cost

At ETH ≈ $2,698 (adjust for current price):

**Ethereum L1**
| gas price | full launch |
| --- | --- |
| 5 gwei (calm) | ~0.12 ETH (~$330) |
| 15 gwei | ~0.36 ETH (~$980) |
| 30 gwei (busy) | ~0.73 ETH (~$1,960) |

Fund **~1 ETH** to cover L1 at any realistic gas price with retry headroom.

**L2 (Base / Optimism / Arbitrum)** — recommended; the contracts use no chain-specific
features. Execution is pennies (L2 gas ~0.001–0.02 gwei); the cost is the ~94 KB of
init bytecode posted to L1 as blobs:

- Execution: **$0.07–$1.31** (Optimism → Arbitrum, at live gas prices).
- L1 data (blobs, ~94 KB): **~$1–$14** depending on L1 blob fees.
- **Total: roughly $1–$15 all-in.** Fund **~0.02–0.05 ETH (~$55–$135)** for ample margin.

## Not included in the launch gas

- **Enabling ICANN TLDs** (`markIcann` for the ~1,500-entry IANA root) is a separate
  ~75M gas — *more than the whole deployment*. Mark TLDs lazily (only ones you use).
- **Token supply/distribution** is a product decision (the genesis mint tx is in the
  buffer; how much to mint is up to you).
- Per-lookup resolution is a free `eth_call`; only state-changing txs cost gas.
