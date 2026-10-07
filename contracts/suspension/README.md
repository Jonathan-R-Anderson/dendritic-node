# ServiceSuspension — DAO suspension for self-certifying hidden services

`ServiceSuspension.sol` is the on-chain list the DAO uses to suspend a
`<56 base32>.key.axon` hidden service. It exists because the other on-chain
suspension path, `AxonRegistry`, keys on a registered **domain name** and works
by zeroing that name's key — a bare self-certifying service has no name there,
so the DAO could not reach it. This registry records suspension state against
the 32-byte **service identity key** itself.

## How it is governed

It implements the same `prune(bytes32,uint256)` / `seize` / `restore` seam that
`AxonGovernance` already calls, so a DAO instance pointed at it governs services
with no adapter:

- `prune`  → **SUSPENDED** (reversible — the network should stop routing)
- `seize`  → **BANNED** (permanent — never restorable)
- `restore`→ **ACTIVE** (lifts a suspension; a banned service cannot be lifted)

The vote happens in `AxonGovernance` (quorum, weighting, evidence CID on the
proposal). Only a passed proposal's `execute()` reaches this contract. Like
`AxonRegistry`, the list is **inert until `setGovernor` is called**, the DAO
holds no key, and it can only mark routing state — never edit a service's
content.

## How nodes consume it

Nodes do **not** read this contract on their dial path. A policy authority
(the DAO executor, or a monitor quorum) reads `blockedKeys()` here, joins each
to its proposal's evidence, and publishes a **signed service-policy document**
(`internal/axon/servicepolicy`). Every node fetches that document and applies
suspensions at its client dial gate — the only layer that sees a service's true
identity. This keeps chain reads off the hot path, matching the rest of the
overlay.

So the end-to-end flow is:

```
DAO proposal + vote (AxonGovernance)
        │ execute()
        ▼
ServiceSuspension.prune/seize/restore(serviceKey, proposalId)
        │ blockedKeys()
        ▼
policy authority → signs NetworkPolicy doc (grades + suspensions)
        │ axon.service_policy.policy_url / policy_key
        ▼
every node's servicepolicy.Policy → refuses the dial (if enforcing)
```

## Deploy + wire

```sh
export PATH="$HOME/.foundry/bin:$PATH"
forge test                                   # 11 tests
forge create src/ServiceSuspension.sol:ServiceSuspension \
  --rpc-url "$RPC" --private-key "$KEY" --broadcast \
  --constructor-args "$OWNER"
# then, once the DAO is deployed:
cast send <suspension> "setGovernor(address)" <axonGovernance> --rpc-url "$RPC" --private-key "$KEY"
```

Grades are deliberately **not** on-chain: they change often and are computed off
-chain from the decentralised content-report records, then carried in the same
signed document. Only suspension — which needs a vote and an audit trail — lives
on-chain.
