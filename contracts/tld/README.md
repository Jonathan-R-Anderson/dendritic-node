# AxonTLD — a working `.axon` name system on Ethereum

Self-certifying addresses (`<56-base32>.key.axon`) need no lookup — the address *is*
the key. **Names** are the convenience layer on top: a human name under the fixed
`.axon` root, **owned on Ethereum**, bound there to a Layer-1 identity. This is the
pragmatic, end-to-end slice of the three-layer design in
`../../../../roadmap/axon/09-naming-registry.md` (which lives in the sibling
`dendritic` checkout): one registry contract + a node-side resolver wired into the
AXON proxy, so a request for a named host dials the address it points at.

```
name  --keccak256-->  node  --AxonTLD.resolve(node)-->  key(32B)  --FullAddress-->  <56>.key.axon
```

## Contract

`src/AxonTLD.sol` — a record is `keccak256(bytes(lowercased full name))` → `{key, owner, updatedAt}`,
where `key` is the 32-byte Ed25519 Layer-1 identity. First-come ownership; `register`,
`setKey`, `transfer`, `release`; views `resolve(bytes32)`, `resolveName(string)`, `nodeOf(string)`.
It keeps the load-bearing property of the full governed system — the name→key binding
is owned and verifiable on-chain — without the governance/commit-reveal/bond/anti-sybil
machinery that the production `TLDRegistry` + per-namespace registrars add.

## Deploy + register (local anvil)

```sh
export PATH=~/.foundry/bin:$PATH
anvil --silent &                      # chainId 31337 on :8545
forge build
forge create src/AxonTLD.sol:AxonTLD --rpc-url http://127.0.0.1:8545 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --broadcast
# register a name -> a node's 32-byte Ed25519 key (the key under its <56>.key.axon addr):
cast send <contract> "register(string,bytes32)" "ai.epin.axon" 0x<32-byte-key> \
    --rpc-url http://127.0.0.1:8545 --private-key 0xac09...ff80
```

## Use it from the node

Set the resolver in the node config and the loopback proxy resolves `.axon` names:

```json
"axon": { "proxy_listen": "127.0.0.1:4480",
          "name_rpc": "http://127.0.0.1:8545",
          "name_contract": "0x<contract>" }
```

```sh
curl -x http://127.0.0.1:4480 http://ai.epin.axon/expert/health
# -> proxy resolves ai.epin.axon on-chain -> <56>.key.axon -> dials it over AXON
```

Resolution (`internal/axon/names`) is a single `eth_call`. A production deployment
reads the same state **trustlessly** through `internal/ethproof` (an `eth_getProof`
against a BLS-verified header) rather than trusting the RPC — the call shape is identical.

## Mainnet

This registry is minimal and deploys to a stock EVM chain. The AXON mainnet already
has `AxonRegistry` (per-namespace name ownership) and an unaudited, undeployed
`TLDRegistry` (the governed root) in the sibling `proof-of-facilitation/contracts`;
paying for names there needs a funded `AxonToken` (supply 0 today) and the user's
wallet. This contract is the thing that actually runs end-to-end now.
