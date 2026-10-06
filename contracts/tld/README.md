# AXON alias registry

AxonTLD binds network-local alternative names to AXON service identities. Registering
`example.com` here gives **no ownership or control of public DNS example.com**.
Operators independently opt into additional suffixes on the contract and their nodes.
Default node configuration still reaches self-certifying `.key.axon` addresses without
any registry; `.axon` remains the built-in alias suffix.

## Authoritative DNS and hierarchical names (protocol v3)

The registry also backs a full BIND authoritative DNS service. See
[deployment, record encoder, subdomains, DNSSEC and secondary instructions](../../packaging/authoritative-dns/README.md).
`protocolVersion()` returns 3. Only second-level registrations are first-come;
deeper names require the immediate parent's effective owner. Children inherit control
until explicitly delegated through two-step transfer. Ancestor release invalidates
descendants using generations, preventing stale-data revival on re-registration.
`childrenPage(parent, offset, limit)` enumerates up to 128 historical immediate names;
check ownership at the same block to filter tombstones.

DNS owner names below the second level additionally allow underscore labels and a
whole leftmost wildcard label. Ordinary hostname validation remains ASCII LDH.
The new `DNS = 4` type stores uint16 RR TYPE plus up to 4096 bytes of uncompressed
wire RDATA. Type/zone validity is enforced by the publisher and BIND before serving.
DNSKEY/signatures/denial records are managed by BIND; publish DS in parent zones.
The 255-byte limit below applies to the original four types, not generic DNS records.

## Naming and authority

Names use ASCII letters, digits and hyphens: 1–63 bytes per label, at most 253 bytes
for the normalized full name, no leading/trailing label hyphens, empty labels or
whitespace. Uppercase is folded and exactly one final dot is removed. Unicode is
rejected: convert IDNA outside this protocol if desired; ASCII `xn--` labels are
accepted without decoding or confusable protection. A domain needs at least two
labels. `key.axon` and every descendant are reserved. All name-based mutation and
lookup methods use these same rules. Canonical hashes remain
`keccak256(bytes(lowercase_full_name_without_final_dot))`.

A suffix is one TLD label, stored without a leading dot (e.g. `com`). The deploying
wallet initially administers suffixes and fees, following this project's simple
creator-administered registries. It cannot seize names or edit somebody else's
records. `proposeAdministrator` / `acceptAdministrator` transfers this policy role
in two steps; the immutable fee beneficiary does not change. Every policy change
emits an event. `.axon` starts enabled. Disabling any suffix blocks registrations
only; existing ownership, resolution, record changes, transfers and release continue.
A released name under a disabled suffix cannot be re-registered until re-enabled.

### TLD admission is governed (ICANN + DAO)

Which TLDs may exist is not the administrator's to decide alone, so the namespace
cannot be flooded with low-quality roots:

- **ICANN root-zone TLDs** (`com`, `net`, `org`, …) — the administrator calls
  `markIcann(suffix, true)` to assert a suffix is in the IANA root zone (a public,
  independently verifiable fact), then `setSuffix(suffix, true)` enables it. The mark
  only controls the admin's direct-enable path; it never touches names or records.
  Enabling a suffix the administrator has *not* marked ICANN reverts.
- **Network-native (non-ICANN) TLDs** — admitted only by a passing **token-holder
  vote**. Anyone calls `proposeSuffix(suffix)`; holders of the DAO vote token call
  `voteSuffix(id, support)` (weight = their `balanceOf`, one vote per address); after
  the voting period anyone calls `executeSuffix(id)`, and if the `for` votes meet the
  quorum and outnumber the `against` votes the suffix is admitted (`daoApproved`) and
  enabled. `proposalInfo` / `hasVoted` read a proposal; `SuffixProposed` /
  `SuffixVoted` / `SuffixProposalExecuted` trace it. The constructor sets the vote
  token, voting period (seconds) and quorum; a zero vote token disables the DAO path,
  so only ICANN suffixes can ever be enabled.
- `.axon`, the network's own root, is grandfathered: enabled at construction and
  re-enable-able without a vote.

The administrator can always **disable** any suffix regardless of how it was admitted
(blocking new registrations only). Admitting a TLD never confers any authority over a
name registered under it. The vote reads live `balanceOf`; a deployment that needs
snapshot-based, transfer-proof weights should supply an `ERC20Votes` token and move
`voteSuffix` to `getPastVotes` (noted in the contract).

The first successful second-level registration owns that namespace indefinitely (no expiry/renewal).
Reads establish no ownership. `register` never updates an existing registration.
Only the effective owner can mutate records, release, or initiate/cancel a transfer.
`transfer` proposes a nonzero recipient, replacing any pending proposal; the recipient
must call `acceptTransfer`. Records survive acceptance and the former owner loses
all privileges. `release` clears records, primary selection and pending transfer.
A new registration starts a new ID sequence and inherits no data. Ancestor release also invalidates all descendants; inherited descendants follow parent transfers, while explicitly delegated controllers remain independent until an ancestor is released.

## Records and resolution

Each domain has at most 32 records, each with a stable uint64 ID during its
registration, a type, a TTL and bounded data. ID 0 means allocate the next ID;
updates/removals of unknown IDs revert. IDs are not reused until release. Duplicate
(type, data) pairs are rejected, regardless of TTL. Enumeration is insertion/ID order;
`recordsPage(node, offset, limit)` returns up to 32 records (offset beyond the end
returns empty). Legacy-type payloads are at most 255 bytes; generic DNS payloads are at most 4098 bytes.

| Type enum | Payload encoding | Validation |
| --- | --- | --- |
| AXON = 0 | 32-byte Ed25519 public key | Nonzero, exactly 32 bytes; clients render canonical `<56-base32>.key.axon` addresses |
| A = 1 | IPv4 in network byte order | Exactly 4 bytes |
| AAAA = 2 | IPv6 in network byte order | Exactly 16 bytes |
| MX = 3 | uint16 priority, big endian, then ASCII hostname | Canonical lowercase hostname, same label/length rules, no trailing dot; 3–255 total bytes |

AXON payload validation checks encoding and the unset sentinel, not proof of possession
or service availability. TTL is 0–604800 seconds; 0 means do not cache. TTL is a cache
hint, not registration expiry. The current resolver makes fresh RPC reads on connection
setup, does not cache records, and does not close existing HTTP connections at TTL expiry.

The first AXON record becomes primary. Owners use `setPrimary` to choose another.
Removal or conversion of the primary selects the remaining AXON record with the
lowest ID, or clears the primary if none remain. `setKey` updates the primary (TTL
300), creating one if absent; zero keys are rejected. `resolve(bytes32)` retains
its `(bytes32 key, address owner, uint64 updatedAt)` ABI. A zero owner is unregistered;
a nonzero owner with zero key is registered without an AXON destination.

`lookupAxon(bytes32)` returns `(address owner, bytes32[32] keys, uint256 count)`
atomically, primary first and then remaining AXON records by ascending ID; unused
slots are zero. This bounded interface needs no pagination. `recordsPage` exposes
all typed records. The HTTP proxy consumes **only AXON records**: A/AAAA are stored
metadata, not clearnet destinations, and MX storage does not implement mail delivery.

The proxy tries at most four AXON destinations, in returned order, stopping at the
first successful connection. Each attempt receives at most one quarter of the total
dial timeout when four candidates are present (otherwise timeout / candidate count).
Only connection establishment is retried; application requests are not replayed.
Failed AXON connections never trigger exit routing.

## Fees and withdrawals

The constructor takes `(registrationFee, recordFee, transferFee, voteToken,
votingPeriod, quorumVotes)`: the three fees as integer native chain currency **wei**
(not token amounts), then the DAO vote-token address, the voting period in seconds and
the quorum in vote-token units (see "TLD admission is governed"). There is no assumed
production fee schedule or deployer wallet. Exact payment is required;
insufficient/excess payments revert. All fees may be zero. Reverts roll back both
mutation and accrued fees. `deploy.sh` passes all six through
`REGISTRATION_FEE_WEI`/`RECORD_FEE_WEI`/`TRANSFER_FEE_WEI`/`VOTE_TOKEN`/
`VOTING_PERIOD_SECONDS`/`QUORUM_VOTES` and refuses to run from a factory that would
capture the beneficiary.

- `register`: registration fee, including its optional initial AXON record (zero key
  registers an empty domain).
- `setRecord`, `setKey`, `removeRecord`, `setPrimary`: one record fee per call.
- `setRecords`: atomic, 1–32 entries, exactly `recordFee * entries.length`; additions
  and updates cost the same. Invalid entries revert the entire batch. Removals are
  separate calls.
- `transfer`: one transfer fee per initiation, including replacement proposals.
- `release`, `acceptTransfer`, `cancelTransfer`, administration: no protocol fee
  (ordinary transaction gas still applies).

`setFees` changes the three fees with an event. Proceeds accrue to `beneficiary`, the
original contract-creating address, forever. Only that address can `withdraw(to)`
the entire accrued balance to a nonzero recipient. Withdrawals use a reentrancy lock
and checks-effects-interactions; a failed payment restores the accrual and cannot
block unrelated mutations. Forced ETH is not part of accrued protocol fees.
These are protocol usage fees, not government taxes. Ordinary read-only `eth_call`
and public state reads **cannot enforce a per-lookup on-chain fee**.

## Deployment and CLI

This is a new, non-upgradeable contract: build/test with Foundry (put
`$HOME/.foundry/bin` before the unrelated system `forge` if necessary):

```sh
forge build
forge test
```

`scripts/deploy.sh` uses a Foundry keystore and direct wallet CREATE. Set `RPC_URL`,
`ACCOUNT`, `DEPLOYER` (the expected wallet), `REGISTRATION_FEE_WEI`, `RECORD_FEE_WEI`,
and `TRANSFER_FEE_WEI` explicitly. Run it without arguments for a dry run; pass
`--broadcast` only when intentionally deploying. It checks the keystore matches the
explicit beneficiary/deployer. **Do not deploy this constructor through a factory or
helper contract**: that contract would become both beneficiary and administrator.
The provided script uses neither. No private keys are hardcoded or put in shell
arguments. Record the chain ID and returned deployed address; configure nodes with
that address on the same chain. Verify `beneficiary()` and `administrator()` after
any real deployment. Deployment and transactions are operator actions, not part of tests.

The following is an operator reference, not a script to run blindly. Use the appropriate
owner/admin/recipient keystore for each command. `REGISTRY`, `RPC_URL`, `ACCOUNT`,
`KEY` (0x + 64 hex digits), `RECIPIENT`, and each fee are explicit operator inputs.
Refresh fees immediately before sending; a racing fee change safely reverts.

```sh
# Policy administration; fee units are wei
# Enable an ICANN TLD: mark it (admin asserts it is in the IANA root zone), then enable.
cast send "$REGISTRY" 'markIcann(string,bool)' com true --rpc-url "$RPC_URL" --account "$ACCOUNT"
cast send "$REGISTRY" 'setSuffix(string,bool)' com true --rpc-url "$RPC_URL" --account "$ACCOUNT"
# (bulk-mark the IANA root zone: for t in $(curl -s https://data.iana.org/TLD/tlds-alpha-by-domain.txt | tail -n +2 | tr A-Z a-z); do cast send "$REGISTRY" 'markIcann(string,bool)' "$t" true ... ; done)
# Admit a NETWORK-NATIVE (non-ICANN) TLD by DAO vote (voteToken holders decide):
PID=$(cast send "$REGISTRY" 'proposeSuffix(string)' hack --rpc-url "$RPC_URL" --account "$ACCOUNT" --json | jq -r .logs[0].topics[1])
cast send "$REGISTRY" 'voteSuffix(uint256,bool)' "$PID" true --rpc-url "$RPC_URL" --account "$ACCOUNT"   # weight = your vote-token balance
# after VOTING_PERIOD_SECONDS, anyone finalises; approval (quorum met, for > against) enables it:
cast send "$REGISTRY" 'executeSuffix(uint256)' "$PID" --rpc-url "$RPC_URL" --account "$ACCOUNT"
cast call "$REGISTRY" 'proposalInfo(uint256)(string,uint64,bool,uint256,uint256)' "$PID" --rpc-url "$RPC_URL"
# The admin can always DISABLE any suffix (blocks new registrations only):
cast send "$REGISTRY" 'setSuffix(string,bool)' hack false --rpc-url "$RPC_URL" --account "$ACCOUNT"
cast send "$REGISTRY" 'setFees(uint256,uint256,uint256)' "$REGISTRATION_FEE_WEI" "$RECORD_FEE_WEI" "$TRANSFER_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
cast call "$REGISTRY" 'fees()(uint256,uint256,uint256)' --rpc-url "$RPC_URL"
cast send "$REGISTRY" 'proposeAdministrator(address)' "$RECIPIENT" --rpc-url "$RPC_URL" --account "$ACCOUNT"
# Recipient's account:
cast send "$REGISTRY" 'acceptAdministrator()' --rpc-url "$RPC_URL" --account "$ACCOUNT"

# Registration includes initial key. Use bytes32 zero to register without destinations.
cast send "$REGISTRY" 'register(string,bytes32)' example.com "$KEY" --value "$REGISTRATION_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
# Add another AXON key (ID 0); receipt RecordChanged event supplies its stable ID.
cast send "$REGISTRY" 'setRecord(string,uint64,uint8,uint32,bytes)' example.com 0 0 300 "$SECOND_KEY" --value "$RECORD_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
# Update record 2 to IPv4 192.0.2.1, or use kind 2 + 16 bytes for IPv6.
cast send "$REGISTRY" 'setRecord(string,uint64,uint8,uint32,bytes)' example.com 2 1 300 0xc0000201 --value "$RECORD_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
# MX priority 10 + mail.example.com (ASCII bytes)
cast send "$REGISTRY" 'setRecord(string,uint64,uint8,uint32,bytes)' example.com 0 3 300 0x000a6d61696c2e6578616d706c652e636f6d --value "$RECORD_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
cast send "$REGISTRY" 'setPrimary(string,uint64)' example.com 1 --value "$RECORD_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
cast send "$REGISTRY" 'removeRecord(string,uint64)' example.com 2 --value "$RECORD_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
# Atomic batch: BATCH is [(id,kind,ttl,0xdata),...], TOTAL_FEE = recordFee * entry count.
cast send "$REGISTRY" 'setRecords(string,(uint64,uint8,uint32,bytes)[])' example.com "$BATCH" --value "$TOTAL_FEE" --rpc-url "$RPC_URL" --account "$ACCOUNT"
cast send "$REGISTRY" 'transfer(string,address)' example.com "$RECIPIENT" --value "$TRANSFER_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
# Recipient's account:
cast send "$REGISTRY" 'acceptTransfer(string)' example.com --rpc-url "$RPC_URL" --account "$ACCOUNT"
# Current owner's account:
cast send "$REGISTRY" 'release(string)' example.com --rpc-url "$RPC_URL" --account "$ACCOUNT"
# Original deployer's account, independent of current administrator:
cast send "$REGISTRY" 'withdraw(address)' "$RECIPIENT" --rpc-url "$RPC_URL" --account "$ACCOUNT"

NODE=$(cast call "$REGISTRY" 'nodeOf(string)(bytes32)' example.com --rpc-url "$RPC_URL")
cast call "$REGISTRY" 'resolve(bytes32)(bytes32,address,uint64)' "$NODE" --rpc-url "$RPC_URL"
cast call "$REGISTRY" 'lookupAxon(bytes32)(address,bytes32[32],uint256)' "$NODE" --rpc-url "$RPC_URL"
cast call "$REGISTRY" 'recordsPage(bytes32,uint256,uint256)((uint64,uint8,uint32,bytes)[])' "$NODE" 0 32 --rpc-url "$RPC_URL"
```

## Node configuration and RPC trust

```json
"axon": {
  "proxy_listen": "127.0.0.1:4480",
  "name_rpc": "http://127.0.0.1:8545",
  "name_contract": "0x<deployed-registry-address>",
  "name_suffixes": ["com"],
  "name_missing_fallback": false,
  "name_legacy_contract": false
}
```

`name_suffixes` is a list of lowercase single TLD labels; `.axon` is implicit.
Suffix matching uses label boundaries (`notcom` does not match `com`). Direct valid
`.key.axon` identities bypass the registry. An operator must enable `com` on chain
as well as configure it on the node. Restart the node after changing these settings.

`name_missing_fallback` defaults false. When true, only a definitive zero-owner,
zero-record result for an additional suffix may use the normal configured `exit_via`
route. No exit means refusal. Registered names without AXON records, malformed
responses, RPC errors/reverts, unsupported ABI methods and failed AXON connections
never fall back. `.axon` never falls back, even when the registry is disabled.
Unconfigured suffixes continue to use ordinary exit policy.

The resolver **trusts the configured RPC's eth_call results**, including absence and
ownership. It does not use `internal/ethproof`, verify storage proofs, verify chain
headers or protect against a lying RPC claiming a name is absent. The RPC observes
queried names (hashes are guessable). Use a trusted RPC; opt-in exit fallback adds
trust in its absence claims. The primary and all destinations are read in one call.

## Compatibility and migration

Existing deployments cannot gain these methods without redeployment. Version 3 also changes flat registration to parent-controlled subdomains: register each ancestor before its children. No existing deployment is modified in place. For the old
registry, explicitly set `name_legacy_contract: true` and omit additional suffixes;
this uses the preserved `resolve(bytes32)` tuple and a single AXON destination for
`.axon`. Modern mode never guesses that an unsupported method means unregistered.
Old raw-string noncanonical registrations are not made newly reachable: the old
contract did not normalize names, so uppercase/trailing-dot/whitespace registrations
may occupy different hashes. Canonical lowercase hashes are unchanged.

There is no automatic migration, import authority or administrative ownership
seizure. Existing records/owners stay on the old contract. Owners must voluntarily
register available canonical names in the new registry using their own wallets and
copy records, coordinating rollout and competing/noncanonical claims off chain.
The new registry does not reserve old names automatically; registration there remains
first-come. Keep the old contract configured in legacy mode until an agreed migration.
Old zero-key owned domains now correctly fail with "no AXON destination".
