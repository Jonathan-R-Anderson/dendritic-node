# Registry-backed authoritative DNS

This service publishes blockchain-owned zones through **ISC BIND 9**, an authoritative
DNS server. `axon-dns` is the read-only registry adapter and record encoder; BIND owns
the DNS protocol implementation. It runs separately from the node's AXON HTTP proxy.
No deployment or chain transaction occurs when building or running this service.

```
AxonTLD v3 -> finalized eth_call snapshot -> validated zone -> BIND -> UDP/TCP DNS clients
                                                      \-> automatic DNSSEC signing
```

## Features

- Parent-controlled subdomains, arbitrary nesting within the DNS name-length limit,
  wallet delegation with explicit acceptance, and inherited control on parent transfer.
- A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR, CAA, DNAME, TLSA, SVCB/HTTPS and other
  BIND-supported data RR types, including RFC 3597 unknown-type records.
- DNS wildcards, empty nonterminals, DNS alias handling, NS delegation/referrals,
  in-bailiwick glue, NXDOMAIN versus NODATA, and SOA negative-caching TTLs.
- UDP and TCP, EDNS, truncated UDP responses with TCP retry, IPv4 and configurable IPv6
  listeners. Both protocols must be reachable on the chosen DNS port.
- BIND-managed DNSSEC signing, signatures, authenticated denial, key persistence and
  policy-driven key rollover. Parent DS publication/trust-anchor setup remains an
  operator action; DNSSEC does not magically connect this alternative namespace to
  the public DNS root.
- AXFR, IXFR, NOTIFY and secondary servers through BIND. Transfers are denied by default;
  configure explicit TSIG keys and secondary addresses before enabling them.
- Atomic zone-file replacement, monotonically incremented SOA serials (RFC 1982 wrap),
  per-zone writer locks, validation before reload, and preservation of the last validated
  zone when RPC access or validation fails.

This is authoritative-only: recursion is disabled. RFC 2136 UPDATE is deliberately
refused because unauthenticated/off-chain updates would bypass wallet ownership and
protocol fees. Record changes use contract transactions; the publisher needs **no
wallet or signing key**. These are policy choices, not a claim that BIND lacks those
features. Additional BIND serving options (views, transfer policies, listeners) belong
in `named.conf`, not in registry records.

## Namespace ownership

Only second-level names such as `example.com` are first-come registrations. The
current owner of `example.com` creates `api.example.com`; the current owner of
`api.example.com` creates `v1.api.example.com`. The immediate parent must exist,
including intermediate `_tcp` labels for service records. Other wallets cannot
squat under another owner's parent, even before that owner creates the child.

A new child inherits its parent's effective owner. Transferring the parent transfers
control of all inherited descendants and preserves their records. To delegate a
subtree to another wallet, initiate `transfer(child, recipient)` and have the recipient
`acceptTransfer(child)`. The subtree now has its own controller; later transfers of
ancestors do not overwrite that controller. Parent-controlled namespace policy is
separate from the contract administrator, who gains no record-editing privileges.

Only the effective controller edits/releases a name. Ancestor release invalidates
all descendant registrations and pending transfers immediately. Generation counters
prevent them from reviving when ancestors are re-registered. Stale descendant data
is hidden by every record/owner read and cleared when that child is re-created.
Physical stale storage may remain on chain; blockchain history is never erased.
A pending inherited-child transfer is invalidated when its controlling ancestor
transfers, even if that ancestor later returns to the original wallet.

Wallet delegation and DNS delegation are different. An NS record below the served
zone apex creates a DNS zone cut, irrespective of wallet ownership. The parent zone
publishes that NS RRset, DS records and necessary glue; the child zone's SOA and
ordinary records are published by a separately configured child authoritative zone.
Configure the child origin in both publisher and BIND if serving it here. The exporter
discards non-glue data below cuts from the parent zone.

The suffix policy remains single-label TLDs. For example, reverse zones can be built
under an enabled `arpa` suffix by registering the necessary parent hierarchy; this
is not public reverse-DNS delegation. A registry name never grants public DNS rights.

## Store DNS records

Protocol v3 appends `DNS = 4` to the existing enum; AXON/A/AAAA/MX numeric values stay
unchanged. A DNS payload is a two-byte network-order RR TYPE followed by uncompressed
wire-format RDATA. All names embedded in RDATA must be absolute. No packet compression
pointers are allowed. The contract bounds the envelope and rejects query/meta types;
type-specific validity and whole-zone consistency are checked by the publisher and
`named-checkzone`. A bad on-chain DNS record therefore blocks that zone's next publication
until its owner fixes/removes it. It does not publish a partially updated zone.

Use the encoder instead of assembling bytes manually:

```sh
go build -o /tmp/axon-dns ./cmd/axon-dns
/tmp/axon-dns encode -rr 'api.example.com. 300 IN A 192.0.2.10'
/tmp/axon-dns encode -rr 'www.example.com. 300 IN CNAME api.example.com.'
/tmp/axon-dns encode -rr 'example.com. 300 IN TXT "verification=value"'
/tmp/axon-dns encode -rr '_sip._tcp.example.com. 300 IN SRV 10 20 5060 sip.example.com.'
/tmp/axon-dns encode -rr '*.example.com. 300 IN A 192.0.2.20'
```

The JSON result supplies `name`, `kind`, `ttl`, and hex `data` for
`setRecord(string,uint64,uint8,uint32,bytes)`. ID 0 adds a record; an existing ID updates
it. Pay exactly the current record fee. First register the owner name and any missing
parents using `register(name, bytes32(0))` with the registration fee. Existing AXON
records can coexist with DNS data; they are never exported as DNS IP addresses.

Example operator commands (not executed automatically):

```sh
# After registering example.com, its owner registers an empty child.
cast send "$REGISTRY" 'register(string,bytes32)' api.example.com \
  0x0000000000000000000000000000000000000000000000000000000000000000 \
  --value "$REGISTRATION_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
# Use the encoder's TTL and DATA for a DNS record.
cast send "$REGISTRY" 'setRecord(string,uint64,uint8,uint32,bytes)' \
  api.example.com 0 4 "$TTL" "$DATA" \
  --value "$RECORD_FEE_WEI" --rpc-url "$RPC_URL" --account "$ACCOUNT"
```

Limits: 32 records per owner name, 4096 wire RDATA bytes per generic DNS record,
TTL 0–604800 seconds, 63 bytes per label and 253 bytes per normalized owner. Names
are ASCII: uppercase folds, one final dot is removed, whitespace/Unicode are rejected.
DNS owner labels below the second level may contain underscores or a whole leftmost
`*` label. The registrable second-level name and TLD remain LDH hostnames. IDNA must
be converted by the caller. `.key.axon` and descendants remain reserved.

RRset TTLs must agree. CNAME cannot coexist with other DNS data at the same owner;
MX/NS targets cannot be CNAMEs. DNSKEY/RRSIG/NSEC/NSEC3/NSEC3PARAM are generated by BIND,
not imported from the registry. Put DS records into the parent zone when establishing
a signed delegation. Apex SOA/NS may come from the registry; if absent, the publisher
creates operational SOA/NS records using the configured nameservers/mailbox. It manages
the SOA serial even when the rest of that SOA came from the registry.

## Run the service

1. Deploy the current registry separately and register/populate your names using the
   [contract instructions](../../contracts/tld/README.md). This task does not deploy it.
2. Copy `publisher.example.json` to `publisher.json` and `named.conf.example` to
   `named.conf`. Set the actual RPC, contract, **expected chain ID**, zones, nameserver
   names and mailbox. Both configurations must list the same served zones/files.
   Use an RPC address reachable from the container; container `127.0.0.1` is not the host.
3. From this directory run `docker compose build`, then intentionally start the service
   with `docker compose up -d`. The example binds host **127.0.0.1:1053 TCP and UDP**;
   edit the port mappings/listeners explicitly for public authoritative service on 53.
4. Test with `dig @127.0.0.1 -p 1053 api.example.com A`, `+tcp`, and `+dnssec`.
   Configure your local resolver/stub zone to use this authority. Browsers will not
   discover a network-local blockchain namespace through public DNS automatically.

Keep the `authoritative-state` volume: it contains zone serial history, BIND journals,
private DNSSEC keys and the local RNDC control key. Back it up securely. Recreating
keys changes the trust anchor and may require updating parent DS records. Restart
both services after changing the set of configured zones; remove retired zones from
both configurations intentionally. The service does not edit host resolver settings.

For a host BIND installation, build `./cmd/axon-dns`, install BIND tools, make the
configured zone directories writable to the publisher/BIND, and run:

```sh
axon-dns publish -config publisher.json -no-reload  # initial provisioning
# Start named with the matching configuration, then:
axon-dns publish -config publisher.json -watch
```

`check_command` is an executable plus arguments; origin and candidate file are appended.
`reload_command` receives the origin as its final argument. Neither is interpreted by
a shell. Watch mode requires a reload command. The container entrypoint supervises
both processes and stops if either exits. Current sync failures are logged and retried
at the configured interval; monitor those logs and snapshot block hashes for staleness.

## Secondaries and trust

For secondaries, create a TSIG key with `tsig-keygen`, include its private key in both
servers' protected config, set the primary zone's `allow-transfer { key "secondary"; };`
and `also-notify { SECONDARY_IP key "secondary"; };`, and configure the secondary with
`type secondary; primaries { PRIMARY_IP key "secondary"; };`. Use BIND's standard
AXFR/IXFR/NOTIFY and key rotation procedures. Never put TSIG or DNSSEC private keys
in the public registry.

The adapter checks chain ID and protocol version 3, then reads the entire selected
subtree at one **finalized block hash** using EIP-1898 `requireCanonical`. RPCs lacking
finalized blocks or hash-pinned eth_call are rejected. This avoids mixed-block zones
and ordinary tip reorgs; it **does not verify blockchain proofs** or protect against a
lying RPC. A maximum enumeration count bounds live names plus historical tombstones;
raise `max_names` deliberately if your zone needs more than the default 10000.

RPC/decoding/validation failures keep the last validated zone. A confirmed release is
different: the publisher replaces it with an authority-only tombstone zone, removing
old user records and serving authoritative negative answers. Recursive caches may
retain old answers until their TTLs expire. DNSSEC authenticates the serving authority's
zone; it does not prove that authority faithfully copied the chain.

The AXON HTTP proxy remains separate: it consumes AXON identities, bypasses the
registry for direct `.key.axon`, and never converts a failed AXON connection into a
clearnet connection. DNS A/AAAA, wildcards and CNAME processing happen in BIND and do
not change overlay routing.

## Verification and compatibility

Protocol v3 requires redeployment; the contracts are not upgradeable. Canonical
name hashes, existing enum values and `resolve(bytes32)` stay compatible. Historical
flat registrations are not imported or seized. Owners must migrate voluntarily,
registering parents before children. Earlier registry versions remain usable with
the existing AXON resolver compatibility settings, but cannot back this publisher.

```sh
go test ./internal/axon/authoritative ./cmd/axon-dns
CGO_ENABLED=0 go test -c -o /tmp/axon-authoritative.test ./internal/axon/authoritative
docker run --rm --network none -e AXON_BIND_TEST=1 \
  -v /tmp/axon-authoritative.test:/tests:ro --entrypoint /tests \
  internetsystemsconsortium/bind9:9.20@sha256:071465f88068854d0ceadd9b985fb1acae4071e80754e545cd811fde57541ad0 \
  -test.run TestBINDIntegration -test.v
```

The integration test verifies actual UDP/TCP answers, wildcard/CNAME/SRV/MX/CAA,
referrals/glue, NXDOMAIN/NODATA, truncation, cryptographic DNSSEC verification,
TSIG-restricted AXFR, live reloads and release cleanup. The BIND test is opt-in on
hosts without BIND installed; it is run in the pinned container during validation.

Protocol references: [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034.html),
[RFC 2181](https://www.rfc-editor.org/rfc/rfc2181.html),
[BIND configuration reference](https://bind9.readthedocs.io/en/stable/reference.html).
