# Security model

## Trust boundaries

- **Who holds plaintext, resolved (T11.5).** The COORDINATOR holds plaintext;
  the node never does. Content arrives already encrypted
  (`backend/services/content_keys.py`), so a storage node holds ciphertext it
  cannot read and has no per-object key to wrap. The local S3 gateway is the
  ingress for already-encrypted bytes, not an encryption origin.

  This paragraph previously said the gateway was "trusted with plaintext because
  it is the encryption origin", which contradicted
  `internal/store/types.go`'s statement that "the node no longer encrypts
  objects". The CODE was right and this file was stale; §1 of the roadmap flagged
  the ambiguity and T11.5 required it resolved rather than left to the reader.
- Volunteer peers are untrusted and receive only independently authenticated,
  content-addressed encrypted shards.
- `rabbiit.io` is the discovery and allocation coordinator. When the signed
  bootstrap document names the origin's AXON address, coordinator requests go
  to it through the overlay, authenticated by the address itself; otherwise, or
  when that fails, they go directly over HTTPS. The coordinator's Ed25519 key
  authenticates bootstrap documents and leases either way.
- Kademlia records and peer responses are untrusted hints. Every returned shard
  must match its SHA-256 ID before Reed-Solomon reconstruction.

## Cryptography

Encryption happens at the COORDINATOR, before bytes reach a node. Each object
receives a random 256-bit XChaCha20-Poly1305 key there; every chunk gets a random
192-bit nonce and associated data binding its bucket, key and index.

**The node's half of that is deliberately small.** It receives authenticated
ciphertext, splits it into Reed-Solomon shards, and gives each shard a SHA-256
content id. It holds no object key, wraps nothing, and cannot decrypt what it
stores. `Manifest.PlainSHA256` is the digest of the STORED (ciphertext) bytes —
named for the earlier design and kept as an end-to-end integrity check, not as a
digest of anything readable.

Recovery at the node verifies shard SHA-256 and Reed-Solomon reconstruction, and
stops there. XChaCha20-Poly1305 authentication and the final plaintext digest are
the coordinator's, because they need the key the node does not have.

## Ethereum BLS verification is an opt-in build capability (P12)

`internal/ethproof` can verify Ethereum sync-committee signatures — the P12
light-client path that lets a node authenticate chain data without trusting an
RPC. That verifier is built on `blst`, which is cgo and **cannot compile with
`CGO_ENABLED=0` on any target except wasm**. The release build is CGO-free by
design: seven platforms cross-compiled from one host, static, `-trimpath`.

So BLS is behind a build tag:

| build | tag | BLS |
|---|---|---|
| ordinary release (`build-release.sh`) | none | **not compiled** |
| P12 development and tests | `ethbls` | real `blst` implementation |

The tag **enables** BLS; its absence selects the stub. A forgotten tag therefore
produces the build that refuses to verify, never one that silently claims it
did.

**Released binaries do not contain BLS, and that is not a downgrade.** Nothing
in `cmd/dendritic-node` constructs a `BLSVerifier` — the only callers of
`NewBLSVerifier` are tests, and `LightClientState` takes its verifier as a
parameter. BLS arrived as a verified library capability with the consensus-spec
vectors and was never wired into a runtime path.

**The no-BLS build fails closed.** `NewBLSVerifier` returns a non-nil verifier
whose every method returns `ErrNoBLSSupport`, naming the missing `ethbls` tag.
It never returns nil (which would invite a `!= nil` bypass), never returns
success, and inspects no argument — rejecting only malformed input would imply
a well-formed one might pass. `ApplyUpdate`, `ApplyFinalityUpdate` and
`ApplyRotatingUpdate` propagate the refusal, so no update can be applied
unverified.

**If a future P12 feature needs BLS in production**, it must either ship an
`ethbls` build with a deliberate release architecture for it, or provide
another authenticated path. It must not treat `ErrNoBLSSupport` as a soft
failure, and must never fall back to an unverified source: a build without BLS
is incapable of claiming that BLS-protected consensus evidence was checked, and
that incapacity is the point.

## Admission and abuse controls

Remote `STORE` is denied unless:

- the coordinator is configured and its public key was learned over the fixed
  TLS bootstrap origin;
- the lease signature is valid and binds object ID, shard ID, size, recipient,
  and expiry;
- the lease lasts no more than one hour;
- the shard fits protocol and local capacity limits;
- neither its shard nor object ID is on the user's denial list;
- the bytes exactly match the leased SHA-256 shard ID.

The coordinator accepts lease requests only from configured origin peer IDs,
verifies their embedded Ed25519 libp2p identity signature, applies clock-skew,
nonce-replay, size, and per-minute limits, and binds each lease to one recipient.

### Hidden-service flood resistance

Every `.axon` service is flood-resistant by construction, with nothing to
configure and no address to register anywhere. Two properties do the work:

- **No address to attack.** A service is reached through a rendezvous point over
  three-hop circuits; its intro and rendezvous points are structurally incapable
  of holding an address (the types have no field for one). There is no origin IP
  to point a flood at, which is most of what a clearnet reverse proxy buys a
  conventional site.
- **Priced introductions.** The one lever an attacker keeps is to pour
  `INTRODUCE1` cells at a service's intro points. Each intro point caps those per
  service with a token bucket and, when a service's introduction rate climbs,
  demands a proof-of-work admission token (`internal/axon/rendez/puzzle.go`). The
  proof is a hashcash solution bound to the service's auth key and the client's
  fresh ephemeral, so every introduction needs its own solve and no solution can
  be replayed onto another. The intro point verifies it in a single SHA-256 and
  keeps no per-client state, so a flood costs the attacker CPU proportional to
  its size while the relay's cost stays flat. The difficulty is adaptive and
  per-service: it is zero while a service is unattacked — honest clients pay
  nothing — and ramps up only under pressure, and only for the targeted service,
  never its neighbours on the same relay.

This is why a service does **not** need a volunteer clearnet gateway, nor any
record under `rabbiit.io`'s DNS, to withstand a denial-of-service attempt. The
gateway described below exists for a different purpose — bridging a hidden
service to *clearnet* visitors over public HTTPS — not for DoS protection of the
hidden service itself.

### Availability mirrors

A node can keep a signed local snapshot of an `.axon` site and serve it when the
origin is offline — the hidden-service form of the reverse gateway
(`internal/axon/mirror`, `axon.mirrors[]`). The origin publishes a
publisher-signed `/.well-known/rabbiit/snapshot.json` plus its objects over its
own AXON listener; each mirror node pulls and verifies them (the pinned
publisher key means a relay cannot feed forged content), serves the origin while
it is healthy, and falls back to the verified snapshot while it is down. Each
mirror runs as its own `.axon` service with a stable address, so many nodes
mirroring one site is what keeps the site reachable — no central CDN, and no DNS
record anywhere.

### Service routing policy (grades, allow/deny, DAO suspension)

Each node decides which hidden services it will route to, keyed by the service's
`.key.axon` identity and enforced at the one layer that can see that identity —
the client's own dial path (`servicepolicy`, `runtime.remoteFor`). The decision
composes, in order: the operator's deny list, the DAO suspension list, the
operator's allow list (which bypasses the grade floor), and a per-service grade
floor. Grades and suspensions arrive in a signed `NetworkPolicy` document
(ed25519, monotonic sequence, expiry), so no node reads the chain on its dial
path. Everything is **opt-in and permissive by default**: with nothing
configured every service is admitted, and a configured-but-not-enforcing node
logs what it *would* refuse without refusing — consistent with the rest of the
overlay, where the DHT never moderates and reputation never bans. Because the
service identity is visible only to the dialing client, this is necessarily the
operator's own routing choice, not a takedown imposed on the network.

**DAO suspension** of a self-certifying service is recorded on-chain in
`ServiceSuspension` (`contracts/suspension`), keyed by the 32-byte service key
and governed by `AxonGovernance` through the same `prune`/`seize`/`restore` seam
it already drives — `prune` suspends (reversible), `seize` bans (permanent),
`restore` lifts. A policy authority reads the on-chain suspension set and the
proposals' evidence and publishes it in the signed document above; nodes apply
it at the dial gate. This reaches bare `.key.axon` services that `AxonRegistry`
(which keys on registered names) cannot.

**Grades are computed by a swarm/thermal model** (`internal/axon/swarmscore`).
Report frequency HEATS a service — faster when the frequency is accelerating —
which lowers its grade and accelerates the DAO: above a threshold it recommends
a suspension proposal and shrinks the recommended voting window as temperature
climbs. Once a trailing window's report-frequency standard deviation drops below
its mean (the burst has settled), the service COOLS back to a good grade. The
function is deterministic, so every node derives the same temperature from the
same shared reports — stigmergic swarm consensus, no coordinator.

**Reports propagate** over the Kademlia-over-AXON DHT (`internal/reportnet`):
each reporter PUTs its signed `ContentReport` (`§89`) under a per-(subject,
reporter) key and PROVIDEs a per-subject rendezvous, so a grader enumerates every
report about a subject with one lookup (`Node.FindReports`) and feeds them to the
thermal model (`reportnet.ToSwarmReports`). A policy authority signs the
resulting grades into the policy document nodes read.

**Mirror discovery is decentralised** (`internal/mirrordisc`): a mirror
announces itself in the DHT under a per-origin rendezvous, and a client finds
every mirror of an origin with one lookup — no directory. The client fallback is
wired: the loopback proxy, when an origin is unreachable, retries the request
against a discovered mirror (which answers from its signed snapshot while the
origin is down), tagging the response `X-Rabbiit-Served-Via: mirror`.

## Local exposure

Configuration, identity, metadata, and master-key files use owner-only
permissions. Plaintext is encrypted while streaming into storage and is never
staged in a temporary file. The dashboard defaults to loopback and validates its
Host header. It may be moved to a private address (RFC1918, IPv4 link-local, or
IPv6 unique-local) so it can be reached from the operator's own network; that
requires `ui_password` of at least 12 characters, which is then demanded by HTTP
Basic auth on every request and compared in constant time. `0.0.0.0` and `::`
are refused with or without a password, because they also bind whatever public
interface the machine has now or acquires later, and publicly routable addresses
are refused outright. A non-loopback dashboard with no password configured
serves 503 rather than opening. The S3 API defaults to loopback; public binding
requires TLS.

The libp2p host registers only the AXON transport and advertises only `/axon`
multiaddresses: its own hidden service. Bootstrap and provider records
containing IP, DNS, TCP, QUIC, WebSocket, or relay components are discarded.
Peer traffic has no direct-network fallback. There is no I2P router, SAM bridge
or Tor anywhere in the node.

AXON conceals peer IP addresses from one another: peers meet at a rendezvous
point through three-hop circuits on each side, and a service's descriptor is
stored under a blinded key. It does not conceal traffic timing, shard sizes, the
fact that two peers advertise the same encrypted shard ID, or -- to an observer
of your connection -- that you are running a node, since links to relays are
ordinary libp2p TCP/QUIC connections. The loopback AXON proxy reaches only
`.key.axon` addresses; there is no exit to clearnet.

**AXON is young, and that matters.** It replaced I2P, which had two decades of
operational hardening and a large anonymity set. AXON's anonymity set is only as
large as its relay population, which is small, and its code has had no external
review. Its sybil resistance relies on diversity heuristics until relay bonding
is deployed. Treat its anonymity as weaker than I2P's was until those change.

The five-minute frontend heartbeat is intentionally direct rather than AXON,
per product requirements. It therefore exposes the node's public egress IP to
`rabbiit.io`, although the heartbeat table itself does not persist that IP.
The heartbeat is signed by the libp2p identity, freshness-checked, and
replay-protected. It uses the fixed User-Agent
`Rabbiit-Storage-Client/1.0`.

## Volunteer gateway trust boundary

Gateway mode is opt-in and does not make the S3 API public. Public handlers
expose only liveness, readiness, signed identity, and bounded challenge
responses. A candidate cannot authorize itself as a probe. Probe requests and
results are signed, short-lived, identity-bound, and subject to an admitted
probe list and network-diversity quorum.

Probe connections use validated literal public addresses while retaining TLS
hostname verification, do not follow redirects, and reject local, private,
link-local, CGNAT, documentation, multicast, transition, and unspecified
targets. This prevents a DHT record from turning probes into an SSRF primitive.

DNS credentials never belong on volunteer nodes, in client configuration, or
in DHT records. The client sends a short-lived, nonce-protected statement to
the fixed credential-free registration API, signed by its persistent Ed25519
identity. The separate server derives the direct request source IP, verifies
TCP/TLS/HTTP availability, and is the only component allowed to call Name.com.
Its durable ownership table ensures it never updates or deletes unrelated DNS
records. A verified gateway remains untrusted with content: clients must retain
end-to-end encryption and content-hash verification.

## Kademlia availability advisory

The Go Kademlia implementation is covered by `GO-2024-3218`, an availability
advisory with no upstream fixed version: hostile DHT peers can attempt to hide
provider records. The client does not trust the DHT for integrity and does not
use it as its only lookup path. It protects the TLS-discovered bootstrap
connections and asks trusted bootstrap plus already-connected swarm peers
directly before using Kademlia provider hints. SHA-256 and AEAD verification
prevent a malicious routing response from substituting data, but a sufficiently
large eclipse attack can still delay availability. This residual availability
risk is inherent in the requested public Kademlia layer and must be included in
the production threat model.
