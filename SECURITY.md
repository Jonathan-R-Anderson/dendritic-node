# Security model

## Trust boundaries

- The local S3 gateway is trusted with plaintext because it is the encryption
  origin.
- Volunteer peers are untrusted and receive only independently authenticated,
  content-addressed encrypted shards.
- `syndichan.org` is the discovery and allocation coordinator. Its HTTPS
  requests are forced through the configured local I2P HTTP proxy; TLS
  authenticates bootstrap documents and its Ed25519 key authenticates leases.
- Kademlia records and peer responses are untrusted hints. Every returned shard
  must match its SHA-256 ID before Reed-Solomon reconstruction.

## Cryptography

Each object receives a random 256-bit XChaCha20-Poly1305 key. Every chunk gets a
random 192-bit nonce and associated data binding its bucket, key, and index.
The object key is wrapped by the local 256-bit master key. Shards are generated
from authenticated ciphertext, and each shard has a SHA-256 content ID.

Recovery verifies, in order: shard SHA-256, Reed-Solomon reconstruction,
XChaCha20-Poly1305 authentication, and the final plaintext SHA-256.

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

## Local exposure

Configuration, identity, metadata, and master-key files use owner-only
permissions. Plaintext is encrypted while streaming into storage and is never
staged in a temporary file. The dashboard is loopback-only and validates its
Host header. The S3 API defaults to loopback; public binding requires TLS.

The libp2p host registers only the custom I2P transport and advertises only
`/garlic32` multiaddresses. Bootstrap and provider records containing IP, DNS,
TCP, QUIC, WebSocket, or relay components are discarded. The SAM bridge and
I2P HTTP proxy are required to be local because SAM is ordinarily unencrypted
and unauthenticated. There is no direct-network fallback.

I2P conceals peer IP addresses from one another, but does not conceal traffic
timing, shard sizes, the fact that a user is running I2P from their ISP, or the
fact that two peers advertise the same encrypted shard ID. The coordinator's
HTTPS outproxy can observe the coordinator hostname, while the coordinator sees
the outproxy rather than the node's IP.

The five-minute frontend heartbeat is intentionally direct rather than I2P,
per product requirements. It therefore exposes the node's public egress IP to
`syndichan.org`, although the heartbeat table itself does not persist that IP.
The heartbeat is signed by the libp2p identity, freshness-checked, and
replay-protected. It uses the fixed User-Agent
`Syndichan-Storage-Client/1.0`.

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
