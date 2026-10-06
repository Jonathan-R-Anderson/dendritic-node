# Anonymity of the dendritic network (AXON)

An honest analysis of what the overlay hides, what it does not, and where the
development deployments and the `.axon` naming layer give anonymity away. If you are
about to run anything that matters on this, read the two red-flag sections first:
**"Where our current deployments are NOT anonymous"** and **"The naming layer leaks"**.

Claims here are against the code in this repo (`internal/axon/*`) and the naming code
in the sibling `dendritic` checkout; file references are given so they can be checked.

---

## TL;DR

- **Design**: AXON is a Tor-shaped onion network — 3-hop ntor circuits, pinned guards,
  self-certifying addresses, and hidden services reached by rendezvous. Run *correctly
  and at scale* it gives Tor-class "who is talking to whom" unlinkability and hides the
  IP of every service.
- **As we are running it now**: **not anonymous.** Our clusters set
  `axon.allow_same_network` (every relay on one LAN), the relay set is tiny (6), and the
  chain is a local anvil. Any one of those alone defeats anonymity; together they make
  the overlay a convenience layer, not a privacy one. That was the right trade for
  *bringing it up*; it is the wrong one for using it in anger.
- **The naming/blockchain layer is public by construction**: registering a name is a
  public Ethereum transaction, and the name→key binding is world-readable. Names trade
  some of Layer 1's privacy for human usability — use them with that in mind.

---

## What AXON is

A short tour of the mechanisms that do the work (and where they live):

- **Self-certifying addresses.** `<56-base32>.key.axon` *is* a 32-byte Ed25519 public
  key plus checksum (`internal/axon/identity/identity.go`). There is no certificate
  authority and no name lookup on the fast path: to reach a service you only need its
  address, and the address proves the key. This is the root of the trust model — Layer 1
  is the guarantee; names (Layer 3) are only convenience.
- **Onion circuits.** A client builds a circuit of `params.DefaultHops = 3` relays —
  guard, middle, terminal — with ntor key agreement per hop and layered relay-cell
  encryption (`internal/axon/circuit`, `runtime/client.go`). Each relay learns only its
  predecessor and successor; none sees both the client and the destination.
- **Pinned guards.** The first hop is a pinned guard (`runtime/client.go` `guardRelay`),
  the standard defence against the statistical deanonymisation that random first hops
  enable. A guard sees your IP but not your destination.
- **Hidden services (the important part).** A service never accepts an inbound
  connection and never reveals an IP. It holds circuits *out* to `serviceIntroPoints = 3`
  intro points (`runtime/service.go`); a client builds a circuit to a rendezvous point it
  chooses, sends an INTRODUCE through an intro point, and the service builds its own
  circuit to that rendezvous point. The two circuits splice there. Neither side learns
  the other's IP, and the service works from behind any NAT/firewall.
- **Blinded directory.** Service descriptors are published under per-period *blinded*
  keys (`internal/axon/identity/blind.go`, `dht`), so the directory holders that store a
  descriptor cannot enumerate services or link a descriptor to a long-term identity
  without already knowing the address. (The running node discovers relays/descriptors
  through a directory rather than full iterative Kademlia — a smaller, more trusted
  discovery base than the spec's DHT; see `DENDRITIC_NETWORK_GAPS.md`.)
- **Traffic shaping.** A padding layer exists (`internal/axon/padding`) to blunt
  volume/timing fingerprints; it is a mitigation, not a cure (see GPA below).
- **Sybil / abuse resistance.** Guards, a reputation layer, and blind-token machinery
  (`reputation`, `token`, `sybil` in the sibling) raise the cost of flooding the relay
  set with adversary nodes — the attack that most directly erodes an onion network.

## Threat model — what it protects against

- **A local network observer / your ISP.** Sees an encrypted QUIC flow to one guard and
  nothing about the destination. ✔ (given a real guard, not a same-LAN one — see below).
- **An individual relay operator.** Learns only its two circuit neighbours; a middle
  relay learns neither end. ✔
- **A directory / HSDir holder.** Holds blinded descriptors it cannot expand into a
  service list. ✔
- **A service you connect to.** Learns *that* someone asked and *what* they asked, but
  not *who* (no client IP). ✔ for "who", ✘ for "what" (see the expert-layer note).
- **Someone who knows a service's name.** Can reach it, and (because the name→key binding
  is on-chain and public) can learn its Layer-1 key — but still not its IP. Partial.

## What it does NOT protect against

- **A global passive adversary (GPA).** An attacker who can watch traffic at both ends of
  a circuit can correlate timing and volume to link client and service. This is the
  known, unsolved limit of low-latency onion routing (Tor has it too). Padding raises the
  cost; it does not remove the attack.
- **Enough adversary relays.** Anonymity is only as large as the honest relay set. If an
  attacker runs a big fraction of relays, the chance they occupy both the guard and the
  terminal/rendezvous of a circuit — and so correlate it — rises sharply. Small networks
  are trivially deanonymised (see below).
- **Guard compromise.** Your guard sees your IP. A hostile or coerced guard, combined with
  visibility near the service, deanonymises you. Guard pinning bounds *how often* you
  expose yourself to a new potential adversary; it does not make the guard trustworthy.
- **Endpoint/content leaks.** The overlay hides the network path, not what you send. A
  request that carries an identifier, a login, or a self-describing payload deanonymises
  at the application layer regardless of the circuit.

## Where our current deployments are NOT anonymous

The development networks stood up with the `dev-cluster` tooling — a standalone node, a
multi-host cluster, and a model-backed expert node — are **development** networks. They
are explicitly non-anonymous, for three independent reasons, any one of which is fatal:

1. **`axon.allow_same_network: true`.** The path-selection code normally requires each
   hop to sit in a *different* network prefix (`runtime/client.go` `pickPath`: one relay
   per prefix). That is the mechanism that stops one network vantage point from seeing a
   whole circuit. We turn it off so a cluster whose relays share a single `/24` (one host,
   or one LAN) can form circuits at all. With it on, **a single observer on that subnet
   sees every hop** — there is no path diversity to hide behind. This flag is for test
   networks only; a real deployment must leave it false.
2. **A tiny relay set (6).** Six relays is at the floor for hidden services to function
   (3 intro points + a rendezvous point + headroom). It is nowhere near an anonymity set:
   with six relays an adversary who runs or watches a couple of them reconstructs circuits
   by elimination. Real anonymity needs *many* relays, run by *independent* operators,
   spread across networks and jurisdictions.
3. **`hops=2`, where used.** The `HOPS=2` variant drops the middle hop for speed. With two
   hops the guard sees the client and the terminal sees the service, so a single relay that
   is both (or two colluding relays) links them directly. `params.MinHops = 2` exists for
   explicitly *non-anonymous* performance use; `hops=3` is the anonymity default.

Treat these deployments as "the overlay works end-to-end," not "the overlay hides me."

## The naming layer leaks (the blockchain `.axon` TLD)

Names buy human usability with on-chain publicity. Be deliberate about the trade:

- **Registration is a public transaction.** `register(name, key)` is an ordinary
  Ethereum tx. The registrant's wallet address, the name, and the target key are all
  public and permanent, and the wallet's funding history can often be traced to a person.
  A name is pseudonymous at best, and only as private as the wallet that bought it.
- **The name→key binding is world-readable.** Anyone can `resolve` any name (or scrape
  the `Registered` events) and learn the Layer-1 key a name points at. So naming a service
  publishes *that service's* address to everyone — it undoes the "you must already know the
  address" property that keeps unnamed Layer-1 services obscure. The operator's *IP* is
  still hidden by the hidden-service mechanism; the service's *identity key* is not.
- **Resolution leaks the query.** A plain `eth_call` to an RPC provider tells that
  provider which name you are resolving, and when. Reading the same state *trustlessly*
  through `internal/ethproof` (an `eth_getProof` against a BLS-verified header) removes the
  need to *trust* the RPC's answer, but the RPC still sees the request. True query privacy
  needs a local chain, a private-information-retrieval scheme, or a trusted local resolver.
- **Names are guessable.** The registry keys on `keccak256(name)`; short or dictionary
  names are enumerable. Obscurity of a name is not a security property.

Rule of thumb: if a service must stay hidden, keep it **Layer-1 only** — reachable by its
`<56>.key.axon` address, never registered under a name. Name the things you *want* found.

## The AI / expert layer

Routing model inference over the overlay (`/expert/<uid>/forward`) hides *who* is asking
(the requester's IP never reaches the expert node or its model backend), but the expert
node and the model see the *prompt content* in cleartext — they must, to answer it. The
overlay gives requester anonymity, not content confidentiality from the service operator.
If the prompt itself is sensitive to the operator, the overlay does not help; that needs a
different construction (client-side computation, or confidential compute), which is
incompatible with handing a plaintext prompt to someone else's model.

## Comparison to Tor

AXON is deliberately Tor-architecture: ntor circuits, pinned guards, rendezvous-based
hidden services, a blinded directory. It adds self-certifying names, an Ethereum-anchored
naming/TLD layer, and an economic/facilitation layer (payments, proof-of-facilitation)
that Tor does not have. It therefore inherits Tor's strengths *and* Tor's hard limits —
chiefly GPA traffic correlation and the dependence on a large, diverse, honest relay set.
It is not a new anonymity primitive; it is a well-trodden one that still has to be deployed
at scale to deliver what the design promises.

## Checklist for an actually-anonymous deployment

- [ ] `allow_same_network` **false** everywhere.
- [ ] `hops` at the default **3** (never 2 for anonymity).
- [ ] Many relays, run by **independent operators**, across **different networks/ASNs and
      jurisdictions** — the larger and more diverse, the better. Not a handful on one host.
- [ ] Guards pinned (default); have a guard-rotation and monitoring policy.
- [ ] Padding enabled; understand it does not defeat a GPA.
- [ ] For names: resolve through `ethproof` (not a trusted RPC), or a local chain; consider
      *not* naming services that must stay hidden; register with a wallet whose history does
      not identify you, and accept that the binding is public forever.
- [ ] Keep application payloads free of identifiers; the overlay cannot un-leak those.
- [ ] Watch the relay set for Sybil growth; lean on the reputation/blind-token machinery.

## Status of the mechanisms (so the analysis is in context)

Built and solid: circuits, guards, rendezvous hidden services, identity blinding, the
loopback proxy, self-certifying addressing. Present but with caveats: directory-based
discovery instead of the full iterative DHT; a padding layer that is a mitigation, not a
GPA defence; the economic/Sybil layer is partly unwired in this node (see
`DENDRITIC_NETWORK_GAPS.md`). The naming layer here is the minimal first-come `AxonTLD`
registry (`contracts/tld`); the governed, vote-created namespace system is a larger,
unported subsystem in the sibling checkout.
