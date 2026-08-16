// Package params is the single home for every tunable protocol constant.
//
// P0 test T0.2 is the reason this package exists: the cell size, guard count,
// tunnel lifetime and DHT k/alpha/d must appear here and nowhere else, so that
// a parameter change is one edit and a divergent literal elsewhere in the tree
// is a build failure rather than a silent second opinion.
//
// Values come from the roadmap's Constitution section 5. Where a value is not
// yet settled the constant is present with the agreed default and the comment
// says what would change it.
package params

import "time"

// ---------------------------------------------------------------------------
// Naming (Constitution section 1, as amended by the naming addendum)
// ---------------------------------------------------------------------------

// RootSuffix is the one compile-time naming constant in the system. Namespace
// labels are NOT constants: they are read from the root registry at runtime,
// and a client that hardcodes the namespace set is non-conformant, because the
// set changes by vote.
const RootSuffix = "axon"

// AddressNamespace is the permanently reserved namespace label under which
// self-certifying Layer 1 addresses live, e.g. <56 base32>.key.axon. No vote
// can allocate it, which is what stops Layer 3 shadowing Layer 1.
const AddressNamespace = "key"

// ---------------------------------------------------------------------------
// Cells and circuits (sections 8.1, 8.5)
// ---------------------------------------------------------------------------

const (
	// CellSize is the fixed on-link size of every cell, on every link,
	// regardless of how many hops remain. Padding to a constant size is the
	// property; changing this changes the wire format.
	CellSize = 1024

	// CellHeaderSize is circuit id (8) + cmd (1) + flags (1) + len (2) + reserved (4).
	CellHeaderSize = 16

	// AEADTagSize is reserved at EVERY hop position, not only the ones in use,
	// so that the on-wire size does not reveal the hop count.
	AEADTagSize = 16

	// MaxHops bounds the tag reservation and therefore the payload capacity.
	MaxHops = 4

	// DefaultHops is the standard circuit length: guard, middle, terminal.
	DefaultHops = 3

	// MinHops is permitted only for explicitly non-anonymous performance
	// contexts and is never a default.
	MinHops = 2

	// RelayBuildBudget caps RELAY_BUILD cells per circuit (T5.8, PAR-08).
	//
	// THE NUMBER, derived rather than chosen: MaxHops (4) extension requests,
	// plus section 8.4's two permitted redraws, plus two spare = 8. Tor arrived
	// at the same figure for RELAY_EARLY by the same reasoning.
	//
	// It exists because an unbounded extension budget is an unbounded circuit,
	// and because the early/normal distinction has been used as a signalling
	// side channel between a hostile entry and a hostile directory node.
	RelayBuildBudget = 8

	// DropCellThreshold is how many structurally valid but impossible cells a
	// circuit may attract before it is torn down (T5.9, PAR-28).
	//
	// A SENDME for a closed stream, a DATA cell for a stream that never opened,
	// a TRUNCATED for a hop already gone: each is droppable, and a droppable
	// event nobody counts is a signalling channel.
	DropCellThreshold = 10

	// CircuitIDQuarantine is how long a freed circuit id is withheld from reuse
	// (section 8.4's C_DEAD state). Reusing an id immediately would let a late
	// cell from a dead circuit land on a live one.
	CircuitIDQuarantine = 60 * time.Second

	// MaxCircuitsPerRelay is the global admission cap (P24, PAR-21). It is the
	// bound MaxCircuitsPerLink is not: that one is per link, so an attacker
	// opens more links.
	MaxCircuitsPerRelay = 65536
)

// Circuit lifecycle budgets (section 8.4's state machine). Specified defaults,
// NOT measurements.
const (
	LinkTimeout      = 5 * time.Second
	CreateTimeout    = 10 * time.Second
	ExtendTimeout    = 10 * time.Second
	OpenIdleTimeout  = 60 * time.Second
	ClosingTimeout   = 5 * time.Second
	MaxExtendRedraws = 2
)

// MaxPayload is the usable cell body: everything after the fixed header.
//
// It was CellSize - CellHeaderSize - (AEADTagSize * MaxHops), reserving 64 bytes
// for a per-hop tag stack so that payload capacity could not leak path length.
// PAR-01 found that tag stack to be a cross-hop tagging channel and section 81.1
// withdrew it; P5a replaced it with a wide-block permutation over the whole
// body, which needs no tags and therefore no reservation.
//
// The reservation's PURPOSE survives and is now structural: the body is one
// fixed-size permuted block whatever the path length, so capacity still cannot
// leak it. AEADTagSize and MaxHops are retained -- MaxHops still bounds path
// length, and AEADTagSize is still the end-to-end authenticator's size.
const MaxPayload = CellSize - CellHeaderSize

// ---------------------------------------------------------------------------
// Guards (section 8.5)
// ---------------------------------------------------------------------------
//
// Workstream 1 of the hard-problems programme found these parameters sit at a
// poor point on the exposure curve: at 2 guards on a 45-day rotation a client
// passes through a hostile guard within a year with probability 0.56 against a
// 5% adversary. They are kept here as the current agreed values, and P17 is the
// phase that is expected to change them.

const (
	PrimaryGuards      = 2
	GuardRotation      = 45 * 24 * time.Hour
	GuardListLifetime  = 90 * 24 * time.Hour
	VanguardLayer2Size = 4
	VanguardLayer3Size = 8
)

// ---------------------------------------------------------------------------
// Tunnels and pools (section 9.2)
// ---------------------------------------------------------------------------

const (
	TunnelLifetime      = 10 * time.Minute
	TunnelRebuildAt     = 0.70 // fraction of lifetime at which build-ahead starts
	InboundPoolSize     = 3
	OutboundPoolSize    = 3
	PoolSpares          = 1
	DescriptorLifetime  = 3 * time.Hour
	DescriptorRepublish = 1 * time.Hour
)

// ---------------------------------------------------------------------------
// Epochs and time periods (sections 5.4, 7.2)
// ---------------------------------------------------------------------------

const (
	// EpochLength is the rotation period for the shared random value and
	// therefore for KadID placement.
	EpochLength = 24 * time.Hour

	// PeriodLength is the blinded-descriptor-key rotation period. It is a
	// separate constant from EpochLength on purpose: they rotate different
	// things and there is no requirement that they stay equal.
	PeriodLength = 24 * time.Hour

	// PeriodLengthSeconds is PeriodLength as the u64 that enters the blinding
	// KDF context. Kept explicit because the KDF hashes the number, so a unit
	// mistake here silently changes every blinded key.
	PeriodLengthSeconds = uint64(86400)

	// PeriodOverlap is how long the previous period's descriptor stays valid,
	// so a client with a slightly stale clock still resolves.
	PeriodOverlap = 12 * time.Hour
)

// ---------------------------------------------------------------------------
// DHT (section 7)
// ---------------------------------------------------------------------------

const (
	KademliaK         = 20 // bucket size
	KademliaAlpha     = 3  // lookup concurrency
	KademliaDisjoint  = 3  // disjoint lookup paths, S/Kademlia style
	ReplicationFactor = 8  // r, across distinct /24, /48 and ASN
	IPv4DiversityBits = 24
	IPv6DiversityBits = 48
)

// ---------------------------------------------------------------------------
// Storage (section 10)
// ---------------------------------------------------------------------------
//
// Read from the existing node's config defaults rather than invented: the
// deployed default is 6 data + 3 parity over 1 MiB chunks.

const (
	DataShards   = 6
	ParityShards = 3
	ChunkBytes   = 1 << 20
)

// ---------------------------------------------------------------------------
// Multipath (Part VI)
// ---------------------------------------------------------------------------

const (
	// MultipathDefaultPaths is deliberately 2, not 8: two paths capture most
	// of the latency and resilience gain at the smallest increase in the
	// number of relays that observe some of the stream.
	MultipathDefaultPaths = 2
	MultipathMaxPaths     = 8
)
