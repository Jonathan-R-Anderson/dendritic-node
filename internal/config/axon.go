package config

import (
	"errors"
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/names"
)

// AxonConfig places the node on AXON, the network's own anonymous overlay. It
// replaced I2P: peers reach each other as AXON hidden services, so no node
// learns another's IP, and there is no router, SAM bridge or HTTP proxy to
// install beside the node.
//
// Every node can be a client and host services. Relaying -- carrying other
// nodes' circuits -- is what makes the overlay exist at all, and it needs an
// address the internet can reach, so it is opt-in: a node behind NAT stays a
// pure client and still stores, serves and is reachable through rendezvous.
type AxonConfig struct {
	// Listen are libp2p multiaddrs that accept AXON links, e.g.
	// "/ip4/0.0.0.0/tcp/4001" and "/ip4/0.0.0.0/udp/4001/quic-v1". Only a relay
	// needs them; empty means outbound only.
	Listen []string `json:"listen,omitempty"`
	// Relay carries other nodes' circuits and publishes this node in the relay
	// directory. It needs Listen and a port the internet can reach.
	//
	// A node does not have to set this explicitly: a node that has declared a
	// reachable address (both Listen and Announce) relays BY DEFAULT, so every
	// participant that CAN route does -- there is no separate, designated backbone,
	// the way I2P makes every router a participant. RelayOff opts such a node back
	// out. EffectiveRelay() is the value the runtime actually uses.
	Relay bool `json:"relay"`
	// RelayOff declines relaying even though this node has a reachable address.
	// It only matters when Listen+Announce are set (otherwise the node cannot
	// relay anyway); use it for a public box that should stay a pure client.
	RelayOff bool `json:"relay_off,omitempty"`
	// Announce are the "ip:port" addresses a relay publishes, for when Listen
	// binds a wildcard. Empty derives them from Listen.
	Announce []string `json:"announce,omitempty"`
	// Seeds are relays to join the overlay through, as
	// "/ip4/1.2.3.4/tcp/4001/p2p/12D3Koo...". Empty means the relays named in
	// the signed bootstrap document, which is the ordinary case.
	Seeds []string `json:"seeds,omitempty"`
	// Origin is the coordinator's AXON service address, <56 base32>.key.axon.
	// When it is known, leases, revocations and the bootstrap document go to it
	// through the overlay rather than to the clearnet domain. Empty means the
	// address the signed bootstrap document names, if any.
	Origin string `json:"origin,omitempty"`
	// ProxyListen is a loopback HTTP proxy that reaches .key.axon addresses
	// (and nothing else), so a browser or port scanner on this machine can
	// reach a DCS container or any other AXON service. Empty disables it.
	ProxyListen string `json:"proxy_listen,omitempty"`
	// Hops is the circuit length. Zero means the anonymity-preserving default
	// (params.DefaultHops, 3). Set it to 2 only for an explicitly non-anonymous
	// performance or test deployment; the runtime refuses anything below MinHops.
	Hops int `json:"hops,omitempty"`
	// AllowSameNetwork lets a circuit use relays that share one network prefix.
	// A real deployment MUST leave this false -- path diversity across networks
	// is what the anonymity rests on. Set it true ONLY for a development or test
	// cluster whose relays all sit on one LAN (e.g. a single /24), where the
	// diversity rule would otherwise reject every path. Off by default.
	AllowSameNetwork bool `json:"allow_same_network,omitempty"`
	// NameRPC and NameContract enable name resolution: a human `.axon` name is
	// looked up in the AxonTLD registry (contracts/tld) at NameContract over the
	// Ethereum JSON-RPC NameRPC, and the loopback proxy dials the <56 base32>.key.axon
	// it points at. Both empty disables names -- only self-certifying addresses
	// are reachable (the default).
	NameRPC      string `json:"name_rpc,omitempty"`
	NameContract string `json:"name_contract,omitempty"`
	// NameSuffixes adds single TLD labels (e.g. com); axon is always implicit.
	NameSuffixes []string `json:"name_suffixes,omitempty"`
	// NameMissingFallback permits exit routing only for definitively unregistered additional-suffix names.
	NameMissingFallback bool `json:"name_missing_fallback,omitempty"`
	// NameLegacyContract enables the old single-key ABI for .axon only.
	NameLegacyContract bool `json:"name_legacy_contract,omitempty"`
	// Exit makes this node a clearnet EXIT (outproxy): it publishes a hidden
	// service that forwards requests out to the ordinary internet on a client's
	// behalf. OFF by default and emphatically opt-in -- an exit carries other
	// people's traffic under its own IP, the role Tor exits take the heat for.
	// ExitAllowPrivate additionally permits destinations on private/loopback/
	// link-local ranges (default false: an exit refuses them, so it cannot be
	// used to reach its operator's own LAN -- basic SSRF protection).
	Exit             bool `json:"exit,omitempty"`
	ExitAllowPrivate bool `json:"exit_allow_private,omitempty"`
	// ExitVia routes this node's clearnet requests (any non-.axon host asked of
	// the loopback proxy) THROUGH the exit at this address, as <56 base32>.key.axon
	// or <addr>:port. Empty keeps the default: clearnet is refused, there is no exit.
	ExitVia string `json:"exit_via,omitempty"`
}

// DefaultProxyListen is where the AXON proxy listens unless configured.
const DefaultProxyListen = "127.0.0.1:4480"

// EffectiveRelay is whether this node relays for the overlay. A node relays if it
// asked to (Relay), OR -- the decentralising default -- if it has declared a
// reachable address (both Listen and Announce), so every node that can route does,
// without a designated backbone. RelayOff overrides the default for a public node
// that wants to stay a pure client. A node with no reachable address never relays.
func (a AxonConfig) EffectiveRelay() bool {
	if a.RelayOff {
		return false
	}
	return a.Relay || (len(a.Listen) > 0 && len(a.Announce) > 0)
}

// Validate checks the AXON settings a running node consumes.
func (a AxonConfig) Validate() error {
	if (a.NameRPC == "") != (a.NameContract == "") {
		return errors.New("name_rpc and name_contract must be configured together")
	}
	for _, s := range a.NameSuffixes {
		if err := names.ValidateSuffix(s); err != nil {
			return fmt.Errorf("name_suffixes: %w", err)
		}
	}
	if len(a.NameSuffixes) > 0 && (a.NameRPC == "" || a.NameLegacyContract) {
		return errors.New("additional name suffixes require a modern registry")
	}
	if a.NameMissingFallback && len(a.NameSuffixes) == 0 {
		return errors.New("name_missing_fallback requires additional suffixes")
	}

	if a.Relay && len(a.Listen) == 0 {
		return errors.New("axon.relay needs axon.listen: a relay nobody can reach is a hole in every path through it")
	}
	for _, value := range a.Listen {
		if _, err := ma.NewMultiaddr(value); err != nil {
			return fmt.Errorf("axon.listen %q is not a multiaddr: %w", value, err)
		}
	}
	for _, value := range a.Announce {
		if _, _, err := net.SplitHostPort(value); err != nil {
			return fmt.Errorf("axon.announce %q must be ip:port: %w", value, err)
		}
	}
	for _, value := range a.Seeds {
		if _, err := peer.AddrInfoFromString(value); err != nil {
			return fmt.Errorf("axon.seeds %q must be a multiaddr ending in /p2p/<id>: %w", value, err)
		}
	}
	if a.ProxyListen != "" {
		host, _, err := net.SplitHostPort(a.ProxyListen)
		if err != nil {
			return fmt.Errorf("axon.proxy_listen %q must be host:port: %w", a.ProxyListen, err)
		}
		// Loopback only: anyone who can reach the proxy can use this node's
		// circuits, and that is a decision for the machine's owner alone.
		if !isLoopback(host) {
			return errors.New("axon.proxy_listen must be a loopback address")
		}
	}
	if a.Origin != "" {
		if _, err := identity.ParseAddress(a.Origin); err != nil {
			return fmt.Errorf("axon.origin %q is not an AXON address (<56 base32>.key.axon)", a.Origin)
		}
	}
	// 0 means the default; otherwise bound it to params' [MinHops, MaxHops] = [2, 4]
	// (kept in sync with internal/axon/params; stated literally to avoid importing it here).
	if a.Hops != 0 && (a.Hops < 2 || a.Hops > 4) {
		return fmt.Errorf("axon.hops %d out of range: 0 (default) or 2..4", a.Hops)
	}
	return nil
}
