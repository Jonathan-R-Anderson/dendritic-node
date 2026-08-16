// Package peer is AXON's L2 membership layer: which peers exist, which are
// reachable, and — the part that has never existed here before — where they sit
// in the address space.
//
// Section 1.4's finding is why this package matters: under the I2P transport no
// node ever observed a peer's IP, so the storage placement engine could only
// guarantee "distinct peers", never distinct networks. Every diversity claim in
// the roadmap (path selection, shard placement, eclipse resistance) rests on
// inputs that did not exist. P3 produces them.
package peer

import (
	"fmt"
	"net"
	"net/netip"

	asnutil "github.com/libp2p/go-libp2p-asn-util"
)

// Failure domains, coarsest first. A peer set that is distinct at a coarser
// level is distinct at every finer one, which is what lets Sample treat these
// as a ladder rather than independent flags.
type Domain int

const (
	DomainPrefix Domain = iota // /24 for IPv4, /48 for IPv6
	DomainASN                  // autonomous system
)

// ASNUnknown is the zero ASN, meaning "not determined".
//
// It is a distinct concept from "ASN 0" and must never be treated as a value
// two peers can share: two peers with unknown ASNs are not known to be in the
// same AS, and collapsing them would silently under-count diversity in exactly
// the direction that flatters the network.
const ASNUnknown uint32 = 0

// Annotation is where one address sits in the address space.
type Annotation struct {
	Addr netip.Addr
	// Prefix is the failure-domain prefix: /24 for IPv4, /48 for IPv6. Stored
	// as a netip.Prefix so comparisons are exact rather than string-wise.
	Prefix netip.Prefix
	// ASN is the autonomous system, or ASNUnknown.
	ASN uint32
	// ASNSource records how the ASN was determined, so a caller can tell a
	// looked-up answer from an absent one without inspecting the value.
	ASNSource ASNSource
}

// ASNSource is the provenance of an ASN annotation.
type ASNSource uint8

const (
	// ASNSourceNone means no lookup succeeded. See the IPv4 note on Annotate.
	ASNSourceNone ASNSource = iota
	// ASNSourceTable means the bundled IPv6-to-ASN dataset answered.
	ASNSourceTable
	// ASNSourceOperator means an operator supplied the mapping out of band.
	ASNSourceOperator
)

func (s ASNSource) String() string {
	switch s {
	case ASNSourceTable:
		return "table"
	case ASNSourceOperator:
		return "operator"
	default:
		return "none"
	}
}

// PrefixLenV4 and PrefixLenV6 are the failure-domain widths from the roadmap's
// section 7.5 replication rules and section 8.7 path diversity.
const (
	PrefixLenV4 = 24
	PrefixLenV6 = 48
)

// Annotate places an address in its failure domains.
//
// THE IPv4 ASN GAP, STATED RATHER THAN HIDDEN
// The vendored go-libp2p-asn-util resolves ASNs for IPv6 only; it carries no
// IPv4 dataset. So for IPv4 peers -- which today is most of them -- ASN comes
// back ASNUnknown with source "none", and any diversity constraint that depends
// on ASN degrades to prefix-only for those peers.
//
// This is reported, never silently substituted. The failure mode it avoids is
// the one section 56.2 names: a diversity mechanism built against an
// unobservable property reports success and delivers nothing. A caller that
// needs true ASN diversity for IPv4 must supply a resolver (see Annotator), and
// until one exists the honest claim is "distinct /24", not "distinct AS".
func Annotate(addr netip.Addr) (Annotation, error) {
	if !addr.IsValid() {
		return Annotation{}, fmt.Errorf("axon/peer: invalid address")
	}
	addr = addr.Unmap()

	bits := PrefixLenV4
	if addr.Is6() {
		bits = PrefixLenV6
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return Annotation{}, fmt.Errorf("axon/peer: prefix /%d for %s: %w", bits, addr, err)
	}

	ann := Annotation{Addr: addr, Prefix: prefix, ASN: ASNUnknown, ASNSource: ASNSourceNone}
	if addr.Is6() {
		if asn := asnutil.AsnForIPv6(net.IP(addr.AsSlice())); asn != 0 {
			ann.ASN, ann.ASNSource = asn, ASNSourceTable
		}
	}
	return ann, nil
}

// Annotator resolves annotations, optionally with an operator-supplied ASN
// table that fills the IPv4 gap.
//
// The table is deliberately operator-supplied rather than fetched: a node that
// asked the network which addresses belong to which AS would be asking the
// thing it is trying to measure, and an adversary who answers that question
// controls every diversity decision downstream.
type Annotator struct {
	// ASNv4 maps an IPv4 prefix to an ASN. Longest match wins.
	ASNv4 []PrefixASN
}

// PrefixASN is one operator-supplied mapping.
type PrefixASN struct {
	Prefix netip.Prefix
	ASN    uint32
}

// Annotate is Annotate plus the operator table.
func (a *Annotator) Annotate(addr netip.Addr) (Annotation, error) {
	ann, err := Annotate(addr)
	if err != nil {
		return Annotation{}, err
	}
	if ann.ASN != ASNUnknown {
		return ann, nil
	}
	best := -1
	bestBits := -1
	for i, m := range a.ASNv4 {
		if m.Prefix.Contains(ann.Addr) && m.Prefix.Bits() > bestBits {
			best, bestBits = i, m.Prefix.Bits()
		}
	}
	if best >= 0 {
		ann.ASN, ann.ASNSource = a.ASNv4[best].ASN, ASNSourceOperator
	}
	return ann, nil
}

// SameDomain reports whether two annotations share the given failure domain.
//
// Unknown ASNs are never "the same": see ASNUnknown. This is the conservative
// direction -- it treats two unknowns as potentially distinct, so a sampler
// will not refuse to draw them, and the caller is told via ASNSource that the
// ASN constraint could not actually be applied.
func SameDomain(a, b Annotation, d Domain) bool {
	switch d {
	case DomainPrefix:
		return a.Prefix == b.Prefix
	case DomainASN:
		if a.ASN == ASNUnknown || b.ASN == ASNUnknown {
			return false
		}
		return a.ASN == b.ASN
	default:
		return false
	}
}
