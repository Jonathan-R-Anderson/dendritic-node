// Package servicepolicy decides whether THIS node will route to a given hidden
// service, keyed by the service's self-certifying identity (its
// <56 base32>.key.axon address).
//
// Why it lives at the client and nowhere else: a service's true identity is
// visible only on the dialing client's own path. The HSDir that holds its
// descriptor sees a per-period blinded key; the intro point sees a throwaway
// per-publish auth key; the rendezvous point sees only a cookie. So a decision
// keyed by the service identity can be enforced ONLY by the client that is
// about to connect -- which also makes it, by construction, that operator's own
// routing choice rather than a takedown imposed on the network. This package is
// the engine; the runtime consults it at runtime.remoteFor (the one place every
// dial funnels through) via the ServiceGate interface.
//
// It composes three inputs, in strict precedence:
//  1. the operator's local deny list      (hard refuse, always)
//  2. the DAO suspension list              (refuse; from a signed network doc)
//  3. the operator's local allow list      (bypass the grade floor)
//  4. a per-service grade floor            (refuse below min; grades from the doc)
//
// Suspensions and grades arrive in a signed NetworkPolicy document (document.go)
// so the node need not read the chain on the hot path. Everything defaults to
// permissive: with no configuration the gate admits every service, and in
// log-only mode (the default when any policy IS configured) it records what it
// WOULD refuse without refusing -- a safe rollout, matching the rest of the
// overlay where reputation never bans and the DHT never moderates.
package servicepolicy

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
)

// Decision is the outcome of evaluating one service address.
type Decision struct {
	// Allow is whether this node will route to the service.
	Allow bool
	// Reason is a short human string for logs and the refusal error.
	Reason string
	// Grade is the service's score in [0,100], or -1 when unknown.
	Grade int
	// Suspended is true when the DAO has suspended the service, regardless of
	// whether an operator allow entry or log-only mode lets it through anyway.
	Suspended bool
}

// Letter is the grade as a letter (A–F), or "?" when unknown.
func Letter(grade int) string {
	switch {
	case grade < 0:
		return "?"
	case grade >= 90:
		return "A"
	case grade >= 80:
		return "B"
	case grade >= 70:
		return "C"
	case grade >= 60:
		return "D"
	default:
		return "F"
	}
}

// parseGrade turns a config min_grade ("", a letter A–F, or a number 0–100) into
// a floor score, or -1 for "no minimum". A letter maps to the bottom of its band
// (C => 70), so min_grade "C" admits C, B and A.
func parseGrade(s string) int {
	s = strings.TrimSpace(strings.ToUpper(s))
	switch s {
	case "":
		return -1
	case "A":
		return 90
	case "B":
		return 80
	case "C":
		return 70
	case "D":
		return 60
	case "F":
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			n = 0
		}
		if n > 100 {
			n = 100
		}
		return n
	}
	return -1
}

// Policy is the node's service-routing policy. Safe for concurrent use: the
// network document is swapped atomically while the local config is fixed at
// construction.
type Policy struct {
	enforce     bool
	minGrade    int // -1 = no floor
	denyUnknown bool
	allow       map[string]bool
	deny        map[string]bool

	doc atomic.Pointer[NetworkPolicy]
	log *log.Logger

	mu       sync.Mutex
	loggedNo map[string]bool // de-dup log-only "would refuse" lines per address
}

// Options configures a Policy. Address lists accept <56 base32>.key.axon forms;
// malformed entries are dropped with a warning rather than failing the node.
type Options struct {
	// Enforce makes refusals real. False is log-only: the gate records what it
	// would refuse and admits anyway, for safe rollout.
	Enforce bool
	// MinGrade is "", a letter A–F, or a number 0–100. Empty disables the floor.
	MinGrade string
	// DenyUnknown refuses a service that has no grade in the document. Off by
	// default, because an unknown service is the common case on a young network.
	DenyUnknown bool
	Allow       []string
	Deny        []string
	Logger      *log.Logger
}

// New builds a Policy from operator options. It never fails: bad address
// entries are logged and skipped so a typo cannot take the node offline.
func New(opts Options) *Policy {
	lg := opts.Logger
	if lg == nil {
		lg = log.Default()
	}
	p := &Policy{
		enforce:     opts.Enforce,
		minGrade:    parseGrade(opts.MinGrade),
		denyUnknown: opts.DenyUnknown,
		allow:       normalizeSet(opts.Allow, "allow", lg),
		deny:        normalizeSet(opts.Deny, "deny", lg),
		log:         lg,
		loggedNo:    map[string]bool{},
	}
	p.doc.Store(&NetworkPolicy{}) // empty doc until one is loaded
	return p
}

// normalizeSet lowercases and validates a list of service addresses into a set.
func normalizeSet(list []string, which string, lg *log.Logger) map[string]bool {
	out := map[string]bool{}
	for _, a := range list {
		norm, ok := normalizeAddr(a)
		if !ok {
			lg.Printf("servicepolicy: ignoring malformed %s address %q", which, a)
			continue
		}
		out[norm] = true
	}
	return out
}

// normalizeAddr validates and canonicalises a service address. It accepts the
// bare 56-char base32 label with or without the ".key.axon" suffix.
func normalizeAddr(a string) (string, bool) {
	a = strings.ToLower(strings.TrimSpace(a))
	if a == "" {
		return "", false
	}
	if !strings.Contains(a, ".") {
		a += ".key.axon"
	}
	pub, err := identity.ParseAddress(a)
	if err != nil {
		return "", false
	}
	return strings.ToLower(identity.FullAddress(pub)), true
}

// SetDocument swaps in a new signed network document (grades + suspensions).
func (p *Policy) SetDocument(doc *NetworkPolicy) {
	if doc == nil {
		doc = &NetworkPolicy{}
	}
	p.doc.Store(doc)
}

// Document returns the current network document (never nil).
func (p *Policy) Document() *NetworkPolicy { return p.doc.Load() }

// Evaluate computes the routing decision for a service address without any
// side effect. addr may be the bare label or the full .key.axon form.
func (p *Policy) Evaluate(addr string) Decision {
	norm, ok := normalizeAddr(addr)
	if !ok {
		// An unparseable address is not ours to grade; let the dial path fail
		// it with its own, clearer error.
		return Decision{Allow: true, Reason: "unparseable address", Grade: -1}
	}
	doc := p.doc.Load()

	if p.deny[norm] {
		return Decision{Allow: false, Reason: "operator deny list", Grade: doc.gradeOf(norm)}
	}
	if s, suspended := doc.suspension(norm); suspended {
		reason := "DAO-suspended"
		if s.Reason != "" {
			reason += ": " + s.Reason
		}
		return Decision{Allow: false, Reason: reason, Grade: doc.gradeOf(norm), Suspended: true}
	}
	grade := doc.gradeOf(norm)
	if p.allow[norm] {
		return Decision{Allow: true, Reason: "operator allow list", Grade: grade}
	}
	if p.minGrade >= 0 {
		if grade < 0 {
			if p.denyUnknown {
				return Decision{Allow: false, Reason: "no grade and deny_unknown set", Grade: -1}
			}
			return Decision{Allow: true, Reason: "ungraded (admitted)", Grade: -1}
		}
		if grade < p.minGrade {
			return Decision{Allow: false,
				Reason: "grade " + Letter(grade) + " below minimum " + Letter(p.minGrade), Grade: grade}
		}
	}
	return Decision{Allow: true, Reason: "ok", Grade: grade}
}

// Gate is the ServiceGate the runtime calls at remoteFor. It returns blocked
// only in enforce mode; in log-only mode it records a one-time "would refuse"
// line per address and returns blocked=false so the dial proceeds.
func (p *Policy) Gate(addr string) (blocked bool, reason string) {
	d := p.Evaluate(addr)
	if d.Allow {
		return false, ""
	}
	if p.enforce {
		return true, d.Reason
	}
	p.mu.Lock()
	if !p.loggedNo[addr] {
		p.loggedNo[addr] = true
		p.log.Printf("servicepolicy: log-only, would refuse %s (%s)", addr, d.Reason)
	}
	p.mu.Unlock()
	return false, ""
}

// Enforcing reports whether refusals are real (false = log-only).
func (p *Policy) Enforcing() bool { return p.enforce }
