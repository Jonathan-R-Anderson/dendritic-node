package servicepolicy

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"testing"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
)

// addr makes a real, parseable <56 base32>.key.axon address from a fresh key.
func addr(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return identity.FullAddress(pub)
}

func quietPolicy(opts Options) *Policy {
	opts.Logger = log.New(io.Discard, "", 0)
	return New(opts)
}

func TestDefaultIsPermissive(t *testing.T) {
	p := quietPolicy(Options{})
	a := addr(t)
	if d := p.Evaluate(a); !d.Allow {
		t.Fatalf("empty policy refused %s: %s", a, d.Reason)
	}
	if blocked, _ := p.Gate(a); blocked {
		t.Fatal("empty policy blocked a dial")
	}
}

func TestOperatorDenyAndAllowListsAndMinGrade(t *testing.T) {
	denied := addr(t)
	allowed := addr(t)
	lowGraded := addr(t)
	highGraded := addr(t)
	ungraded := addr(t)

	p := quietPolicy(Options{
		Enforce:  true,
		MinGrade: "B", // floor = 80
		Allow:    []string{allowed},
		Deny:     []string{denied},
	})
	doc := &NetworkPolicy{Grades: map[string]int{
		lowGraded:  72, // C, below B
		highGraded: 95, // A
		allowed:    10, // F — but on the allow list, so grade is bypassed
	}}
	p.SetDocument(doc.canonical())

	if d := p.Evaluate(denied); d.Allow {
		t.Fatal("deny-list address was allowed")
	}
	if d := p.Evaluate(allowed); !d.Allow {
		t.Fatalf("allow-list address refused despite bypass: %s", d.Reason)
	}
	if d := p.Evaluate(lowGraded); d.Allow {
		t.Fatalf("grade C admitted under a B floor")
	}
	if d := p.Evaluate(highGraded); !d.Allow {
		t.Fatalf("grade A refused under a B floor: %s", d.Reason)
	}
	// Ungraded is admitted by default even with a floor set.
	if d := p.Evaluate(ungraded); !d.Allow {
		t.Fatalf("ungraded service refused without deny_unknown: %s", d.Reason)
	}
}

func TestDenyUnknownRefusesUngraded(t *testing.T) {
	a := addr(t)
	p := quietPolicy(Options{Enforce: true, MinGrade: "C", DenyUnknown: true})
	if d := p.Evaluate(a); d.Allow {
		t.Fatal("ungraded service admitted despite deny_unknown")
	}
}

func TestSuspensionDeniesAndTakesPrecedenceOverAllow(t *testing.T) {
	suspended := addr(t)
	p := quietPolicy(Options{Enforce: true, Allow: []string{suspended}})
	doc := &NetworkPolicy{Suspended: map[string]Suspension{
		suspended: {Reason: "malware distribution", ProposalID: 7},
	}}
	p.SetDocument(doc.canonical())

	d := p.Evaluate(suspended)
	if d.Allow {
		t.Fatal("DAO-suspended service was allowed despite being on the allow list")
	}
	if !d.Suspended {
		t.Fatal("decision did not mark the service suspended")
	}
}

func TestDenyListBeatsSuspension(t *testing.T) {
	// Precedence: an operator deny is evaluated before the suspension, so the
	// reason the operator sees is their own rule.
	a := addr(t)
	p := quietPolicy(Options{Enforce: true, Deny: []string{a}})
	doc := &NetworkPolicy{Suspended: map[string]Suspension{a: {Reason: "x"}}}
	p.SetDocument(doc.canonical())
	d := p.Evaluate(a)
	if d.Allow || d.Reason != "operator deny list" {
		t.Fatalf("expected operator-deny precedence, got allow=%v reason=%q", d.Allow, d.Reason)
	}
}

func TestGateLogOnlyNeverBlocks(t *testing.T) {
	a := addr(t)
	// Same deny, two modes.
	logOnly := quietPolicy(Options{Enforce: false, Deny: []string{a}})
	if blocked, _ := logOnly.Gate(a); blocked {
		t.Fatal("log-only mode blocked a dial")
	}
	if d := logOnly.Evaluate(a); d.Allow {
		t.Fatal("Evaluate should still report the refusal in log-only mode")
	}
	enforcing := quietPolicy(Options{Enforce: true, Deny: []string{a}})
	if blocked, reason := enforcing.Gate(a); !blocked || reason == "" {
		t.Fatalf("enforce mode did not block: blocked=%v reason=%q", blocked, reason)
	}
}

func TestLetterAndParseGrade(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{{-1, "?"}, {0, "F"}, {59, "F"}, {60, "D"}, {75, "C"}, {85, "B"}, {90, "A"}, {100, "A"}}
	for _, c := range cases {
		if got := Letter(c.score); got != c.want {
			t.Errorf("Letter(%d)=%q want %q", c.score, got, c.want)
		}
	}
	for in, want := range map[string]int{"": -1, "A": 90, "b": 80, "C": 70, "D": 60, "F": 0, "73": 73, "x": -1, "250": 100} {
		if got := parseGrade(in); got != want {
			t.Errorf("parseGrade(%q)=%d want %d", in, got, want)
		}
	}
}

func TestMalformedAllowEntriesAreDropped(t *testing.T) {
	good := addr(t)
	p := quietPolicy(Options{Enforce: true, Allow: []string{good, "not-an-address", ""}})
	if !p.allow[good] {
		t.Fatal("valid allow entry was dropped")
	}
	if len(p.allow) != 1 {
		t.Fatalf("expected 1 valid allow entry, got %d", len(p.allow))
	}
}
