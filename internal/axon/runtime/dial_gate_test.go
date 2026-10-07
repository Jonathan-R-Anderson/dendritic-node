package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
)

type blockGate struct{ reason string }

func (b blockGate) Gate(string) (bool, string) { return true, b.reason }

// recordGate records the address it was asked about, then blocks — blocking so
// remoteFor returns before spawning connect() against a bare test Runtime.
type recordGate struct{ seen *string }

func (g recordGate) Gate(addr string) (bool, string) { *g.seen = addr; return true, "recorded" }

// TestRemoteForEnforcesGate: a blocking gate refuses the dial immediately, with
// its reason, before any descriptor fetch or circuit build. The gate is the one
// place a grade floor or DAO suspension can act.
func TestRemoteForEnforcesGate(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	addr := identity.FullAddress(pub)

	rt := &Runtime{
		cfg:   Config{Gate: blockGate{reason: "DAO-suspended: fraud"}},
		ctx:   context.Background(),
		dials: map[string]*remote{},
	}
	_, err := rt.remoteFor(context.Background(), addr)
	if err == nil {
		t.Fatal("blocked service was not refused")
	}
	if !strings.Contains(err.Error(), "refused by policy") || !strings.Contains(err.Error(), "fraud") {
		t.Fatalf("refusal did not carry the policy reason: %v", err)
	}
	// Nothing should have been recorded for a refused dial.
	if len(rt.dials) != 0 {
		t.Fatal("a refused dial left a remote entry behind")
	}
}

// TestRemoteForGateReceivesNormalizedAddress: the gate is consulted with the
// canonical lowercase .key.axon key, so operator/doc lists match regardless of
// how the address was typed.
func TestRemoteForGateReceivesNormalizedAddress(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	full := identity.FullAddress(pub)

	var seen string
	rt := &Runtime{
		cfg:   Config{Gate: recordGate{seen: &seen}},
		ctx:   context.Background(),
		dials: map[string]*remote{},
	}
	// Pass an upper-cased variant; the gate must see the normalized form.
	_, _ = rt.remoteFor(context.Background(), strings.ToUpper(full[:4])+full[4:])
	if seen != strings.ToLower(full) {
		t.Fatalf("gate saw %q, want normalized %q", seen, strings.ToLower(full))
	}
}
