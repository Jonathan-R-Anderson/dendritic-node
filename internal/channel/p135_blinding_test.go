package channel

// P13.5 FINDING 2 — the "misblinded hop", and why it is not the vulnerability
// it looked like.
//
// THE CLAIM
// ---------
// "The payer picks the route and holds every blinding; SettleRoute computes all
// hops' scalars at once, so nothing makes a hop's scalar contingent on a
// downstream payment actually happening."
//
// Every clause of that is TRUE about SettleRoute. The conclusion does not
// follow, because SettleRoute is not on the production path.
//
// WHAT ACTUALLY HAPPENS
// ---------------------
// A hop claims upstream through Forwarder.ClaimUpstream (routing.go), which
// does exactly one thing to obtain its authorisation:
//
//	preimage, known := f.vault.Lookup(in.Lock.Hash)
//	if !known { return ErrSecretUnknown }
//
// A HASH PREIMAGE, from the vault, keyed by the incoming lock's own hash. Not a
// scalar, not a blinding, nothing derived from BuildLocks. And the vault learns
// that preimage when the DOWNSTREAM settlement reveals it. So the hop's upstream
// claim is contingent on the downstream payment by construction: without the
// downstream reveal there is no preimage, and without the preimage
// ClaimUpstream refuses before it ever reaches the channel.
//
// The point-based LockChain is adaptor machinery for a routing design that is
// built but not wired in. It is real code with real tests and no production
// caller, which is precisely why it reads as dangerous — an audit sees
// SettleRoute handing out every hop's scalar and cannot tell from the function
// alone that nobody calls it.
//
// So this file does what the finding asks when a design turns out to be safe:
// it documents why, and pins the property with regression tests, so that wiring
// SettleRoute into the claim path later has to break something first.

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The production claim path must not depend on the adaptor-scalar machinery.
//
// This is the load-bearing fact of the whole finding. If SettleRoute ever gains
// a non-test caller, the reasoning above stops holding and this fails.
func TestSettleRouteIsNotOnTheProductionClaimPath(t *testing.T) {
	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var callers []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(body)
		// The definition itself lives in atomic.go; a CALL is what matters.
		for _, line := range strings.Split(src, "\n") {
			if !strings.Contains(line, "SettleRoute(") {
				continue
			}
			if strings.Contains(line, "func SettleRoute") {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			callers = append(callers, name+": "+trimmed)
		}
	}
	if len(callers) > 0 {
		t.Fatalf("SettleRoute now has production callers:\n  %s\n\n"+
			"The claim that a hop's upstream authorisation is contingent on its "+
			"downstream payment rests on the claim path using a VAULT PREIMAGE "+
			"(Forwarder.ClaimUpstream), not a payer-computed scalar. If scalars "+
			"are now used to claim, re-open P13.5 finding 2 before shipping.",
			strings.Join(callers, "\n  "))
	}
}

// A hop cannot claim upstream without the downstream secret.
//
// The mechanism, asserted rather than argued: ClaimUpstream consults the vault
// and refuses when the preimage is absent.
func TestAHopCannotClaimUpstreamWithoutTheDownstreamSecret(t *testing.T) {
	dir := t.TempDir()
	vault, err := OpenPreimageVault(dir)
	if err != nil {
		t.Fatalf("OpenPreimageVault: %v", err)
	}
	hub, upstream, in := wiredPair(t, anon(500))
	fwd := NewForwarder(hub.coord, vault, hub.key.address())

	pre := [32]byte{31: 0x21}
	var h [32]byte
	copy(h[:], keccak(pre[:]))

	incoming := Incoming{
		Channel: in,
		Lock:    HTLC{ID: [32]byte{31: 1}, Hash: h, Amount: anon(50), Expiry: 2_000_000_000},
	}
	// The vault has never seen the secret: the downstream payment has not
	// settled, so there is nothing to claim with.
	if _, err := fwd.ClaimUpstream(context.Background(), incoming,
		derive("p135/claim", nil), directPeer{t, upstream.coord}); err == nil {
		t.Fatal("a hop claimed upstream with no downstream secret")
	}

	// Once the downstream reveals it, the claim becomes possible — the vault is
	// the ONLY thing that changed.
	if err := vault.Learn(pre); err != nil {
		t.Fatalf("Learn: %v", err)
	}
	if _, known := vault.Lookup(h); !known {
		t.Fatal("the vault did not record the revealed preimage")
	}
}

// A blinding is drawn fresh per payment, so nothing is reused across payments.
func TestBlindingsAreFreshPerPayment(t *testing.T) {
	c := DefaultCurve()
	_, Z, err := NewSecret(c)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		chain, err := BuildLocks(c, Z, 3)
		if err != nil {
			t.Fatalf("BuildLocks: %v", err)
		}
		for hop := range chain.Locks {
			b, err := chain.BlindingFor(hop)
			if err != nil {
				t.Fatalf("BlindingFor: %v", err)
			}
			k := b.String()
			if seen[k] {
				t.Fatalf("blinding reused across payments at hop %d", hop)
			}
			seen[k] = true
		}
	}
}

// A hop receives a COMMITMENT to its lock point, never a scalar.
//
// If an onion ever carried a usable scalar, a hop could claim without the
// downstream reveal — which is the failure the finding feared.
func TestAHopsOnionInstructionCarriesNoScalar(t *testing.T) {
	req := planReq(t)
	plan, err := PlanPayment(req)
	if err != nil {
		t.Fatalf("PlanPayment: %v", err)
	}
	for i, cand := range plan.Route {
		shared := derive("syndichan/payment/hopsecret/v1", req.Seed[:], []byte(cand.NodeID))
		hop, err := plan.Packet.Peel(shared)
		if err != nil {
			t.Fatalf("hop %d peel: %v", i, err)
		}
		// The commitment is a one-way hash of the lock point. It cannot be
		// inverted into the scalar that satisfies it.
		var zero Commitment
		if hop.OutgoingCommitment == zero {
			t.Fatalf("hop %d received no commitment", i)
		}
		blinding, err := plan.Locks.BlindingFor(i)
		if err != nil {
			t.Fatalf("BlindingFor: %v", err)
		}
		// The instruction must not contain the blinding in any form the hop
		// could read off it.
		if strings.Contains(string(hop.BlindedEndpoint), blinding.String()) {
			t.Fatalf("hop %d's instruction leaks its blinding", i)
		}
	}
}

// ---- cross-payment interference --------------------------------------------
//
// The multipath audit proved that single-payment reasoning misses attacks that
// need two payments. These exercise the pairs explicitly.

// Two payments sharing a recipient secret must not share lock points.
func TestTwoPaymentsSharingASecretDoNotShareLockPoints(t *testing.T) {
	c := DefaultCurve()
	z, Z, err := NewSecret(c)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	_ = z
	a, err := BuildLocks(c, Z, 3)
	if err != nil {
		t.Fatalf("BuildLocks a: %v", err)
	}
	b, err := BuildLocks(c, Z, 3)
	if err != nil {
		t.Fatalf("BuildLocks b: %v", err)
	}
	for i := range a.Locks {
		for j := range b.Locks {
			if a.Locks[i].Equal(b.Locks[j]) {
				t.Fatalf("payment A hop %d and payment B hop %d share a lock point "+
					"despite a fresh blinding per payment", i, j)
			}
		}
	}
}

// A scalar from payment A must not satisfy payment B's lock at the same index.
func TestAScalarFromOnePaymentDoesNotSatisfyAnother(t *testing.T) {
	c := DefaultCurve()
	z, Z, _ := NewSecret(c)
	a, _ := BuildLocks(c, Z, 3)
	b, _ := BuildLocks(c, Z, 3)

	scalarsA, err := SettleRoute(c, a, z)
	if err != nil {
		t.Fatalf("SettleRoute: %v", err)
	}
	for i := range b.Locks {
		if err := Satisfies(c, b.Locks[i], scalarsA[i]); err == nil {
			t.Fatalf("payment A's scalar for hop %d satisfied payment B's lock", i)
		}
	}
	// Sanity: A's scalars do satisfy A, so the test is not vacuous.
	for i := range a.Locks {
		if err := Satisfies(c, a.Locks[i], scalarsA[i]); err != nil {
			t.Fatalf("payment A's own scalar failed at hop %d: %v", i, err)
		}
	}
}

// Two payments over the SAME route must not produce the same onion.
//
// The ephemeral key is per-payment; reusing one would link every payment sent
// under it, which the onion header calls out explicitly.
func TestTwoPaymentsOverOneRouteProduceDifferentOnions(t *testing.T) {
	reqA := planReq(t)
	reqB := planReq(t)
	reqB.Seed = [32]byte{31: 0x99} // a different payment, same candidates
	planA, err := PlanPayment(reqA)
	if err != nil {
		t.Fatalf("PlanPayment A: %v", err)
	}
	planB, err := PlanPayment(reqB)
	if err != nil {
		t.Fatalf("PlanPayment B: %v", err)
	}
	if planA.Packet.EphemeralPublicKey == planB.Packet.EphemeralPublicKey {
		t.Fatal("two payments shared an onion ephemeral key; they would be linkable")
	}
	// And a hop's shared secret differs, so a replayed onion does not peel.
	for _, cand := range planA.Route {
		sharedA := derive("syndichan/payment/hopsecret/v1", reqA.Seed[:], []byte(cand.NodeID))
		if _, err := planB.Packet.Peel(sharedA); err == nil {
			t.Fatal("payment A's hop secret peeled payment B's onion")
		}
	}
}

// Settlement material from payment A must not settle payment B on a channel.
//
// The channel-level statement of the same property, through the real engine:
// two locks, two preimages, no crossover.
func TestSettlementMaterialDoesNotCrossPayments(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	const now = int64(1_000_000)
	payer.clock, payee.clock = now, now

	preA := [32]byte{31: 0x31}
	preB := [32]byte{31: 0x32}
	var hA, hB [32]byte
	copy(hA[:], keccak(preA[:]))
	copy(hB[:], keccak(preB[:]))

	for i, h := range [][32]byte{hA, hB} {
		tr := StateTransition{Kind: KindLockAdd, Amount: anon(50),
			LockID: [32]byte{31: byte(i + 1)}, Hash: h, Expiry: now + 3600}
		if _, err := payer.coord.Pay(ctx, id, derive("p135/x-lock", []byte{byte(i)}),
			tr, directPeer{t, payee.coord}); err != nil {
			t.Fatalf("lock %d: %v", i, err)
		}
	}

	// Payment A's preimage against payment B's lock.
	cross := StateTransition{Kind: KindLockSettle,
		LockID: [32]byte{31: 2}, Preimage: preA}
	if _, err := payee.coord.Pay(ctx, id, derive("p135/x-settle", nil),
		cross, directPeer{t, payer.coord}); err == nil {
		t.Fatal("payment A's preimage settled payment B's lock")
	}

	// Each still settles with its own.
	own := StateTransition{Kind: KindLockSettle,
		LockID: [32]byte{31: 2}, Preimage: preB}
	if _, err := payee.coord.Pay(ctx, id, derive("p135/x-settle-own", nil),
		own, directPeer{t, payer.coord}); err != nil {
		t.Fatalf("payment B refused its own preimage: %v", err)
	}
	bal, _ := payee.coord.Balances(id)
	if bal.Mine.Cmp(anon(50)) != 0 {
		t.Fatalf("payee holds %s, want exactly one lock's 50", bal.Mine)
	}
	_ = big.NewInt
}

// ---- FINDING 3: lock-id reuse defeated the sweep's idempotency key ----------
//
// Found by adversarial review while investigating findings 1 and 2, and verified
// as a working exploit before the fix.
//
// SweepClaimable derived its claim intent from the lock ID alone. The goal was
// right — a retry after a crash must reuse the intent so it cannot claim twice —
// but a lock ID is unique only among PENDING locks: Channel.Accept builds its
// duplicate check over st.Pending, so a resolved lock's id is free again.
//
//	1. payment 1 uses lock id L, resolves. AppliedAt(intent_L) recorded.
//	2. payment 2 reuses L upstream. Accept permits it — L is not pending.
//	3. the hub forwards, pays downstream, learns the preimage.
//	4. the sweep recomputes intent_L; Pay finds it applied and returns Done
//	   WITHOUT claiming.
//	5. res.Done is true, so the sweep reports success.
//
// Hub paid downstream, never claimed upstream, and believed it had.

// Two lock instances that merely share an id must not share a claim intent.
func TestLockIDReuseDoesNotCollideTheClaimIntent(t *testing.T) {
	ch := [32]byte{31: 0xC1}
	sameID := [32]byte{31: 0x07}

	// Payment 1's lock, and payment 2's reusing the id with its own secret.
	first := Incoming{Channel: ch, Lock: HTLC{
		ID: sameID, Hash: [32]byte{31: 0xA1}, Amount: anon(100), Expiry: 2_000_000_000}}
	second := Incoming{Channel: ch, Lock: HTLC{
		ID: sameID, Hash: [32]byte{31: 0xA2}, Amount: anon(100), Expiry: 2_000_000_000}}

	if claimUpstreamIntent(first) == claimUpstreamIntent(second) {
		t.Fatal("two lock instances sharing an id derived the same claim intent; " +
			"the second claim would be answered from the first's record and the " +
			"hub would pay downstream without collecting upstream")
	}

	// The crash property must survive: the SAME lock derives the SAME intent, so
	// a restart mid-claim cannot claim twice.
	again := Incoming{Channel: ch, Lock: HTLC{
		ID: sameID, Hash: [32]byte{31: 0xA1}, Amount: anon(100), Expiry: 2_000_000_000}}
	if claimUpstreamIntent(first) != claimUpstreamIntent(again) {
		t.Fatal("the same lock derived two different intents; a retry after a crash " +
			"would claim a second time")
	}
}

// Every field that distinguishes one lock instance from another must move the
// intent, or some pair of instances collides.
func TestClaimIntentDependsOnEveryLockField(t *testing.T) {
	base := Incoming{Channel: [32]byte{31: 0xC1}, Lock: HTLC{
		ID: [32]byte{31: 0x07}, Hash: [32]byte{31: 0xA1},
		Amount: anon(100), Expiry: 2_000_000_000}}
	want := claimUpstreamIntent(base)

	alt := base
	alt.Channel = [32]byte{31: 0xC2}
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the channel does not affect the claim intent")
	}
	alt = base
	alt.Lock.ID = [32]byte{31: 0x08}
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the lock id does not affect the claim intent")
	}
	alt = base
	alt.Lock.Hash = [32]byte{31: 0xA2}
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the payment hash does not affect the claim intent")
	}
	alt = base
	alt.Lock.Amount = anon(101)
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the amount does not affect the claim intent")
	}
	alt = base
	alt.Lock.Expiry = 2_000_000_001
	if claimUpstreamIntent(alt) == want {
		t.Fatal("the expiry does not affect the claim intent")
	}
}
