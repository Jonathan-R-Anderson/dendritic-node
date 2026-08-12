package channel

// P13 — the multi-path security table, mapped row by row.
//
// Specification: doc/p13-multipath-security-table.md. Same coverage mechanism
// as the other P13 suites: the spec is data, each row registers itself, and an
// unclaimed row fails the suite.
//
// TWELVE OF THESE ROWS ARE GAPS, AND THEIR TESTS SAY SO
// -----------------------------------------------------
// SplitPlan is referenced nowhere outside multipath.go and its own test.
// Nothing executes a plan. So every property that needs fragments coordinated
// AT SETTLEMENT TIME — partial settlement, partial refund, aggregate replay,
// crash recovery — has no implementation and cannot honestly be tested as
// though it did.
//
// A GAP row's test therefore does the only useful thing available: it pins the
// absence mechanically, so that writing an executor FAILS this suite and forces
// the table to be revisited. A gap that is documented and then silently closed
// is how a security table becomes fiction.

import (
	"math/big"
	"os"
	"reflect"
	"testing"
)

var p13MultipathSpec = []p13Row{
	{"mp", "plan conservation", "fragments sum to the total"},
	{"mp", "exact total", "no unit is lost to rounding"},
	{"mp", "no path creates value", "rejected at plan and at channel"},
	{"mp", "no double spend per path", "rejected per channel"},
	{"mp", "nonce monotonic per channel", "strictly increasing"},
	{"mp", "independent channel conservation", "each channel conserves alone"},
	{"mp", "aggregate conservation at plan time", "enforced before sending"},
	{"mp", "one secret settles every fragment", "one z opens all chains"},
	{"mp", "fragments carry different locks", "not linkable"},
	{"mp", "within-route expiry ladder", "outgoing shorter than incoming"},
	{"mp", "per-leg refund restores both sides", "no liquidity bleed"},
	{"mp", "cancelling one path leaves siblings intact", "no cross-path leak"},
	{"mp", "individual path replay", "refused"},
	{"mp", "duplicate claim on one fragment", "refused"},
	{"mp", "per leg unwind is independent", "one stall does not strand others"},
	{"mp", "channels survive restart independently", "latest state reloads"},
	{"mp", "fragments never share a hub", "disjoint operator sets"},
	{"mp", "hub holdings stay zero across fragments", "no custody"},
	{"mp", "signer identity per leg", "both parties or refused"},
	{"mp", "cross path state rejection", "wrong channel refused"},
	{"mp", "per leg recovery is idempotent", "re-apply is a no-op"},
	{"mp", "no aggregate write path", "Accept is the only mutator"},

	// Gaps. Each pins an absence.
	{"mp", "GAP aggregate settlement accounting", "no executor exists"},
	{"mp", "GAP cross-fragment expiry ordering", "LockChain carries no expiry"},
	{"mp", "GAP partial path failure", "no executor exists"},
	{"mp", "GAP plan level replay identity", "SplitPlan has no identity"},
	{"mp", "GAP partial settlement", "no executor exists"},
	{"mp", "GAP partial refund reconciliation", "no executor exists"},
	{"mp", "GAP aggregate stall resolution", "no executor exists"},
	{"mp", "GAP plan is not persisted", "no store integration"},
	{"mp", "GAP no resumption after restart", "no executor exists"},
	{"mp", "GAP no aggregate recovery", "no executor exists"},
}

// methodNames returns the exported method set of a type, for pinning an
// absence mechanically rather than by assertion in prose.
func methodNames(v any) map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(v)
	for i := 0; i < t.NumMethod(); i++ {
		out[t.Method(i).Name] = true
	}
	return out
}

// assertNoExecutorMethod fails if a method implying plan execution has appeared.
//
// This is the mechanism that makes a GAP row honest: the day somebody writes
// SplitPlan.Execute, this suite breaks and the security table must be updated
// before the build is green again.
func assertNoExecutorMethod(t *testing.T, names ...string) {
	t.Helper()
	have := methodNames(&SplitPlan{})
	for _, n := range names {
		if have[n] {
			t.Fatalf("SplitPlan.%s now exists. A multi-path executor has been written, "+
				"so the GAP rows in doc/p13-multipath-security-table.md are no longer "+
				"accurate. Update the table and replace this test with a real one.", n)
		}
	}
}

func TestP13MultipathSecuritySuite(t *testing.T) {
	covered := map[string]bool{}
	cover := func(name string) { covered["mp/"+name] = true }

	newPlan := func(t *testing.T, total Amount) (*SplitPlan, Curve, *big.Int, Point) {
		t.Helper()
		c := DefaultCurve()
		z, Z, err := NewSecret(c)
		if err != nil {
			t.Fatalf("NewSecret: %v", err)
		}
		plan, err := Split(c, Z, total, threeIndependentRoutes())
		if err != nil {
			t.Fatalf("Split: %v", err)
		}
		return plan, c, z, Z
	}

	// ---- plan-layer properties -----------------------------------------

	t.Run("mp/plan conservation", func(t *testing.T) {
		cover("plan conservation")
		plan, _, _, _ := newPlan(t, Amount(100_000))
		var sum Amount
		for _, f := range plan.Fragments {
			sum += f.Amount
		}
		if sum != plan.Total {
			t.Fatalf("fragments sum to %d, total is %d", sum, plan.Total)
		}
		// Tamper: shave one fragment. Verify must catch it — a short-paid
		// recipient is silent until somebody reconciles.
		plan.Fragments[0].Amount -= 1
		if err := plan.Verify(); err == nil {
			t.Fatal("a plan whose fragments do not sum to the total verified")
		}
	})

	t.Run("mp/exact total", func(t *testing.T) {
		cover("exact total")
		// Totals chosen to stress the rounding path: just over the floor, odd
		// values, and values where spare/n divides badly.
		for _, total := range []Amount{2 * MinFragment, 3*MinFragment + 1, 100_001, 999_997} {
			c := DefaultCurve()
			_, Z, _ := NewSecret(c)
			plan, err := Split(c, Z, total, threeIndependentRoutes())
			if err != nil {
				continue // too small to split is a legitimate refusal, not a loss
			}
			var sum Amount
			for _, f := range plan.Fragments {
				sum += f.Amount
			}
			if sum != total {
				t.Fatalf("total %d split to %d — %d units lost to rounding",
					total, sum, total-sum)
			}
		}
	})

	t.Run("mp/no path creates value", func(t *testing.T) {
		cover("no path creates value")
		plan, _, _, _ := newPlan(t, Amount(100_000))
		plan.Fragments[0].Amount += 5_000 // inflate one leg after planning
		if err := plan.Verify(); err == nil {
			t.Fatal("an inflated fragment verified; the payer would be over-charged")
		}
		// And at the channel layer: a leg state exceeding its deposits.
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(600), anon(600)))); err == nil {
			t.Fatal("a leg state creating value was accepted")
		}
	})

	t.Run("mp/aggregate conservation at plan time", func(t *testing.T) {
		cover("aggregate conservation at plan time")
		plan, _, _, _ := newPlan(t, Amount(250_000))
		if err := plan.Verify(); err != nil {
			t.Fatalf("a well-formed plan failed verification: %v", err)
		}
		// Dropping a fragment entirely must not still verify.
		plan.Fragments = plan.Fragments[:len(plan.Fragments)-1]
		if err := plan.Verify(); err == nil {
			t.Fatal("a plan missing a fragment verified against its own total")
		}
	})

	// ---- cryptographic properties ---------------------------------------

	t.Run("mp/one secret settles every fragment", func(t *testing.T) {
		cover("one secret settles every fragment")
		plan, c, z, _ := newPlan(t, Amount(100_000))
		for i, f := range plan.Fragments {
			scalars, err := SettleRoute(c, f.Locks, z)
			if err != nil {
				t.Fatalf("fragment %d: SettleRoute: %v", i, err)
			}
			for hop, s := range scalars {
				if err := Satisfies(c, f.Locks.Locks[hop], s); err != nil {
					t.Fatalf("fragment %d hop %d not satisfied by the recipient's secret: %v",
						i, hop, err)
				}
			}
		}
		// A different secret must open nothing — otherwise fragments could be
		// claimed by someone who is not the recipient.
		other, _, _ := NewSecret(c)
		scalars, err := SettleRoute(c, plan.Fragments[0].Locks, other)
		if err != nil {
			t.Fatalf("SettleRoute: %v", err)
		}
		if err := Satisfies(c, plan.Fragments[0].Locks.Locks[0], scalars[0]); err == nil {
			t.Fatal("a wrong secret satisfied a fragment's lock")
		}
	})

	t.Run("mp/fragments carry different locks", func(t *testing.T) {
		cover("fragments carry different locks")
		plan, _, _, _ := newPlan(t, Amount(100_000))
		seen := map[string]int{}
		for i, f := range plan.Fragments {
			for _, l := range f.Locks.Locks {
				key := l.X.String() + ":" + l.Y.String()
				if prev, dup := seen[key]; dup {
					t.Fatalf("fragments %d and %d share a lock point; "+
						"they are trivially linkable as one payment", prev, i)
				}
				seen[key] = i
			}
		}
	})

	// ---- per-channel properties, which are fragment-agnostic ------------

	t.Run("mp/nonce monotonic per channel", func(t *testing.T) {
		cover("nonce monotonic per channel")
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(4, anon(400), anon(600)))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Two fragments of one payment landing on the same channel at the same
		// nonce. The channel does not know fragments exist, which is exactly
		// why this is safe.
		if err := f.ch.Accept(f.signed(t, f.state(4, anon(350), anon(650)))); err == nil {
			t.Fatal("two legs wrote the same nonce on one channel")
		}
	})

	t.Run("mp/independent channel conservation", func(t *testing.T) {
		cover("independent channel conservation")
		// Two channels, each with its own deposits. A leg on one must not be
		// able to draw on the other's capacity.
		f1, f2 := newP13Fixture(t), newP13Fixture(t)
		if err := f1.ch.Accept(f1.signed(t, f1.state(1, anon(0), anon(1000)))); err != nil {
			t.Fatalf("f1 legitimate drain: %v", err)
		}
		// f2 is untouched and must still conserve against its OWN deposits.
		if err := f2.ch.Accept(f2.signed(t, f2.state(1, anon(1400), anon(0)))); err == nil {
			t.Fatal("a channel accepted balances exceeding its own deposits")
		}
	})

	t.Run("mp/no double spend per path", func(t *testing.T) {
		cover("no double spend per path")
		f := newP13Fixture(t)
		st := f.state(6, anon(300), anon(700))
		if err := f.ch.Accept(f.signed(t, st)); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := f.ch.Accept(f.signed(t, st)); err == nil {
			t.Fatal("the same leg state was applied twice")
		}
	})

	t.Run("mp/individual path replay", func(t *testing.T) {
		cover("individual path replay")
		f := newP13Fixture(t)
		captured := f.signed(t, f.state(3, anon(400), anon(600)))
		if err := f.ch.Accept(captured); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := f.ch.Accept(f.signed(t, f.state(9, anon(350), anon(650)))); err != nil {
			t.Fatalf("later state: %v", err)
		}
		// The captured leg is replayed after the channel has moved on.
		if err := f.ch.Accept(captured); err == nil {
			t.Fatal("a captured leg state was replayed successfully")
		}
		if f.ch.Latest.State.Nonce != 9 {
			t.Fatal("the replay rolled the channel back")
		}
	})

	t.Run("mp/duplicate claim on one fragment", func(t *testing.T) {
		cover("duplicate claim on one fragment")
		f := newP13Fixture(t)
		pre := [32]byte{31: 0x77}
		var h [32]byte
		copy(h[:], keccak(pre[:]))
		lock := HTLC{ID: [32]byte{31: 1}, Hash: h, Amount: anon(10),
			Expiry: 2_000_000_000, PayerIsA: true}
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(490), anon(500), lock))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := f.ch.Accept(f.signed(t, f.state(2, anon(490), anon(510)))); err != nil {
			t.Fatalf("first claim: %v", err)
		}
		// Claim it again at a fresh nonce: the lock is gone, so the value has
		// nothing to come from.
		if err := f.ch.Accept(f.signed(t, f.state(3, anon(490), anon(520)))); err == nil {
			t.Fatal("a fragment's lock was claimed twice")
		}
	})

	t.Run("mp/signer identity per leg", func(t *testing.T) {
		cover("signer identity per leg")
		f := newP13Fixture(t)
		outsider := newSigner(t)
		st := f.state(1, anon(400), anon(600))
		raw := st.Digest(f.chainI, f.con)
		if err := f.ch.Accept(SignedState{State: st,
			SigA: outsider.sign(raw), SigB: f.b.sign(raw)}); err == nil {
			t.Fatal("a leg signed by a non-party was accepted")
		}
		// One party signing both slots is the other identity attack.
		if err := f.ch.Accept(SignedState{State: st,
			SigA: f.b.sign(raw), SigB: f.b.sign(raw)}); err == nil {
			t.Fatal("one party signed both slots of a leg")
		}
	})

	t.Run("mp/cross path state rejection", func(t *testing.T) {
		cover("cross path state rejection")
		f1, f2 := newP13Fixture(t), newP13Fixture(t)
		// A fully valid state for f1's channel, offered to f2's.
		legA := f1.signed(t, f1.state(1, anon(400), anon(600)))
		if err := f2.ch.Accept(legA); err == nil {
			t.Fatal("one path's signed state authorised a change on another path's channel")
		}
		// And it must still work on its own channel — the rejection is about
		// identity, not about the state being malformed.
		if err := f1.ch.Accept(legA); err != nil {
			t.Fatalf("the state was rejected on its own channel too: %v", err)
		}
	})

	t.Run("mp/per leg recovery is idempotent", func(t *testing.T) {
		cover("per leg recovery is idempotent")
		f := newP13Fixture(t)
		leg := f.signed(t, f.state(5, anon(400), anon(600)))
		if err := f.ch.Accept(leg); err != nil {
			t.Fatalf("first apply: %v", err)
		}
		before := f.ch.Latest.State.BalanceA.String()
		// Recovery re-applying the same leg must change nothing.
		for i := 0; i < 3; i++ {
			if err := f.ch.Accept(leg); err == nil {
				t.Fatal("re-applying a leg succeeded; recovery would double-settle")
			}
		}
		if f.ch.Latest.State.BalanceA.String() != before {
			t.Fatal("re-application mutated the channel")
		}
	})

	t.Run("mp/channels survive restart independently", func(t *testing.T) {
		cover("channels survive restart independently")
		f := newP13Fixture(t)
		dir, err := os.MkdirTemp("", "p13mp")
		if err != nil {
			t.Fatalf("tempdir: %v", err)
		}
		defer os.RemoveAll(dir)
		store, err := OpenStore(dir)
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		occ, err := f.chain.ReadChannel(t.Context(), f.con, f.id)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := store.TrackFromChain(f.chainI, f.con, occ); err != nil {
			t.Fatalf("track: %v", err)
		}
		if err := store.Accept(f.id, f.signed(t, f.state(8, anon(325), anon(675)))); err != nil {
			t.Fatalf("accept: %v", err)
		}
		reopened, err := OpenStore(dir)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		got, ok := reopened.Get(f.id)
		if !ok || got.Latest.State.Nonce != 8 {
			t.Fatal("a committed leg did not survive restart")
		}
		// The channel survives. What does NOT survive is the knowledge that
		// this leg belonged to a multi-path payment — see the GAP rows.
	})

	// ---- hub and routing properties -------------------------------------

	t.Run("mp/fragments never share a hub", func(t *testing.T) {
		cover("fragments never share a hub")
		plan, _, _, _ := newPlan(t, Amount(100_000))
		seen := map[string]int{}
		for i, f := range plan.Fragments {
			for _, hop := range f.Route {
				if prev, dup := seen[hop.Operator]; dup {
					t.Fatalf("fragments %d and %d both transit operator %q; "+
						"its liquidity would be double-counted and it would see both legs",
						prev, i, hop.Operator)
				}
				seen[hop.Operator] = i
			}
		}
	})

	t.Run("mp/hub holdings stay zero across fragments", func(t *testing.T) {
		cover("hub holdings stay zero across fragments")
		// One hub per fragment, each carrying its leg. No hub ever owns value,
		// at any point in any leg's life.
		hubs := []*Hub{NewHub(), NewHub(), NewHub()}
		secrets := make([]Preimage, len(hubs))
		conds := make([]Hash, len(hubs))
		for i, h := range hubs {
			if err := h.OpenReader(p13Tipper, 1000); err != nil {
				t.Fatalf("hub %d: %v", i, err)
			}
			h.FundRecipient(p13Recipient, 1000)
			secrets[i][31] = byte(i + 1)
			conds[i] = HashOf(secrets[i])
			if _, err := h.Reserve(p13Tipper, p13Recipient, 100, conds[i]); err != nil {
				t.Fatalf("hub %d reserve: %v", i, err)
			}
			if h.HubHoldings() != 0 {
				t.Fatalf("hub %d holds value mid-flight", i)
			}
		}
		// A fragment must settle ONLY against its own condition. If one
		// fragment's preimage could settle another, a recipient revealing once
		// would drain every leg — and the per-fragment lock chains that make
		// fragments unlinkable would be pointless.
		for i, h := range hubs {
			for j := range hubs {
				if i == j {
					continue
				}
				if err := h.Deliver(conds[i], secrets[j]); err == nil {
					t.Fatalf("fragment %d settled using fragment %d's preimage", i, j)
				}
			}
		}
		for i, h := range hubs {
			if err := h.Deliver(conds[i], secrets[i]); err != nil {
				t.Fatalf("hub %d deliver: %v", i, err)
			}
			if h.HubHoldings() != 0 {
				t.Fatalf("hub %d retained value after delivery", i)
			}
		}
	})

	t.Run("mp/per-leg refund restores both sides", func(t *testing.T) {
		cover("per-leg refund restores both sides")
		h := NewHub()
		if err := h.OpenReader(p13Tipper, 500); err != nil {
			t.Fatalf("OpenReader: %v", err)
		}
		h.FundRecipient(p13Recipient, 500)
		before := snapshot(h, p13Tipper, p13Recipient)
		var secret Preimage
		secret[31] = 9
		cond := HashOf(secret)
		if _, err := h.Reserve(p13Tipper, p13Recipient, 120, cond); err != nil {
			t.Fatalf("reserve: %v", err)
		}
		if err := h.Cancel(cond); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if snapshot(h, p13Tipper, p13Recipient) != before {
			t.Fatal("a leg refund did not restore both sides")
		}
	})

	t.Run("mp/cancelling one path leaves siblings intact", func(t *testing.T) {
		cover("cancelling one path leaves siblings intact")
		hubA, hubB := NewHub(), NewHub()
		for _, h := range []*Hub{hubA, hubB} {
			if err := h.OpenReader(p13Tipper, 500); err != nil {
				t.Fatalf("OpenReader: %v", err)
			}
			h.FundRecipient(p13Recipient, 500)
		}
		var sA, sB Preimage
		sA[31], sB[31] = 1, 2
		condA, condB := HashOf(sA), HashOf(sB)
		if _, err := hubA.Reserve(p13Tipper, p13Recipient, 100, condA); err != nil {
			t.Fatalf("A: %v", err)
		}
		if _, err := hubB.Reserve(p13Tipper, p13Recipient, 150, condB); err != nil {
			t.Fatalf("B: %v", err)
		}
		beforeB := snapshot(hubB, p13Tipper, p13Recipient)

		if err := hubA.Cancel(condA); err != nil {
			t.Fatalf("cancel A: %v", err)
		}
		if snapshot(hubB, p13Tipper, p13Recipient) != beforeB {
			t.Fatal("cancelling one path changed a sibling path's accounting")
		}
		// B must still settle normally afterwards.
		if err := hubB.Deliver(condB, sB); err != nil {
			t.Fatalf("sibling path could not settle after a cancel elsewhere: %v", err)
		}
		// A's cancel must not have let A settle too.
		if err := hubA.Deliver(condA, sA); err == nil {
			t.Fatal("a cancelled path settled anyway")
		}
	})

	t.Run("mp/per leg unwind is independent", func(t *testing.T) {
		cover("per leg unwind is independent")
		// A stalled leg (never delivered, never cancelled) must not block a
		// sibling from resolving.
		stalled, healthy := NewHub(), NewHub()
		for _, h := range []*Hub{stalled, healthy} {
			if err := h.OpenReader(p13Tipper, 500); err != nil {
				t.Fatalf("OpenReader: %v", err)
			}
			h.FundRecipient(p13Recipient, 500)
		}
		var s1, s2 Preimage
		s1[31], s2[31] = 3, 4
		c1, c2 := HashOf(s1), HashOf(s2)
		if _, err := stalled.Reserve(p13Tipper, p13Recipient, 100, c1); err != nil {
			t.Fatalf("stalled: %v", err)
		}
		if _, err := healthy.Reserve(p13Tipper, p13Recipient, 100, c2); err != nil {
			t.Fatalf("healthy: %v", err)
		}
		if err := healthy.Deliver(c2, s2); err != nil {
			t.Fatalf("a healthy leg could not settle while a sibling stalled: %v", err)
		}
		if stalled.InFlight() != 100 {
			t.Fatal("the stalled leg was resolved by its sibling settling")
		}
	})

	t.Run("mp/within-route expiry ladder", func(t *testing.T) {
		cover("within-route expiry ladder")
		// Exercises the REAL planner. An earlier version of this test computed
		// the ladder inline and therefore tested nothing — it would have passed
		// with the implementation deleted.
		req := planReq(t)
		plan, err := PlanPayment(req)
		if err != nil {
			t.Fatalf("PlanPayment: %v", err)
		}
		if len(plan.Route) < 2 {
			t.Fatalf("route has %d hops; the ladder needs at least 2 to mean anything",
				len(plan.Route))
		}
		// Peel each hop's instruction with the shared secret that hop would
		// hold, which is what a router actually does.
		var prev uint64
		for i, c := range plan.Route {
			shared := derive("syndichan/payment/hopsecret/v1", req.Seed[:], []byte(c.NodeID))
			hop, err := plan.Packet.Peel(shared)
			if err != nil {
				t.Fatalf("hop %d could not peel its own instruction: %v", i, err)
			}
			if hop.OutgoingExpiry == 0 {
				t.Fatalf("hop %d has no outgoing expiry", i)
			}
			if i > 0 && hop.OutgoingExpiry >= prev {
				t.Fatalf("hop %d expiry %d is not strictly shorter than hop %d's %d; "+
					"an intermediary could be paid downstream with no time to claim upstream",
					i, hop.OutgoingExpiry, i-1, prev)
			}
			prev = hop.OutgoingExpiry
		}
	})

	t.Run("mp/no aggregate write path", func(t *testing.T) {
		cover("no aggregate write path")
		// Channel.Accept is the only mutator. If an aggregate executor is ever
		// written, it MUST go through Accept per channel rather than writing
		// balances directly — this pins that there is currently no other door.
		have := methodNames(&Channel{})
		for _, forbidden := range []string{"SetBalances", "ApplyAggregate", "ApplyPlan", "ForceState"} {
			if have[forbidden] {
				t.Fatalf("Channel.%s exists — an aggregate path can now write balances "+
					"without Accept's conservation and nonce checks", forbidden)
			}
		}
		// And the store's write surface funnels through Accept/Update only.
		st := methodNames(&Store{})
		for _, forbidden := range []string{"WritePlan", "ApplySplitPlan", "SettleMultipath"} {
			if st[forbidden] {
				t.Fatalf("Store.%s exists — see doc/p13-multipath-security-table.md row 25", forbidden)
			}
		}
	})

	// ---- the gaps -------------------------------------------------------

	t.Run("mp/GAP aggregate settlement accounting", func(t *testing.T) {
		cover("GAP aggregate settlement accounting")
		assertNoExecutorMethod(t, "Settle", "Execute", "Send", "Dispatch")
		// Concretely: a plan whose fragments have all "settled" and one that
		// has settled none are indistinguishable to this package, because
		// Verify inspects the PLAN and nothing inspects outcomes.
		plan, _, _, _ := newPlan(t, Amount(100_000))
		if err := plan.Verify(); err != nil {
			t.Fatalf("plan: %v", err)
		}
		t.Log("GAP: Verify checks the plan, not what happened to it. " +
			"No code sums delivered fragments against Total.")
	})

	t.Run("mp/GAP cross-fragment expiry ordering", func(t *testing.T) {
		cover("GAP cross-fragment expiry ordering")
		// Mechanical: a LockChain has no expiry field at all, so there is
		// nothing to order across fragments.
		lc := reflect.TypeOf(LockChain{})
		for i := 0; i < lc.NumField(); i++ {
			if lc.Field(i).Name == "Expiry" || lc.Field(i).Name == "Expiries" {
				t.Fatalf("LockChain now carries %s — cross-fragment expiry ordering "+
					"is implementable and the table row must be rewritten", lc.Field(i).Name)
			}
		}
		frag := reflect.TypeOf(Fragment{})
		for i := 0; i < frag.NumField(); i++ {
			if frag.Field(i).Name == "Expiry" {
				t.Fatal("Fragment now carries an Expiry — update the table row")
			}
		}
		t.Log("GAP: fragments carry points, not deadlines. The payer's exposure " +
			"across fragments is unbounded by any check in this package.")
	})

	t.Run("mp/GAP partial path failure", func(t *testing.T) {
		cover("GAP partial path failure")
		assertNoExecutorMethod(t, "OnFragmentFailed", "Reconcile", "Resolve")
		t.Log("GAP: nothing observes per-fragment outcomes, so 'two of three succeeded' " +
			"has no representation and no resolution policy.")
	})

	t.Run("mp/GAP plan level replay identity", func(t *testing.T) {
		cover("GAP plan level replay identity")
		// A SplitPlan has no id, nonce or intent binding, so a replay of the
		// whole plan is only blocked incidentally, by per-leg nonces.
		sp := reflect.TypeOf(SplitPlan{})
		for i := 0; i < sp.NumField(); i++ {
			switch sp.Field(i).Name {
			case "ID", "Nonce", "Intent", "PaymentID":
				t.Fatalf("SplitPlan now has %s — plan-level replay protection is "+
					"implementable and the table row must be rewritten", sp.Field(i).Name)
			}
		}
		t.Log("GAP: whole-plan replay is blocked only as a side effect of per-leg nonces, " +
			"not by any guard that knows a plan is a unit.")
	})

	t.Run("mp/GAP partial settlement", func(t *testing.T) {
		cover("GAP partial settlement")
		assertNoExecutorMethod(t, "Settled", "MarkSettled", "Outcome")
		t.Log("GAP: a recipient claiming the two largest fragments and letting the " +
			"rest expire is undetectable here.")
	})

	t.Run("mp/GAP partial refund reconciliation", func(t *testing.T) {
		cover("GAP partial refund reconciliation")
		assertNoExecutorMethod(t, "Refunded", "Reconcile")
		t.Log("GAP: per-leg refunds work; nothing sums them against Total.")
	})

	t.Run("mp/GAP aggregate stall resolution", func(t *testing.T) {
		cover("GAP aggregate stall resolution")
		assertNoExecutorMethod(t, "ExpireStale", "Timeout")
		t.Log("GAP: per-leg timeouts unwind each hop; whether the PAYMENT then " +
			"resolves coherently has no owner.")
	})

	t.Run("mp/GAP plan is not persisted", func(t *testing.T) {
		cover("GAP plan is not persisted")
		st := methodNames(&Store{})
		for _, n := range []string{"PutPlan", "SavePlan", "TrackPlan", "Plans"} {
			if st[n] {
				t.Fatalf("Store.%s exists — plans are now persisted and the crash/restart "+
					"rows must be rewritten", n)
			}
		}
		t.Log("GAP: SplitPlan is an in-memory value with no encoder and no store. " +
			"A crash between committing a leg and finishing the plan loses the plan.")
	})

	t.Run("mp/GAP no resumption after restart", func(t *testing.T) {
		cover("GAP no resumption after restart")
		assertNoExecutorMethod(t, "Resume", "Recover")
		t.Log("GAP: channels reload correctly, so no value is lost — what is lost " +
			"is the knowledge that several legs were one payment.")
	})

	t.Run("mp/GAP no aggregate recovery", func(t *testing.T) {
		cover("GAP no aggregate recovery")
		assertNoExecutorMethod(t, "Recover", "Reconcile", "Resume")
		t.Log("GAP: per-leg recovery is idempotent; there is no aggregate recovery " +
			"to be idempotent about.")
	})

	// ---- the audit ------------------------------------------------------

	t.Run("spec coverage", func(t *testing.T) {
		var missing []string
		for _, row := range p13MultipathSpec {
			if !covered["mp/"+row.name] {
				missing = append(missing, row.name+" ("+row.expected+")")
			}
		}
		if len(missing) > 0 {
			t.Fatalf("%d multi-path requirement(s) have no test:\n  %v", len(missing), missing)
		}
		var gaps int
		for _, row := range p13MultipathSpec {
			if len(row.name) > 4 && row.name[:4] == "GAP " {
				gaps++
			}
		}
		t.Logf("all %d multi-path rows exercised: %d enforced, %d gaps pinned",
			len(p13MultipathSpec), len(p13MultipathSpec)-gaps, gaps)
	})
}
