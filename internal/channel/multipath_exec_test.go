package channel

// The multi-path executor, end to end through the real engine.
//
// Every payment here goes payer -> Coordinator.Pay -> SCPP/1 -> the peer's
// Handle -> Channel.Accept, on both sides. Nothing constructs a signed state by
// hand and nothing writes a balance directly, because a test that bypasses the
// machinery proves things about the test.
//
// Fragments live on SEPARATE channels with separate counterparties, which is
// what the security table requires and what makes the isolation rows meaningful
// rather than incidental.

import (
	"context"
	"errors"
	"math/big"
	"testing"
)

const (
	mpClock    = int64(1_000_000)
	mpExpiry   = mpClock + 3_600
	mpDeadline = mpClock + 7_200
)

// mpFixture is one payer and N payees, each on its own funded channel.
type mpFixture struct {
	payer    *wiredNode
	payees   []*wiredNode
	channels [][32]byte
	exec     *MultipathExecutor
	secret   [32]byte
	dir      string
}

func newMPFixture(t *testing.T, legs int, deposit *big.Int) *mpFixture {
	t.Helper()
	contract := mustAddr(t, deployedChannelManager)
	chain := NewFakeChain()
	pk := newSigner(t)

	f := &mpFixture{dir: t.TempDir(), secret: [32]byte{31: 0xA5}}
	// One chain shared by everyone, so every node reads the same deposits.
	for i := 0; i < legs; i++ {
		qk := newSigner(t)
		id := chain.Add(pk.address(), qk.address(), deposit, new(big.Int))
		f.channels = append(f.channels, id)
		f.payees = append(f.payees, newWiredNode(t, qk, chain, contract))
	}
	f.payer = newWiredNode(t, pk, chain, contract)

	exec, err := NewMultipathExecutor(f.payer.coord, f.dir)
	if err != nil {
		t.Fatalf("NewMultipathExecutor: %v", err)
	}
	f.exec = exec
	return f
}

// peers routes each channel to its own counterparty's real coordinator.
func (f *mpFixture) peers(t *testing.T) PeerFor {
	return func(ch [32]byte) (Peer, error) {
		for i, id := range f.channels {
			if id == ch {
				return directPeer{t, f.payees[i].coord}, nil
			}
		}
		return nil, errors.New("no peer for that channel")
	}
}

// deadPeer stands in for a counterparty that stopped answering.
type deadPeer struct{}

func (deadPeer) Exchange(context.Context, Envelope) (Envelope, error) {
	return Envelope{}, errors.New("counterparty is unreachable")
}

// payment builds a conserving payment across every channel in the fixture.
func (f *mpFixture) payment(t *testing.T, id [32]byte, amounts ...int64) *MultipathPayment {
	t.Helper()
	var amts []*big.Int
	var exp []int64
	total := new(big.Int)
	for _, a := range amounts {
		amts = append(amts, anon(a))
		exp = append(exp, mpExpiry)
		total.Add(total, anon(a))
	}
	pay, err := BuildPayment(id, f.secret, total, mpDeadline, f.channels[:len(amounts)], amts, exp)
	if err != nil {
		t.Fatalf("BuildPayment: %v", err)
	}
	return pay
}

// advanceTo moves every node's clock. A refund is refused while the lock is
// live (RejectLockNotExpired), so unwinding a payment means reaching its expiry
// rather than asking nicely.
func (f *mpFixture) advanceTo(unix int64) {
	f.payer.clock = unix
	for _, p := range f.payees {
		p.clock = unix
	}
}

// noErrs fails if any leg reported an error.
func noErrs(t *testing.T, label string, errs []error) {
	t.Helper()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("%s: leg %d: %v", label, i, e)
		}
	}
}

// conserves is the invariant asserted after EVERY terminal outcome: the value
// the channels actually moved equals the value the legs account for.
func (f *mpFixture) conserves(t *testing.T, pay *MultipathPayment) {
	t.Helper()
	out := f.exec.Summarise(pay)
	delivered := new(big.Int)
	for i, leg := range pay.Legs {
		bal, err := f.payees[i].coord.Balances(leg.Channel)
		if err != nil {
			// A counterparty that never received a message never adopted the
			// channel. It has been delivered nothing, which is the correct
			// contribution to the sum — not a reason to fail the check.
			continue
		}
		delivered.Add(delivered, bal.Mine)
	}
	if delivered.Cmp(out.SettledAmount) != 0 {
		t.Fatalf("conservation broken: channels delivered %s, executor accounts for %s",
			delivered, out.SettledAmount)
	}
	// And nothing was created: delivered can never exceed the payment total.
	if delivered.Cmp(pay.Total) > 0 {
		t.Fatalf("channels delivered %s, more than the payment total %s", delivered, pay.Total)
	}
}

// ---- construction ---------------------------------------------------------

func TestBuildPaymentRefusesFragmentsThatDoNotSum(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	_, err := BuildPayment([32]byte{1}, f.secret, anon(100), mpDeadline,
		f.channels, []*big.Int{anon(40), anon(40)}, []int64{mpExpiry, mpExpiry})
	if !errors.Is(err, ErrPlanNotConserving) {
		t.Fatalf("a short-paying split was accepted: %v", err)
	}
	// And over-paying is refused in the same place.
	_, err = BuildPayment([32]byte{1}, f.secret, anon(100), mpDeadline,
		f.channels, []*big.Int{anon(80), anon(80)}, []int64{mpExpiry, mpExpiry})
	if !errors.Is(err, ErrPlanNotConserving) {
		t.Fatalf("an over-paying split was accepted: %v", err)
	}
}

func TestBuildPaymentRefusesUnsafeExpiries(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	// A leg outliving the payment deadline leaves the payer exposed after they
	// believe the payment is finished.
	_, err := BuildPayment([32]byte{2}, f.secret, anon(100), mpDeadline,
		f.channels, []*big.Int{anon(50), anon(50)},
		[]int64{mpExpiry, mpDeadline + 1})
	if !errors.Is(err, ErrFragmentExpiryUnsafe) {
		t.Fatalf("a fragment outliving the deadline was accepted: %v", err)
	}
	// An unset expiry is a lock nobody can reclaim.
	_, err = BuildPayment([32]byte{2}, f.secret, anon(100), mpDeadline,
		f.channels, []*big.Int{anon(50), anon(50)}, []int64{mpExpiry, 0})
	if !errors.Is(err, ErrFragmentExpiryUnsafe) {
		t.Fatalf("a fragment with no expiry was accepted: %v", err)
	}
}

func TestBuildPaymentRefusesTwoFragmentsOnOneChannel(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	same := [][32]byte{f.channels[0], f.channels[0]}
	_, err := BuildPayment([32]byte{3}, f.secret, anon(100), mpDeadline,
		same, []*big.Int{anon(50), anon(50)}, []int64{mpExpiry, mpExpiry})
	if !errors.Is(err, ErrDuplicateFragmentChannel) {
		t.Fatalf("two fragments on one channel were accepted: %v", err)
	}
}

// ---- the happy paths ------------------------------------------------------

func TestTwoWaySplitSettlesCompletely(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 1}, 30, 70)

	errs, err := f.exec.Lock(ctx, pay, f.peers(t))
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	noErrs(t, "lock", errs)

	// Locked, not yet delivered: value sits in neither balance.
	mid := f.exec.Summarise(pay)
	if mid.Locked != 2 || mid.Settled != 0 {
		t.Fatalf("after lock: %+v", mid)
	}
	if mid.SettledAmount.Sign() != 0 {
		t.Fatal("locked value was counted as settled")
	}

	errs, err = f.exec.Settle(ctx, pay, f.secret, f.peers(t))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	noErrs(t, "settle", errs)

	out := f.exec.Summarise(pay)
	if !out.Complete(pay) {
		t.Fatalf("payment did not complete: %+v", out)
	}
	if out.SettledAmount.Cmp(anon(100)) != 0 {
		t.Fatalf("settled %s, want 100", out.SettledAmount)
	}
	f.conserves(t, pay)
}

func TestFourWaySplitSettlesCompletely(t *testing.T) {
	f := newMPFixture(t, 4, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 2}, 11, 23, 37, 29)

	errs, err := f.exec.Lock(ctx, pay, f.peers(t))
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	noErrs(t, "lock", errs)
	errs, err = f.exec.Settle(ctx, pay, f.secret, f.peers(t))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	noErrs(t, "settle", errs)

	out := f.exec.Summarise(pay)
	if !out.Complete(pay) || out.Settled != 4 {
		t.Fatalf("4-way split did not complete: %+v", out)
	}
	f.conserves(t, pay)
}

// ---- isolation ------------------------------------------------------------

// The mutation finding from the earlier P13 pass, now enforced by construction.
func TestOneFragmentsPreimageCannotSettleAnother(t *testing.T) {
	f := newMPFixture(t, 3, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 3}, 20, 30, 50)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	// Every fragment's hash must differ, or one preimage opens several.
	for i := range pay.Legs {
		for j := range pay.Legs {
			if i != j && pay.Legs[i].Hash == pay.Legs[j].Hash {
				t.Fatalf("fragments %d and %d share a payment hash", i, j)
			}
		}
	}

	// Fragment 0's preimage offered against fragment 1's lock: the channel must
	// refuse it. This goes through the real transition, so the refusal is
	// Channel.Accept's, not the executor's.
	wrong := FragmentPreimage(f.secret, 0)
	tr := StateTransition{Kind: KindLockSettle, LockID: pay.Legs[1].LockID, Preimage: wrong}
	_, err := f.payer.coord.Pay(ctx, pay.Legs[1].Channel,
		derive("test/cross-fragment", pay.Legs[1].Intent[:]), tr, directPeer{t, f.payees[1].coord})
	if err == nil {
		t.Fatal("one fragment's preimage settled another fragment")
	}

	// The correct preimage still works afterwards — the failure must not have
	// poisoned the lock.
	errs, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	noErrs(t, "settle", errs)
	if !f.exec.Summarise(pay).Complete(pay) {
		t.Fatal("payment did not complete after a rejected cross-fragment claim")
	}
	f.conserves(t, pay)
}

func TestWrongPreimageOnOneFragmentDoesNotSettleIt(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 4}, 40, 60)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// A secret that is not the payment's.
	other := [32]byte{31: 0xFF}
	errs, err := f.exec.Settle(ctx, pay, other, f.peers(t))
	if err != nil {
		t.Fatalf("Settle: %v", err)
	}
	for i, e := range errs {
		if e == nil {
			t.Fatalf("leg %d settled with the wrong secret", i)
		}
	}
	out := f.exec.Summarise(pay)
	if out.Settled != 0 {
		t.Fatalf("%d legs settled with a wrong secret", out.Settled)
	}
	f.conserves(t, pay)
}

// A signature valid for one channel must never move another.
func TestFragmentStateCannotAuthoriseAnotherChannel(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 5}, 50, 50)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	ch0, ok := f.payer.coord.Channel(pay.Legs[0].Channel)
	if !ok {
		t.Fatal("no channel 0")
	}
	// Channel 0's fully signed latest state, offered to channel 1.
	stolen := ch0.Latest
	ch1, _ := f.payer.coord.Channel(pay.Legs[1].Channel)
	if err := ch1.Accept(stolen); err == nil {
		t.Fatal("one fragment's signed state authorised another fragment's channel")
	}
	_ = ctx
}

// ---- replay and duplication ------------------------------------------------

func TestReplayingTheWholePaymentPaysOnce(t *testing.T) {
	f := newMPFixture(t, 3, anon(500))
	ctx := context.Background()
	id := [32]byte{31: 6}
	pay := f.payment(t, id, 20, 30, 50)

	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t)); err != nil {
		t.Fatalf("Settle: %v", err)
	}
	first := f.exec.Summarise(pay)

	// The identical payment, rebuilt from the same id and secret: every intent
	// re-derives to the same bytes, so every channel recognises it.
	replay := f.payment(t, id, 20, 30, 50)
	if _, err := f.exec.Lock(ctx, replay, f.peers(t)); err != nil {
		t.Fatalf("replay lock: %v", err)
	}
	if _, err := f.exec.Settle(ctx, replay, f.secret, f.peers(t)); err != nil {
		t.Fatalf("replay settle: %v", err)
	}
	second := f.exec.Summarise(pay)

	if second.SettledAmount.Cmp(first.SettledAmount) != 0 {
		t.Fatalf("replaying the payment moved more value: %s -> %s",
			first.SettledAmount, second.SettledAmount)
	}
	f.conserves(t, pay)
}

func TestReplayingOneFragmentPaysOnce(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 7}, 40, 60)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	before, _ := f.payer.coord.Balances(pay.Legs[0].Channel)

	// Same intent, same transition: the engine answers from its record.
	leg := pay.Legs[0]
	tr := StateTransition{Kind: KindLockAdd, Amount: new(big.Int).Set(leg.Amount),
		LockID: leg.LockID, Hash: leg.Hash, Expiry: leg.Expiry}
	res, err := f.payer.coord.Pay(ctx, leg.Channel, leg.Intent, tr, directPeer{t, f.payees[0].coord})
	if err != nil {
		t.Fatalf("replayed leg: %v", err)
	}
	if !res.Done {
		t.Fatal("a replayed leg was not recognised as already applied")
	}
	after, _ := f.payer.coord.Balances(leg.Channel)
	if before.Mine.Cmp(after.Mine) != 0 {
		t.Fatalf("replaying a fragment moved value: %s -> %s", before.Mine, after.Mine)
	}
}

func TestSettlingTwiceDeliversOnce(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 8}, 25, 75)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t)); err != nil {
		t.Fatalf("settle: %v", err)
	}
	once := f.exec.Summarise(pay)
	if _, err := f.exec.Settle(ctx, pay, f.secret, f.peers(t)); err != nil {
		t.Fatalf("second settle: %v", err)
	}
	twice := f.exec.Summarise(pay)
	if twice.SettledAmount.Cmp(once.SettledAmount) != 0 {
		t.Fatalf("settling twice delivered twice: %s -> %s", once.SettledAmount, twice.SettledAmount)
	}
	f.conserves(t, pay)
}

// ---- partial failure -------------------------------------------------------

func TestOnePathFailsWhileAnotherSucceeds(t *testing.T) {
	f := newMPFixture(t, 3, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 9}, 20, 30, 50)

	// Leg 1's counterparty is gone; the others must still resolve.
	peers := func(ch [32]byte) (Peer, error) {
		if ch == pay.Legs[1].Channel {
			return deadPeer{}, nil
		}
		return f.peers(t)(ch)
	}
	errs, err := f.exec.Lock(ctx, pay, peers)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if errs[1] == nil {
		t.Fatal("a dead counterparty reported success")
	}
	if errs[0] != nil || errs[2] != nil {
		t.Fatalf("a dead leg prevented its siblings: %v / %v", errs[0], errs[2])
	}

	out := f.exec.Summarise(pay)
	if out.Locked != 2 || out.Pending != 1 {
		t.Fatalf("expected 2 locked and 1 pending, got %+v", out)
	}
	f.conserves(t, pay)

	// The payment cannot complete, so the locked legs are unwound. The value
	// must come back to the payer, not sit locked forever.
	f.advanceTo(mpExpiry + 120)
	rerrs, err := f.exec.Refund(ctx, pay, peers)
	if err != nil {
		t.Fatalf("Refund: %v", err)
	}
	for i, e := range rerrs {
		if e != nil && i != 1 {
			t.Fatalf("refund leg %d: %v", i, e)
		}
	}
	final := f.exec.Summarise(pay)
	if final.Refunded != 2 || final.Settled != 0 {
		t.Fatalf("unwind left %+v", final)
	}
	if final.SettledAmount.Sign() != 0 {
		t.Fatal("a fully refunded payment reports delivered value")
	}
	f.conserves(t, pay)
}

func TestRefundingDoesNotTouchASettledLeg(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 10}, 40, 60)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// Settle only leg 0, by hand through the real engine.
	leg := pay.Legs[0]
	tr := StateTransition{Kind: KindLockSettle, LockID: leg.LockID,
		Preimage: FragmentPreimage(f.secret, 0)}
	if _, err := f.payer.coord.Pay(ctx, leg.Channel, settleIntent(leg.Intent), tr,
		directPeer{t, f.payees[0].coord}); err != nil {
		t.Fatalf("settle leg 0: %v", err)
	}
	delivered := f.exec.Summarise(pay).SettledAmount

	// Refunding now must leave leg 0 alone: refunding a settled leg would pay
	// its value out twice.
	f.advanceTo(mpExpiry + 120)
	rerrs, err := f.exec.Refund(ctx, pay, f.peers(t))
	if err != nil {
		t.Fatalf("Refund: %v", err)
	}
	noErrs(t, "refund", rerrs)
	out := f.exec.Summarise(pay)
	if out.Settled != 1 || out.Refunded != 1 {
		t.Fatalf("expected 1 settled and 1 refunded, got %+v", out)
	}
	if out.SettledAmount.Cmp(delivered) != 0 {
		t.Fatalf("a refund changed delivered value: %s -> %s", delivered, out.SettledAmount)
	}
	f.conserves(t, pay)
}

func TestInsufficientCapacityOnOnePathFailsOnlyThatPath(t *testing.T) {
	// Leg 1's channel cannot cover its fragment.
	contract := mustAddr(t, deployedChannelManager)
	chain := NewFakeChain()
	pk := newSigner(t)
	f := &mpFixture{dir: t.TempDir(), secret: [32]byte{31: 0xA5}}
	for i, dep := range []*big.Int{anon(500), anon(5)} {
		qk := newSigner(t)
		f.channels = append(f.channels, chain.Add(pk.address(), qk.address(), dep, new(big.Int)))
		f.payees = append(f.payees, newWiredNode(t, qk, chain, contract))
		_ = i
	}
	f.payer = newWiredNode(t, pk, chain, contract)
	exec, err := NewMultipathExecutor(f.payer.coord, f.dir)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	f.exec = exec

	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 11}, 50, 50)
	errs, err := f.exec.Lock(ctx, pay, f.peers(t))
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if errs[1] == nil {
		t.Fatal("a fragment larger than its channel was accepted")
	}
	out := f.exec.Summarise(pay)
	if out.Locked != 1 {
		t.Fatalf("expected only the funded leg to lock: %+v", out)
	}
	f.conserves(t, pay)
}

// ---- crash and recovery ----------------------------------------------------

// Recovery must read the CHANNELS, not the previous process's intentions.
func TestRecoveryAfterPartialProgressDiscoversRealState(t *testing.T) {
	f := newMPFixture(t, 3, anon(500))
	ctx := context.Background()
	id := [32]byte{31: 12}
	pay := f.payment(t, id, 20, 30, 50)

	// Crash after one leg commits: lock only leg 0, then lose the process.
	peers := func(ch [32]byte) (Peer, error) {
		if ch == pay.Legs[0].Channel {
			return f.peers(t)(ch)
		}
		return deadPeer{}, nil
	}
	if _, err := f.exec.Lock(ctx, pay, peers); err != nil {
		t.Fatalf("partial lock: %v", err)
	}
	if got := f.exec.Summarise(pay).Locked; got != 1 {
		t.Fatalf("expected 1 leg locked before the crash, got %d", got)
	}

	// A NEW executor over the same store and journal — nothing carried in
	// memory from the previous one.
	revived, err := NewMultipathExecutor(f.payer.coord, f.dir)
	if err != nil {
		t.Fatalf("revived exec: %v", err)
	}
	loaded, err := revived.LoadJournal(id)
	if err != nil {
		t.Fatalf("LoadJournal: %v", err)
	}
	if len(loaded.Legs) != 3 || loaded.Total.Cmp(anon(100)) != 0 {
		t.Fatalf("journal did not survive: %+v", loaded)
	}
	// It must see the one real lock, not three intended ones.
	if got := revived.Summarise(loaded).Locked; got != 1 {
		t.Fatalf("recovery believed the previous process's intent: %d locked", got)
	}

	// Resuming with the secret drives the payment to completion.
	secret := f.secret
	out, errs, err := revived.Resume(ctx, id, &secret, f.peers(t))
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	noErrs(t, "resume", errs)
	if !out.Complete(loaded) {
		t.Fatalf("resume did not complete the payment: %+v", out)
	}
	f.conserves(t, loaded)
}

func TestRecoveryWithoutTheSecretUnwinds(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	id := [32]byte{31: 13}
	pay := f.payment(t, id, 40, 60)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	revived, err := NewMultipathExecutor(f.payer.coord, f.dir)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	f.advanceTo(mpExpiry + 120)
	out, errs, err := revived.Resume(ctx, id, nil, f.peers(t))
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	noErrs(t, "resume", errs)
	if out.Refunded != 2 || out.SettledAmount.Sign() != 0 {
		t.Fatalf("unwind did not return everything: %+v", out)
	}
	f.conserves(t, pay)
}

// Crash before ANY leg commits: the journal exists, the channels are untouched.
func TestCrashBeforeAnyLegCommits(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	id := [32]byte{31: 14}
	pay := f.payment(t, id, 30, 70)
	if err := f.exec.Journal(pay); err != nil {
		t.Fatalf("Journal: %v", err)
	}
	revived, err := NewMultipathExecutor(f.payer.coord, f.dir)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	loaded, err := revived.LoadJournal(id)
	if err != nil {
		t.Fatalf("LoadJournal: %v", err)
	}
	out := revived.Summarise(loaded)
	if out.Locked != 0 || out.Settled != 0 || out.Pending != 2 {
		t.Fatalf("a journalled-but-unsent payment looked committed: %+v", out)
	}
	// And it can still be driven normally afterwards.
	secret := f.secret
	final, errs, err := revived.Resume(ctx, id, &secret, f.peers(t))
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	noErrs(t, "resume", errs)
	if !final.Complete(loaded) {
		t.Fatalf("resume from a fresh journal did not complete: %+v", final)
	}
	f.conserves(t, loaded)
}

// A retry after an ambiguous outcome converges rather than paying twice.
func TestRetryAfterAmbiguousOutcomeConverges(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 15}, 45, 55)

	// flaky answers once and then fails, so the caller cannot tell whether the
	// second leg landed.
	calls := 0
	flaky := func(ch [32]byte) (Peer, error) {
		if ch == pay.Legs[1].Channel {
			calls++
			if calls == 1 {
				return deadPeer{}, nil
			}
		}
		return f.peers(t)(ch)
	}
	if _, err := f.exec.Lock(ctx, pay, flaky); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// Retry: leg 0 is already applied and must not move again.
	before, _ := f.payer.coord.Balances(pay.Legs[0].Channel)
	if _, err := f.exec.Lock(ctx, pay, flaky); err != nil {
		t.Fatalf("retry: %v", err)
	}
	after, _ := f.payer.coord.Balances(pay.Legs[0].Channel)
	if before.Mine.Cmp(after.Mine) != 0 {
		t.Fatalf("retry moved value on an already-locked leg: %s -> %s", before.Mine, after.Mine)
	}
	out := f.exec.Summarise(pay)
	if out.Locked != 2 {
		t.Fatalf("retry did not converge: %+v", out)
	}
	f.conserves(t, pay)
}

// ---- properties the first mutation pass showed were untested ---------------

// A non-positive fragment must be refused at construction.
//
// The channel layer would also refuse it (requirePositive in LOCK_ADD), but a
// zero or negative fragment can still satisfy the conservation sum when another
// fragment absorbs it, so it reaches the wire looking legitimate. Refusing it
// here is the cheap check, and nothing was asserting it.
func TestBuildPaymentRefusesNonPositiveFragments(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	for _, bad := range []*big.Int{new(big.Int), new(big.Int).Neg(anon(10))} {
		// The sibling absorbs it, so the total still adds up exactly.
		other := new(big.Int).Sub(anon(100), bad)
		_, err := BuildPayment([32]byte{31: 200}, f.secret, anon(100), mpDeadline,
			f.channels, []*big.Int{bad, other}, []int64{mpExpiry, mpExpiry})
		if err == nil {
			t.Fatalf("a fragment of %s was accepted", bad)
		}
	}
}

// A peer REFUSAL must surface as a leg error.
//
// Coordinator.Pay returns a refusal as (result, nil) — the round trip worked,
// the peer said no. Nothing here exercised that path: a wrong preimage fails
// LOCALLY (the transition will not apply), and a dead counterparty fails at the
// transport. Both produce a real error, so neither test noticed when the
// rejection check was deleted.
//
// Refunding a live lock is a genuine remote refusal: RejectLockNotExpired.
func TestARefusedLegIsNotReportedAsSuccess(t *testing.T) {
	f := newMPFixture(t, 2, anon(500))
	ctx := context.Background()
	pay := f.payment(t, [32]byte{31: 201}, 40, 60)
	if _, err := f.exec.Lock(ctx, pay, f.peers(t)); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// Refund while the locks are still live. The peer must refuse, and the
	// executor must say so rather than reporting a silent no-op as success.
	errs, err := f.exec.Refund(ctx, pay, f.peers(t))
	if err != nil {
		t.Fatalf("Refund: %v", err)
	}
	for i, e := range errs {
		if e == nil {
			t.Fatalf("leg %d: a refused refund was reported as success", i)
		}
	}
	// And nothing moved: the legs are still locked, not refunded.
	out := f.exec.Summarise(pay)
	if out.Refunded != 0 || out.Locked != 2 {
		t.Fatalf("a refused refund changed state: %+v", out)
	}
	f.conserves(t, pay)
}

// The intent must depend on EVERY input that identifies a fragment.
//
// Today two fragments always differ in both index and channel — duplicate
// channels are refused, and the index is the loop counter — so dropping either
// one alone still yields distinct intents. That makes the redundancy invisible
// to any behavioural test, and it is exactly the kind of redundancy that stops
// being redundant later: relax the one-fragment-per-channel rule and an intent
// that ignores the index collides silently, which the engine would then read as
// "already applied".
//
// So the derivation is tested directly for sensitivity to each input, the way a
// key derivation is.
func TestFragmentIntentDependsOnEveryInput(t *testing.T) {
	id := [32]byte{31: 202}
	ch := [32]byte{31: 0xC1}
	base := FragmentIntent(id, 0, ch, anon(10))

	cases := []struct {
		name string
		got  [32]byte
	}{
		{"payment id", FragmentIntent([32]byte{31: 203}, 0, ch, anon(10))},
		{"index", FragmentIntent(id, 1, ch, anon(10))},
		{"channel", FragmentIntent(id, 0, [32]byte{31: 0xC2}, anon(10))},
		{"amount", FragmentIntent(id, 0, ch, anon(11))},
	}
	for _, c := range cases {
		if c.got == base {
			t.Fatalf("changing the %s did not change the intent", c.name)
		}
	}
	// And it is deterministic, which is what makes a retry a retry.
	if FragmentIntent(id, 0, ch, anon(10)) != base {
		t.Fatal("the intent derivation is not deterministic")
	}
}
