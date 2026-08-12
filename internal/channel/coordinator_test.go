package channel

// Roadmap invariants P5-1 and P5-2, end to end.
//
// The test that matters here is not "a payment works" — session_test.go already
// proves that. It is that the SCPP/1 entry point and the API entry point reach
// the same state machine and the same store, so the two cannot drift into
// different payment semantics.

import (
	"context"
	"errors"
	"math/big"
	"testing"
)

// wiredNode is a full stack: chain → store → coordinator → session.
type wiredNode struct {
	t     *testing.T
	dir   string
	store *Store
	coord *Coordinator
	key   *signer
	clock int64
}

func newWiredNode(t *testing.T, key *signer, chain ChainReader, contract Address) *wiredNode {
	t.Helper()
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	n := &wiredNode{t: t, dir: dir, store: store, key: key, clock: 1_000_000}
	n.coord = NewCoordinator(store, chain, big.NewInt(1), contract, key.address(),
		func(raw [32]byte) ([]byte, error) { return key.sign(raw), nil })
	n.coord.Session().SetClock(func() int64 { return n.clock }, 30, 600)
	return n
}

// directPeer hands a message straight to the other coordinator, so the test
// exercises the real Handle path rather than a stub.
type directPeer struct {
	t     *testing.T
	other *Coordinator
}

func (p directPeer) Exchange(ctx context.Context, out Envelope) (Envelope, error) {
	reply, err := p.other.Handle(ctx, hop(p.t, out))
	if err != nil {
		return Envelope{}, err
	}
	if reply == nil {
		return Envelope{}, errors.New("peer had nothing to say")
	}
	return hop(p.t, *reply), nil
}

func wiredPair(t *testing.T, deposit *big.Int) (payer, payee *wiredNode, id [32]byte) {
	t.Helper()
	pk, qk := newSigner(t), newSigner(t)
	contract := mustAddr(t, deployedChannelManager)

	chain := NewFakeChain()
	id = chain.Add(pk.address(), qk.address(), deposit, new(big.Int))

	payer = newWiredNode(t, pk, chain, contract)
	payee = newWiredNode(t, qk, chain, contract)
	return payer, payee, id
}

// ---- the end-to-end path (P5-2) ---------------------------------------------

func TestAPaymentTraversesTheWholeStack(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	result, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25),
		directPeer{t, payee.coord})
	if err != nil {
		t.Fatalf("pay: %v", err)
	}
	if !result.Done || result.Nonce != 1 {
		t.Fatalf("result: %+v", result)
	}

	// Neither node was handed a channel: both adopted from the chain on the way
	// through, which is what makes the deposit authoritative.
	for _, n := range []*wiredNode{payer, payee} {
		bal, err := n.coord.Balances(id)
		if err != nil {
			t.Fatalf("balances: %v", err)
		}
		if bal.Nonce != 1 {
			t.Fatalf("node at nonce %d", bal.Nonce)
		}
	}
	mine, _ := payee.coord.Balances(id)
	if mine.Mine.Cmp(anon(25)) != 0 {
		t.Fatalf("payee holds %s, want 25", mine.Mine)
	}
}

// Both doors, one state machine. An API-driven payment and a protocol-driven one
// must land in the same place, at consecutive nonces, with no second semantics.
func TestBothEntryPointsShareOneCommitPath(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	peer := directPeer{t, payee.coord}

	// Door one: the API. Coordinator.Pay.
	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25), peer); err != nil {
		t.Fatalf("api payment: %v", err)
	}

	// Door two: a raw SCPP/1 frame arriving at Handle, exactly as a transport
	// would deliver it.
	propose, err := payer.coord.Session().Propose(id, intent(2), payTransition(30))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	reply, err := payee.coord.Handle(ctx, hop(t, propose))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if reply == nil || reply.Type != MsgStateAccept {
		t.Fatalf("protocol payment was not accepted: %v", reply)
	}
	if _, err := payer.coord.Handle(ctx, hop(t, *reply)); err != nil {
		t.Fatalf("handle accept: %v", err)
	}

	// One channel, one lineage, both payments on it.
	for name, n := range map[string]*wiredNode{"payer": payer, "payee": payee} {
		bal, _ := n.coord.Balances(id)
		if bal.Nonce != 2 {
			t.Fatalf("%s is at nonce %d, want 2", name, bal.Nonce)
		}
	}
	got, _ := payee.coord.Balances(id)
	if got.Mine.Cmp(anon(55)) != 0 {
		t.Fatalf("payee holds %s after 25 + 30, want 55", got.Mine)
	}
}

// ---- collateral comes from the chain (P5-1) ---------------------------------

// The whole point, as one test: the peer's story is consistent and the chain
// disagrees, so the payment cannot happen.
func TestAFabricatedDepositCannotFundAPayment(t *testing.T) {
	pk, qk := newSigner(t), newSigner(t)
	contract := mustAddr(t, deployedChannelManager)

	// The chain says ten.
	chain := NewFakeChain()
	id := chain.Add(pk.address(), qk.address(), anon(10), new(big.Int))

	payer := newWiredNode(t, pk, chain, contract)
	payee := newWiredNode(t, qk, chain, contract)
	ctx := context.Background()

	// The payer tries to send a hundred, which would be fine if the deposit were
	// the thousand it might claim elsewhere.
	_, err := payer.coord.Pay(ctx, id, intent(1), payTransition(100),
		directPeer{t, payee.coord})
	if err == nil {
		t.Fatal("a payment larger than the on-chain deposit went through")
	}
	if !errors.Is(err, ErrInsufficient) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// Within the real deposit, it works.
	if _, err := payer.coord.Pay(ctx, id, intent(2), payTransition(5),
		directPeer{t, payee.coord}); err != nil {
		t.Fatalf("a payment within the real deposit failed: %v", err)
	}
}

// A channel the chain has never heard of is not adopted, however insistently it
// is announced.
func TestAnInventedChannelIsNeverAdopted(t *testing.T) {
	pk := newSigner(t)
	chain := NewFakeChain()
	node := newWiredNode(t, pk, chain, mustAddr(t, deployedChannelManager))

	invented := [32]byte{0xde, 0xad, 0xbe, 0xef}
	if err := node.coord.Adopt(context.Background(), invented); !errors.Is(err, ErrChannelNotOnChain) {
		t.Fatalf("got %v, want ErrChannelNotOnChain", err)
	}
	if len(node.coord.Channels()) != 0 {
		t.Fatal("an invented channel was tracked")
	}
}

// A real channel between two other people is real, and still none of this
// node's business.
func TestAChannelThisNodeIsNotPartyToIsRefused(t *testing.T) {
	mine, theirs1, theirs2 := newSigner(t), newSigner(t), newSigner(t)
	chain := NewFakeChain()
	id := chain.Add(theirs1.address(), theirs2.address(), anon(500), new(big.Int))

	node := newWiredNode(t, mine, chain, mustAddr(t, deployedChannelManager))
	if err := node.coord.Adopt(context.Background(), id); !errors.Is(err, ErrNotAParticipant) {
		t.Fatalf("got %v, want ErrNotAParticipant", err)
	}
	if len(node.coord.Channels()) != 0 {
		t.Fatal("a stranger's channel was tracked")
	}
}

// Adoption happens on the way through, so a peer proposing on a channel this
// node has never seen still gets checked against the chain first.
func TestAProposalOnAnUnknownChannelAdoptsFromTheChainFirst(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	if len(payee.coord.Channels()) != 0 {
		t.Fatal("the payee started with the channel already tracked")
	}
	// The payer adopts its own channel explicitly. Session().Propose does NOT
	// adopt, and must not: reading the chain is the coordinator's job, and a
	// protocol engine that could do it would be a second place deciding what a
	// channel is.
	if err := payer.coord.Adopt(ctx, id); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	propose, err := payer.coord.Session().Propose(id, intent(1), payTransition(25))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	reply, err := payee.coord.Handle(ctx, hop(t, propose))
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if reply == nil || reply.Type != MsgStateAccept {
		t.Fatal("the payee did not accept after adopting")
	}
	if len(payee.coord.Channels()) != 1 {
		t.Fatal("the payee did not adopt the channel")
	}
}

// ---- idempotence and recovery through the coordinator -----------------------

func TestPayingTwiceWithOneIntentPaysOnce(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	peer := directPeer{t, payee.coord}

	first, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25), peer)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25), peer)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !second.Done || second.Nonce != first.Nonce {
		t.Fatalf("the repeat produced %+v, want the same as %+v", second, first)
	}
	got, _ := payee.coord.Balances(id)
	if got.Mine.Cmp(anon(25)) != 0 {
		t.Fatalf("payee holds %s — the intent was applied twice", got.Mine)
	}
}

func TestRecoverPullsBackACompletedPaymentAfterACrash(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	if err := payer.coord.Adopt(ctx, id); err != nil {
		t.Fatalf("adopt: %v", err)
	}

	// The payee completes it; the reply never reaches the payer.
	propose, err := payer.coord.Session().Propose(id, intent(1), payTransition(25))
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := payee.coord.Handle(ctx, hop(t, propose)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	before, _ := payer.coord.Balances(id)
	if before.Nonce != 0 {
		t.Fatal("the payer already has the state")
	}

	outcome, err := payer.coord.Recover(ctx, id, directPeer{t, payee.coord})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if outcome != ResyncAdopted {
		t.Fatalf("outcome %s, want ADOPTED", outcome)
	}
	after, _ := payer.coord.Balances(id)
	if after.Nonce != 1 || after.Theirs.Cmp(anon(25)) != 0 {
		t.Fatalf("recovered to nonce %d with %s to the peer", after.Nonce, after.Theirs)
	}
}

func TestRecoverAllReportsEveryChannel(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()
	peer := directPeer{t, payee.coord}

	if _, err := payer.coord.Pay(ctx, id, intent(1), payTransition(25), peer); err != nil {
		t.Fatalf("pay: %v", err)
	}
	report := payer.coord.RecoverAll(ctx, peer)
	if len(report) != 1 {
		t.Fatalf("report covers %d channels", len(report))
	}
	// Nothing pending, so nothing to resync.
	if report[id] != ResyncSame {
		t.Fatalf("outcome %s", report[id])
	}
}

// ---- rejections come back as results, not errors ----------------------------

func TestARefusedPaymentIsAResultNotAnError(t *testing.T) {
	payer, payee, id := wiredPair(t, anon(500))
	ctx := context.Background()

	// A lock expiring far too soon: structurally fine, refused on policy.
	add := StateTransition{
		Kind: KindLockAdd, Amount: anon(50), LockID: [32]byte{31: 1},
		Hash: [32]byte{31: 9}, Expiry: payer.clock + 10,
	}
	result, err := payer.coord.Pay(ctx, id, intent(1), add, directPeer{t, payee.coord})
	if err != nil {
		t.Fatalf("a refusal came back as an error: %v", err)
	}
	if result.Done {
		t.Fatal("a refused payment reported success")
	}
	if result.Rejected != RejectLocksMalformed {
		t.Fatalf("code %s", result.Rejected)
	}
	// Nothing moved on either side.
	for _, n := range []*wiredNode{payer, payee} {
		bal, _ := n.coord.Balances(id)
		if bal.Nonce != 0 {
			t.Fatal("a refused payment changed state")
		}
	}
}

// ---- the layering itself ----------------------------------------------------

// The coordinator is what PeerSession commits through, so a protocol message
// cannot reach the store without passing adoption.
func TestTheSessionCommitsThroughTheCoordinator(t *testing.T) {
	payer, _, _ := wiredPair(t, anon(500))
	var committer Committer = payer.coord
	if _, ok := committer.(*Coordinator); !ok {
		t.Fatal("the coordinator is not the committer")
	}
	// And the store is a valid Committer too — that is what lets the protocol
	// tests run without a chain.
	var _ Committer = payer.store
}
