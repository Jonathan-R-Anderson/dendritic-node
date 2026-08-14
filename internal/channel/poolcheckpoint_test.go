package channel

// Withdrawing pooled value — roadmap P15 phase 5, the WRITE path.
//
// A checkpoint moves real money out of a channel, so these tests are mostly
// about the ways it must refuse. The financially dangerous mistakes are:
//
//	a request that invents an amount the state does not hold
//	a repeat that withdraws the same value twice
//	a hardcoded party A, which withdraws against the wrong side
//	an unknown outcome reported as failure, inviting a second attempt
//
// Each has a test below, and each was written to fail against a plausible
// wrong implementation rather than to describe the one that exists.

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

func checkpointAPIFor(t *testing.T, deposit int64) (*http.Client, string, *wiredNode, *wiredNode, [32]byte, func()) {
	t.Helper()
	return poolAPIFor(t, deposit)
}

func postCheckpoint(t *testing.T, c *http.Client, base string, body any, token string) (int, map[string]any) {
	t.Helper()
	return do(t, c, http.MethodPost, base+"/v1/pool/checkpoint", body, token)
}

// ---- authentication ----------------------------------------------------------

func TestCheckpointRefusesWithoutTheNodeToken(t *testing.T) {
	c, base, payer, payee, id, stop := checkpointAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 100)

	for _, token := range []string{"", "wrong", testToken + "x"} {
		code, _ := postCheckpoint(t, c, base,
			map[string]any{"channel": poolChannelHex(id)}, token)
		if code != http.StatusUnauthorized {
			t.Fatalf("token %q: got %d, want 401", token, code)
		}
	}
}

func TestCheckpointIsPostOnly(t *testing.T) {
	c, base, _, _, id, stop := checkpointAPIFor(t, 500)
	defer stop()

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		code, _ := do(t, c, method, base+"/v1/pool/checkpoint",
			map[string]any{"channel": poolChannelHex(id)}, testToken)
		if code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: got %d, want 405", method, code)
		}
	}
}

// ---- what the request may and may not assert ---------------------------------

func TestCheckpointRefusesAnAmountLargerThanTheChannelHolds(t *testing.T) {
	c, base, payer, payee, id, stop := checkpointAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 100)

	// THE ONE THAT WOULD BE THEFT. If the request were treated as authority,
	// this would sign a state withdrawing value nobody paid.
	code, body := postCheckpoint(t, c, base, map[string]any{
		"channel": poolChannelHex(id),
		"amount":  anon(5000).String(),
	}, testToken)
	if code == http.StatusOK {
		t.Fatalf("a request withdrew more than the channel holds: %v", body)
	}
	if !strings.Contains(strings.ToLower(errText(body)), "withdrawable") {
		t.Fatalf("refusal did not name the reason: %v", body)
	}

	// And the state must be untouched — a refused request that still moved the
	// nonce would strand the channel.
	if v := poolOf(t, c, base); v.Withdrawable != anon(100).String() {
		t.Fatalf("a refused checkpoint changed the balance: %q", v.Withdrawable)
	}
}

func TestCheckpointRefusesAChannelThisNodeIsNotPartyTo(t *testing.T) {
	c, base, _, _, _, stop := checkpointAPIFor(t, 500)
	defer stop()

	var stranger [32]byte
	for i := range stranger {
		stranger[i] = 0x7e
	}
	code, _ := postCheckpoint(t, c, base,
		map[string]any{"channel": poolChannelHex(stranger)}, testToken)
	if code == http.StatusOK {
		t.Fatal("checkpointed a channel the node does not hold")
	}
	if code != http.StatusNotFound && code != http.StatusUnprocessableEntity {
		t.Fatalf("unexpected status %d for an unknown channel", code)
	}
}

func TestCheckpointRefusesMalformedRequests(t *testing.T) {
	c, base, _, _, _, stop := checkpointAPIFor(t, 500)
	defer stop()

	cases := []struct {
		name string
		body any
	}{
		{"no channel", map[string]any{}},
		{"channel not hex", map[string]any{"channel": "not-hex"}},
		{"channel too short", map[string]any{"channel": "abcd"}},
		{"amount not a number", map[string]any{"channel": strings.Repeat("ab", 32), "amount": "lots"}},
		{"amount hex", map[string]any{"channel": strings.Repeat("ab", 32), "amount": "0x10"}},
	}
	for _, tc := range cases {
		code, _ := postCheckpoint(t, c, base, tc.body, testToken)
		if code == http.StatusOK {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
}

func TestCheckpointRefusesZeroAndNegativeAmounts(t *testing.T) {
	c, base, payer, payee, id, stop := checkpointAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 100)

	for _, amount := range []string{"0", "-1", "-" + anon(50).String()} {
		code, _ := postCheckpoint(t, c, base, map[string]any{
			"channel": poolChannelHex(id), "amount": amount,
		}, testToken)
		if code == http.StatusOK {
			t.Fatalf("amount %q was accepted", amount)
		}
	}
}

func TestCheckpointRefusesAnEmptyChannel(t *testing.T) {
	c, base, _, _, id, stop := checkpointAPIFor(t, 500)
	defer stop()

	// Nobody has tipped through it. Withdrawing would spend gas to move zero
	// and would appear in the recipient's history as a withdrawal.
	code, _ := postCheckpoint(t, c, base,
		map[string]any{"channel": poolChannelHex(id)}, testToken)
	if code == http.StatusOK {
		t.Fatal("checkpointed a channel holding nothing")
	}
}

// ---- the happy path, and what it must report ---------------------------------

func TestCheckpointWithdrawsWhatTheStateActuallyHolds(t *testing.T) {
	c, base, payer, payee, id, stop := checkpointAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 65)

	code, body := postCheckpoint(t, c, base,
		map[string]any{"channel": poolChannelHex(id)}, testToken)
	if code != http.StatusOK {
		t.Fatalf("checkpoint: got %d, %v", code, body)
	}
	// No chain writer is wired here, so the honest outcome is SIGNED — the
	// value left the channel balance but has not been paid out.
	if body["outcome"] != string(CheckpointSigned) {
		t.Fatalf("outcome = %v, want SIGNED", body["outcome"])
	}
	if body["amount"] != anon(65).String() {
		t.Fatalf("amount = %v, want %s", body["amount"], anon(65))
	}

	// Pool.View must fall by exactly the withdrawal: the value is now recorded
	// as a withdrawal rather than as the recipient's balance.
	after := poolOf(t, c, base)
	if after.Withdrawable != "0" {
		t.Fatalf("withdrawable after checkpoint = %q, want 0", after.Withdrawable)
	}
}

func TestCheckpointOfPartOfTheBalanceLeavesTheRest(t *testing.T) {
	c, base, payer, payee, id, stop := checkpointAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 100)

	code, body := postCheckpoint(t, c, base, map[string]any{
		"channel": poolChannelHex(id), "amount": anon(40).String(),
	}, testToken)
	if code != http.StatusOK {
		t.Fatalf("partial checkpoint: %d %v", code, body)
	}
	if body["amount"] != anon(40).String() {
		t.Fatalf("amount = %v, want %s", body["amount"], anon(40))
	}
	if v := poolOf(t, c, base); v.Withdrawable != anon(60).String() {
		t.Fatalf("remaining = %q, want %s", v.Withdrawable, anon(60))
	}
}

// ---- idempotence -------------------------------------------------------------

func TestARepeatedCheckpointDoesNotWithdrawTwice(t *testing.T) {
	c, base, payer, payee, id, stop := checkpointAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 80)

	first, body1 := postCheckpoint(t, c, base,
		map[string]any{"channel": poolChannelHex(id)}, testToken)
	if first != http.StatusOK {
		t.Fatalf("first checkpoint: %d %v", first, body1)
	}

	// THE REPLAY. An identical request must not produce a second withdrawal.
	// After the first, the balance is zero, so a naive implementation either
	// refuses (fine) or — the dangerous case — signs another withdrawal at a
	// new nonce against value that is no longer there.
	second, body2 := postCheckpoint(t, c, base,
		map[string]any{"channel": poolChannelHex(id)}, testToken)

	if second == http.StatusOK && body2["amount"] != "0" {
		total := new(big.Int)
		a1, _ := new(big.Int).SetString(str(body1["amount"]), 10)
		a2, _ := new(big.Int).SetString(str(body2["amount"]), 10)
		total.Add(orZero(a1), orZero(a2))
		if total.Cmp(anon(80)) > 0 {
			t.Fatalf("two checkpoints withdrew %s from a channel holding %s",
				total, anon(80))
		}
	}

	// Whatever it answered, the channel must not have paid out twice.
	ch, _ := payee.coord.store.Get(id)
	got := withdrawnBy(ch.Latest.State, ch.PartyA == payee.coord.self)
	if got.Cmp(anon(80)) > 0 {
		t.Fatalf("withdrawal is %s, more than the %s ever paid in", got, anon(80))
	}
}

func TestTheCheckpointIntentIsDerivedFromTheStateNotTheCaller(t *testing.T) {
	var id [32]byte
	id[0] = 0x11

	// Same channel, same state, same amount → same key, so a repeat is
	// recognised. Change any of them and it is different work.
	base := CheckpointIntent(id, 4, anon(10))
	if base != CheckpointIntent(id, 4, anon(10)) {
		t.Fatal("the intent is not deterministic; a retry would look like new work")
	}
	if base == CheckpointIntent(id, 5, anon(10)) {
		t.Fatal("the intent ignores the nonce")
	}
	if base == CheckpointIntent(id, 4, anon(11)) {
		t.Fatal("the intent ignores the amount")
	}
	var other [32]byte
	other[0] = 0x22
	if base == CheckpointIntent(other, 4, anon(10)) {
		t.Fatal("the intent ignores the channel")
	}
}

// ---- party ordering ----------------------------------------------------------

func TestCheckpointDoesNotAssumeThePartyOrdering(t *testing.T) {
	// The regression this pins: an implementation reading WithdrawA or
	// BalanceA unconditionally works whenever the recipient happens to sort
	// lower, and silently withdraws against the contributor's side when it
	// does not. The suite's wiring fixes one ordering, so the check is made
	// directly against the side-aware helpers.
	mine := anon(7)
	theirs := anon(3)

	asA := State{BalanceA: mine, BalanceB: theirs}
	asB := State{BalanceA: theirs, BalanceB: mine}
	if recipientBalance(asA, true).Cmp(mine) != 0 {
		t.Fatal("party A's balance read from the wrong side")
	}
	if recipientBalance(asB, false).Cmp(mine) != 0 {
		t.Fatal("party B's balance read from the wrong side")
	}

	wA := State{WithdrawA: mine, WithdrawB: nil}
	wB := State{WithdrawA: nil, WithdrawB: mine}
	if withdrawnBy(wA, true).Cmp(mine) != 0 {
		t.Fatal("party A's withdrawal read from the wrong side")
	}
	if withdrawnBy(wB, false).Cmp(mine) != 0 {
		t.Fatal("party B's withdrawal read from the wrong side")
	}
	// And the cross cases must be zero, not the other party's number.
	if withdrawnBy(wA, false).Sign() != 0 || withdrawnBy(wB, true).Sign() != 0 {
		t.Fatal("a withdrawal was attributed to the wrong party")
	}
}

// ---- the contributor is required ---------------------------------------------

func TestCheckpointCannotCompleteWithoutTheContributor(t *testing.T) {
	// A checkpoint needs BOTH signatures — the contract verifies them. A node
	// that could withdraw alone would be able to take value the contributor
	// never agreed to hand over.
	payer, payee, id := wiredPair(t, anon(500))
	if _, err := payer.coord.Pay(context.Background(), id, intent(99),
		payTransition(50), directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}

	_, err := payee.coord.Checkpoint(context.Background(), id, nil, nil)
	if err == nil {
		t.Fatal("a checkpoint completed with no counterparty to co-sign it")
	}
	if !errors.Is(err, ErrCheckpointNoPeer) {
		t.Fatalf("want ErrCheckpointNoPeer, got %v", err)
	}

	// Nothing may have been recorded as withdrawn.
	ch, _ := payee.coord.store.Get(id)
	if withdrawnBy(ch.Latest.State, ch.PartyA == payee.coord.self).Sign() != 0 {
		t.Fatal("value was recorded as withdrawn without a co-signature")
	}
}

func TestAnUnreachableContributorIsUnknownNotFailure(t *testing.T) {
	// After the proposal is sent, a dead connection means the contributor MAY
	// have signed. Reporting failure here is what makes a recipient retry and
	// risk a second withdrawal.
	payer, payee, id := wiredPair(t, anon(500))
	if _, err := payer.coord.Pay(context.Background(), id, intent(98),
		payTransition(50), directPeer{t, payee.coord}); err != nil {
		t.Fatalf("pay: %v", err)
	}

	res, err := payee.coord.Checkpoint(context.Background(), id, nil, deadPeer{})
	if err == nil {
		t.Fatal("a dead peer produced no error")
	}
	if res.Outcome != CheckpointUnknown {
		t.Fatalf("outcome = %q, want UNKNOWN", res.Outcome)
	}
}

// ---- the node holds no ledger ------------------------------------------------

func TestCheckpointKeepsNoHistoryOfItsOwn(t *testing.T) {
	c, base, payer, payee, id, stop := checkpointAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 45)
	postCheckpoint(t, c, base, map[string]any{"channel": poolChannelHex(id)}, testToken)

	// The pool view is recomputed from signed states. After a withdrawal it
	// must reflect the new state, not a running total kept somewhere.
	raw := rawPool(t, c, base)
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, forbidden := range []string{"history", "withdrawals", "checkpoints", "total_withdrawn"} {
		if _, present := body[forbidden]; present {
			t.Fatalf("the pool view grew a ledger field: %q", forbidden)
		}
	}
}

func TestPoolViewAfterCheckpointEqualsAFreshReconstruction(t *testing.T) {
	c, base, payer, payee, id, stop := checkpointAPIFor(t, 500)
	defer stop()
	payInto(t, payer, payee, id, 90)
	postCheckpoint(t, c, base, map[string]any{"channel": poolChannelHex(id)}, testToken)

	served := poolOf(t, c, base)

	// A brand-new Pool object over the same store. If the endpoint were
	// carrying state between calls, these would differ.
	fresh := Pool{
		Name: PoolName, Recipient: payee.coord.self,
		Members: payee.coord.store.IDs(), Policy: PoolPolicy{Enabled: true},
	}
	view, err := fresh.View(payee.coord.store)
	if err != nil {
		t.Fatalf("fresh view: %v", err)
	}
	if decString(view.Withdrawable) != served.Withdrawable {
		t.Fatalf("served %q, fresh reconstruction %q",
			served.Withdrawable, decString(view.Withdrawable))
	}
}

// ---- helpers -----------------------------------------------------------------

func errText(body map[string]any) string {
	if body == nil {
		return ""
	}
	return str(body["error"])
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
