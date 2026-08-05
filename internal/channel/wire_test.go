package channel

import (
	"bytes"
	"errors"
	"testing"
)

func payerPayee(t *testing.T) (*Key, *Key, Peer, Peer) {
	t.Helper()
	payer, payee := DeriveKey(seedA), DeriveKey(seedB)
	// Each side's view of the other. Outbound/Inbound are from the LOCAL
	// perspective, so they mirror.
	payerView := Peer{PublicKey: payee.PublicKey(), Outbound: 1000, Inbound: 0, Nonce: 4}
	payeeView := Peer{PublicKey: payer.PublicKey(), Outbound: 1000, Inbound: 0, Nonce: 4}
	return payer, payee, payerView, payeeView
}

func TestFullPaymentExchange(t *testing.T) {
	payer, payee, payerView, payeeView := payerPayee(t)

	req, err := ProposePayment(payer, "ch1", payerView, 250)
	if err != nil {
		t.Fatal(err)
	}
	accept, err := AcceptPayment(payee, payeeView, req)
	if err != nil {
		t.Fatalf("payee rejected a valid payment: %v", err)
	}
	proof, err := ConfirmPayment(payerView, req, accept)
	if err != nil {
		t.Fatalf("payer could not confirm: %v", err)
	}
	if proof.Nonce != 5 {
		t.Errorf("nonce = %d, want 5", proof.Nonce)
	}
}

// The payee must validate against its OWN record. A signature proves who said
// something, never that it is true.
func TestPayeeRejectsInventedBalances(t *testing.T) {
	payer, payee, payerView, payeeView := payerPayee(t)

	// Payer claims a starting balance it does not have.
	inflated := payerView
	inflated.Outbound = 999999
	req, _ := ProposePayment(payer, "ch1", inflated, 500)

	if _, err := AcceptPayment(payee, payeeView, req); err == nil {
		t.Fatal("the payee accepted balances it never agreed to")
	}
}

// A replayed or rolled-back nonce must be refused.
func TestPayeeRejectsNonMonotonicNonce(t *testing.T) {
	payer, payee, payerView, payeeView := payerPayee(t)
	stale := payerView
	stale.Nonce = 2 // behind the payee's record of 4
	req, _ := ProposePayment(payer, "ch1", stale, 100)
	if _, err := AcceptPayment(payee, payeeView, req); !errors.Is(err, ErrNonceRegressed) {
		t.Fatalf("got %v, want a nonce error", err)
	}
}

// A payment that does not conserve value must be refused even with a valid
// signature over it.
func TestPayeeRejectsNonConservingPayment(t *testing.T) {
	payer, payee, payerView, payeeView := payerPayee(t)
	req, _ := ProposePayment(payer, "ch1", payerView, 250)
	// Payer's outbound drops by 250 but claims the payee gains 900.
	req.Inbound = 900
	proof, _ := payer.SignBalance("ch1", req.Nonce, req.Outbound, req.Inbound)
	req.Signature = proof.Signature

	if _, err := AcceptPayment(payee, payeeView, req); err == nil {
		t.Fatal("accepted a payment that creates value")
	}
}

// The payer must reject a countersignature over DIFFERENT balances — a peer
// that signed something else is not accepting this payment.
func TestPayerRejectsAlteredAcceptance(t *testing.T) {
	payer, payee, payerView, payeeView := payerPayee(t)
	req, _ := ProposePayment(payer, "ch1", payerView, 250)
	accept, _ := AcceptPayment(payee, payeeView, req)

	altered := accept
	altered.Inbound = 900
	if _, err := ConfirmPayment(payerView, req, altered); !errors.Is(err, ErrProtocol) {
		t.Fatalf("got %v, want a protocol error", err)
	}
}

func TestRejectionIsReportedNotSwallowed(t *testing.T) {
	_, _, payerView, _ := payerPayee(t)
	reject := Message{Kind: KindPayReject, Reason: "insufficient inbound"}
	if _, err := ConfirmPayment(payerView, Message{}, reject); !errors.Is(err, ErrRejected) {
		t.Fatalf("got %v, want ErrRejected", err)
	}
}

// Reconciliation, not retry. A peer holding a strictly newer valid state wins;
// an older claim is ignored rather than erroring, because after a crash a peer
// may genuinely be behind.
func TestReconciliationAdoptsOnlyStrictlyNewerStates(t *testing.T) {
	payer, payee, payerView, payeeView := payerPayee(t)
	req, _ := ProposePayment(payer, "ch1", payerView, 250)
	accept, _ := AcceptPayment(payee, payeeView, req)

	reply := Message{
		Kind: KindStateReply, Channel: accept.Channel, Nonce: accept.Nonce,
		Outbound: accept.Outbound, Inbound: accept.Inbound, Signature: accept.Signature,
	}
	proof, adopted, err := AdoptReconciled(payerView, reply)
	if err != nil || !adopted {
		t.Fatalf("a newer valid state was not adopted: %v", err)
	}
	if proof.Nonce != 5 {
		t.Errorf("adopted nonce %d", proof.Nonce)
	}

	// An older claim: ignored, not an error.
	old := reply
	old.Nonce = 3
	if _, adopted, err := AdoptReconciled(payerView, old); adopted || err != nil {
		t.Errorf("an older state was adopted or errored: %v", err)
	}
}

// A peer-controlled length is an allocation a peer controls.
func TestOversizedFrameIsRefusedBeforeAllocating(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // ~4 GiB
	if _, err := ReadMessage(&buf); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
	var zero bytes.Buffer
	zero.Write([]byte{0, 0, 0, 0})
	if _, err := ReadMessage(&zero); !errors.Is(err, ErrFrameTooLarge) {
		t.Error("a zero-length frame was accepted")
	}
}

func TestFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	sent := Message{Kind: KindPayRequest, Channel: "ch1", Nonce: 7, Outbound: 10, Inbound: 20}
	if err := WriteMessage(&buf, sent); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Nonce != 7 || got.Channel != "ch1" || got.Outbound != 10 {
		t.Fatalf("round trip changed the message: %+v", got)
	}
}

func TestCannotProposeMoreThanTheBalance(t *testing.T) {
	payer, _, payerView, _ := payerPayee(t)
	if _, err := ProposePayment(payer, "ch1", payerView, 1001); !errors.Is(err, ErrInsufficient) {
		t.Fatal("proposed a payment larger than the outbound balance")
	}
	if _, err := ProposePayment(payer, "ch1", payerView, 0); !errors.Is(err, ErrInsufficient) {
		t.Fatal("proposed a zero payment")
	}
}
