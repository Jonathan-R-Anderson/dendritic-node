package channel

// The two-party exchange that actually moves value.
//
// THE PROBLEM THIS PROTOCOL IS SHAPED AROUND
// ------------------------------------------
// A channel payment is an exchange of signatures, and it has three outcomes,
// not two:
//
//	completed     — both sides hold the counter-signed state
//	failed        — neither does
//	INDETERMINATE — the payee countersigned and the payer never received it
//
// The third is the one that matters, and most implementations get it wrong by
// treating a timeout as a failure. It is not. The payee may hold a fully signed
// state showing the payer owes the money, and the payer, believing the payment
// failed, retries at a NEW nonce — paying twice for one thing.
//
// So a timeout here returns ErrIndeterminate and the caller MUST NOT retry. It
// must reconcile: ask the peer for their latest state and adopt it if it is
// newer and valid. Reconciliation is cheap and idempotent; blind retry is how a
// payer loses money to their own error handling.
//
// WHY THE PAYEE SIGNS SECOND
// --------------------------
// The payer signs a state that is worse for themselves and sends it. The payee
// countersigns only if it is better for them. Neither party ever holds a state
// signed only by the OTHER — which would be a claim they could bank without
// having agreed to anything.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrame bounds a single message. A peer is untrusted, and a length field it
// controls is an allocation it controls.
const MaxFrame = 1 << 20

var (
	ErrIndeterminate = errors.New("channel: payment outcome unknown — reconcile, do not retry")
	ErrRejected      = errors.New("channel: peer rejected the payment")
	ErrFrameTooLarge = errors.New("channel: frame exceeds the limit")
	ErrProtocol      = errors.New("channel: protocol violation")
)

// MessageKind identifies a wire message.
type MessageKind uint8

const (
	KindPayRequest MessageKind = 1
	KindPayAccept  MessageKind = 2
	KindPayReject  MessageKind = 3
	KindStateQuery MessageKind = 4 // reconciliation
	KindStateReply MessageKind = 5
)

// Message is the whole protocol. Deliberately small: every message a peer can
// send is a message that must be validated, so the surface stays minimal.
type Message struct {
	Kind    MessageKind `json:"kind"`
	Channel ChannelID   `json:"channel"`
	Nonce   uint64      `json:"nonce"`
	// Balances the sender asserts AFTER this payment.
	Outbound Amount `json:"outbound"`
	Inbound  Amount `json:"inbound"`
	// Signature over (channel, nonce, outbound, inbound) from the sender.
	Signature []byte `json:"signature,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// WriteMessage frames and writes one message.
func WriteMessage(w io.Writer, m Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(body) > MaxFrame {
		return ErrFrameTooLarge
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(body)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ReadMessage reads one framed message.
//
// The declared length is checked BEFORE allocating. A peer sending a 4 GiB
// length would otherwise be an out-of-memory kill on this node, which is a
// denial of service costing the attacker one packet.
func ReadMessage(r io.Reader) (Message, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Message{}, err
	}
	size := binary.BigEndian.Uint32(head[:])
	if size == 0 || size > MaxFrame {
		return Message{}, ErrFrameTooLarge
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(body, &m); err != nil {
		return Message{}, ErrProtocol
	}
	return m, nil
}

// Peer is the counterparty's view needed to validate a payment.
type Peer struct {
	PublicKey []byte
	// Expected balances BEFORE the payment, from this node's own record. The
	// peer does not get to assert the starting point — only the delta.
	Outbound Amount
	Inbound  Amount
	Nonce    uint64
}

// ProposePayment builds the payer's half of the exchange.
func ProposePayment(key *Key, ch ChannelID, current Peer, amount Amount) (Message, error) {
	if amount <= 0 || amount > current.Outbound {
		return Message{}, ErrInsufficient
	}
	next := Message{
		Kind:     KindPayRequest,
		Channel:  ch,
		Nonce:    current.Nonce + 1,
		Outbound: current.Outbound - amount,
		Inbound:  current.Inbound + amount,
	}
	proof, err := key.SignBalance(ch, next.Nonce, next.Outbound, next.Inbound)
	if err != nil {
		return Message{}, err
	}
	next.Signature = proof.Signature
	return next, nil
}

// AcceptPayment is the payee's half: validate, then countersign.
//
// Every field the peer sent is checked against this node's OWN record. A payee
// that trusted the proposed balances would accept any state the payer cared to
// invent, signature and all — the signature proves who said it, never that it
// is true.
func AcceptPayment(key *Key, peer Peer, req Message) (Message, error) {
	if req.Kind != KindPayRequest {
		return Message{}, ErrProtocol
	}
	// Monotonic nonce. An equal or lower one is a replay or a rollback.
	if req.Nonce != peer.Nonce+1 {
		return Message{}, ErrNonceRegressed
	}
	// From the payee's side, the payer's outbound is the payee's inbound. The
	// payment must INCREASE what this node is owed and decrease the payer's, by
	// the same amount, conserving the total.
	delta := req.Inbound - peer.Inbound
	if delta <= 0 {
		return Message{}, fmt.Errorf("%w: payment does not increase the balance owed", ErrProtocol)
	}
	if peer.Outbound-req.Outbound != delta {
		return Message{}, fmt.Errorf("%w: balances do not conserve", ErrProtocol)
	}
	// And the payer's signature must cover exactly those balances.
	if err := VerifyBalance(peer.PublicKey, BalanceProof{
		Channel: req.Channel, Nonce: req.Nonce, Signature: req.Signature,
	}, req.Outbound, req.Inbound); err != nil {
		return Message{}, err
	}

	countersigned, err := key.SignBalance(req.Channel, req.Nonce, req.Outbound, req.Inbound)
	if err != nil {
		return Message{}, err
	}
	return Message{
		Kind: KindPayAccept, Channel: req.Channel, Nonce: req.Nonce,
		Outbound: req.Outbound, Inbound: req.Inbound,
		Signature: countersigned.Signature,
	}, nil
}

// ConfirmPayment is the payer checking the countersignature.
//
// A caller MUST persist the returned proof before treating the payment as
// complete — see native.go on why the fsync ordering is the highest-consequence
// detail in this package.
func ConfirmPayment(peer Peer, sent Message, reply Message) (BalanceProof, error) {
	switch reply.Kind {
	case KindPayReject:
		return BalanceProof{}, fmt.Errorf("%w: %s", ErrRejected, reply.Reason)
	case KindPayAccept:
	default:
		return BalanceProof{}, ErrProtocol
	}
	// The reply must be about the state that was actually sent. A peer that
	// countersigned different balances is not accepting this payment.
	if reply.Channel != sent.Channel || reply.Nonce != sent.Nonce ||
		reply.Outbound != sent.Outbound || reply.Inbound != sent.Inbound {
		return BalanceProof{}, ErrProtocol
	}
	proof := BalanceProof{
		Channel: reply.Channel, Nonce: reply.Nonce, Signature: reply.Signature,
	}
	if err := VerifyBalance(peer.PublicKey, proof, reply.Outbound, reply.Inbound); err != nil {
		return BalanceProof{}, err
	}
	return proof, nil
}

// Reconcile builds the query a payer sends after an indeterminate outcome.
//
// The correct response to "I do not know whether that payment happened" — never
// a retry. The peer answers with the newest state it holds, and the payer
// adopts it if it is newer and valid.
func Reconcile(ch ChannelID) Message {
	return Message{Kind: KindStateQuery, Channel: ch}
}

// AdoptReconciled decides whether a peer's claimed state supersedes ours.
//
// Adopts only a STRICTLY newer, validly signed state. A peer claiming an older
// one is ignored rather than treated as an error: after a crash it may
// genuinely be behind, and refusing to talk to it would strand the channel.
func AdoptReconciled(peer Peer, reply Message) (BalanceProof, bool, error) {
	if reply.Kind != KindStateReply {
		return BalanceProof{}, false, ErrProtocol
	}
	if reply.Nonce <= peer.Nonce {
		return BalanceProof{}, false, nil
	}
	proof := BalanceProof{
		Channel: reply.Channel, Nonce: reply.Nonce, Signature: reply.Signature,
	}
	if err := VerifyBalance(peer.PublicKey, proof, reply.Outbound, reply.Inbound); err != nil {
		return BalanceProof{}, false, err
	}
	return proof, true, nil
}
