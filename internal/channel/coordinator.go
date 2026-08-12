package channel

// The payment coordinator — roadmap invariant P5-2.
//
// ONE COMPONENT TURNS A MESSAGE INTO MONEY
// ----------------------------------------
//	SCPP frame ─┐
//	            ├─▶ COORDINATOR ─▶ state machine ─▶ store
//	HTTP call ──┘
//
// Both entry points arrive here and nowhere else. That matters less for the two
// that exist today than for the five that will: HTTP, SCPP/1, HTLC routing, the
// settlement worker and the browser all end up touching the same channels, and
// a second path that commits state is a second set of payment semantics nobody
// meant to write.
//
// WHAT IT OWNS
// ------------
// Channel lookup, confirming a channel is real on chain, obtaining the
// authoritative deposit, intent idempotency, driving PeerSession, choosing
// direct versus routed, and returning a definitive result.
//
// WHAT IT MUST NOT DO
// -------------------
// Implement cryptographic validation. That is Channel.Accept's, and a second
// implementation of a money rule is two rules that will disagree eventually.
// Touch persisted maps. That is the store's.
//
// So this file contains no signature checking, no conservation arithmetic and
// no map writes. It decides WHICH operation is being asked for; the layers below
// decide whether it is legal and record it.
//
// WHY IT IS ALSO THE Committer
// ----------------------------
// PeerSession reaches persistence through the Committer interface. In production
// the coordinator is that interface, so a protocol message cannot reach the
// store without passing the check that the channel was established from a chain
// read. Handing PeerSession the store directly is legal — the protocol tests do
// it — but then nothing is enforcing where the collateral came from.

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

var (
	ErrChannelNotAdopted = errors.New("coordinator: channel is not tracked; adopt it from the chain first")
	ErrNotAParticipant   = errors.New("coordinator: this node is not a party to that channel")
)

// Coordinator is the single entry point for money-bearing operations.
type Coordinator struct {
	store    *Store
	chain    ChainReader
	chainID  *big.Int
	contract Address
	self     Address

	sess *PeerSession

	// adopting serialises chain reads per channel so two concurrent messages
	// about an unknown channel do not both go and fetch it.
	adopting sync.Mutex
}

// NewCoordinator wires the stack. The PeerSession it builds commits through the
// coordinator, not through the store, so every protocol-driven write passes the
// adoption check.
func NewCoordinator(store *Store, chain ChainReader, chainID *big.Int,
	contract, self Address, sign StateSigner) *Coordinator {

	c := &Coordinator{
		store: store, chain: chain,
		chainID:  new(big.Int).Set(orZero(chainID)),
		contract: contract, self: self,
	}
	c.sess = NewPeerSession(c, self, sign)
	return c
}

// Session exposes the protocol engine for clock configuration. It is not a way
// to bypass the coordinator: the session commits through it either way.
func (c *Coordinator) Session() *PeerSession { return c.sess }

// ---- Committer, for PeerSession --------------------------------------------

// Channel returns a tracked channel snapshot.
func (c *Coordinator) Channel(id [32]byte) (*Channel, bool) { return c.store.Get(id) }

// Commit is the ONE path that writes a money-bearing change.
//
// Everything else in this system proposes, transports or observes. When a
// second caller for this appears, it is worth asking what makes it different
// rather than adding it.
func (c *Coordinator) Commit(id [32]byte, mutate func(*Channel) error) error {
	return c.store.Update(id, mutate)
}

// ---- adoption ---------------------------------------------------------------

// Adopt makes a channel known to this node, using the chain as the authority.
//
// A peer may name a channel. It may not describe one. Everything that decides
// what the channel IS — the parties, and above all the deposits every later
// conservation check is measured against — comes from ChannelManagerV2.
//
// Idempotent: adopting an already-tracked channel is a no-op, because a peer
// re-announcing is ordinary and re-reading the chain for it is not free.
func (c *Coordinator) Adopt(ctx context.Context, id [32]byte) error {
	if _, ok := c.store.Get(id); ok {
		return nil
	}

	c.adopting.Lock()
	defer c.adopting.Unlock()
	// Re-check under the lock: another message about the same channel may have
	// adopted it while this one waited.
	if _, ok := c.store.Get(id); ok {
		return nil
	}

	occ, err := c.chain.ReadChannel(ctx, c.contract, id)
	if err != nil {
		return err
	}
	// A channel this node is not part of is not this node's business, and
	// tracking one would let a stranger fill the store with channels.
	if occ.PartyA != c.self && occ.PartyB != c.self {
		return ErrNotAParticipant
	}
	if err := c.store.TrackFromChain(c.chainID, c.contract, occ); err != nil {
		if errors.Is(err, ErrChannelExists) {
			return nil
		}
		return err
	}
	return nil
}

// AdoptAnnounced handles a peer's CHANNEL_ANNOUNCE.
//
// Note what is taken from the message: the channel id, and nothing else. The
// body also carries parties and deposits — they are read past deliberately, and
// the chain is asked instead. A peer's figures are a claim; the contract's are
// the fact.
func (c *Coordinator) AdoptAnnounced(ctx context.Context, env Envelope) error {
	id, err := parseBytes32(env.Channel)
	if err != nil {
		return err
	}
	return c.Adopt(ctx, id)
}

// ---- the payment result -----------------------------------------------------

// PaymentResult is the definitive answer to "did this payment happen".
type PaymentResult struct {
	// Done is true only when a fully signed state is persisted here.
	Done bool
	// Nonce carries the payment, when Done.
	Nonce uint64
	// Route says how it went. Direct today; routed once P6 lands.
	Route string
	// Rejected is set when the peer refused, with the reason it gave.
	Rejected RejectCode
	// Detail is the peer's explanation, for a human. Never parsed.
	Detail string
}

// Retryable reports whether this payment is worth attempting again later.
func (r PaymentResult) Retryable() bool { return r.Rejected != "" && r.Rejected.Retryable() }

// ---- outgoing payments -------------------------------------------------------

// Peer is however a message reaches the other node. Supplied by P5's transport;
// this layer only needs request/response.
type Peer interface {
	Exchange(ctx context.Context, out Envelope) (Envelope, error)
}

// Pay runs a payment to completion and returns a definitive result.
//
// Direct or routed is decided here — the choice belongs to the coordinator, not
// to the protocol engine, because it depends on what channels exist rather than
// on what a state says. Today there is one answer; P6 adds the other, and it
// changes nothing below this function.
func (c *Coordinator) Pay(ctx context.Context, id [32]byte, intent [32]byte,
	tr StateTransition, peer Peer) (PaymentResult, error) {

	if err := c.Adopt(ctx, id); err != nil {
		return PaymentResult{}, err
	}
	ch, ok := c.store.Get(id)
	if !ok {
		return PaymentResult{}, ErrChannelNotAdopted
	}
	if ch.Conflict != nil {
		return PaymentResult{}, ErrConflicted
	}

	// Already applied: answer from the record rather than paying again. The
	// protocol is idempotent underneath as well, but a caller asking twice
	// deserves the same answer without a round trip.
	if nonce, applied := ch.AppliedAt(intent); applied {
		return PaymentResult{Done: true, Nonce: nonce, Route: "direct"}, nil
	}

	propose, err := c.sess.Propose(id, intent, tr)
	if err != nil {
		return PaymentResult{}, err
	}

	reply, err := peer.Exchange(ctx, propose)
	if err != nil {
		// The message may or may not have arrived. Resolving that is resync's
		// job, not a guess made here — see Recover.
		return PaymentResult{}, err
	}

	switch reply.Type {
	case MsgStateAccept:
		if err := c.sess.HandleAccept(reply); err != nil {
			return PaymentResult{}, err
		}
		fresh, _ := c.store.Get(id)
		return PaymentResult{Done: true, Nonce: fresh.Latest.State.Nonce, Route: "direct"}, nil

	case MsgStateReject:
		code, err := c.sess.HandleReject(reply)
		if err != nil {
			return PaymentResult{}, err
		}
		var body StateRejectBody
		_ = reply.Body_(&body)
		return PaymentResult{Rejected: code, Detail: body.Detail}, nil

	case MsgStateResponse:
		// The peer answered a proposal with its latest state, which is what it
		// does when the intent already landed and the channel moved on.
		if _, err := c.sess.HandleResponse(reply); err != nil {
			return PaymentResult{}, err
		}
		fresh, _ := c.store.Get(id)
		if nonce, applied := fresh.AppliedAt(intent); applied {
			return PaymentResult{Done: true, Nonce: nonce, Route: "direct"}, nil
		}
		return PaymentResult{}, nil

	default:
		return PaymentResult{}, fmt.Errorf("coordinator: unexpected reply %s", reply.Type)
	}
}

// ---- incoming messages -------------------------------------------------------

// Handle processes one inbound SCPP/1 message and returns the reply, if any.
//
// The single door for the protocol. A transport reads a frame and hands it
// here; it never reaches into the session or the store itself.
func (c *Coordinator) Handle(ctx context.Context, env Envelope) (*Envelope, error) {
	switch env.Type {
	case MsgChannelAnnounce:
		return nil, c.AdoptAnnounced(ctx, env)

	case MsgStatePropose:
		// Adopt first: a proposal about a channel we have not seen is normal
		// when the peer opened it, and the chain settles whether it is real.
		id, err := parseBytes32(env.Channel)
		if err != nil {
			return nil, err
		}
		if err := c.Adopt(ctx, id); err != nil {
			return nil, err
		}
		reply, err := c.sess.HandlePropose(env)
		if err != nil {
			return nil, err
		}
		return &reply, nil

	case MsgStateRequest:
		reply, err := c.sess.HandleRequest(env)
		if err != nil {
			return nil, err
		}
		return &reply, nil

	case MsgStateResponse:
		if _, err := c.sess.HandleResponse(env); err != nil {
			return nil, err
		}
		return nil, nil

	case MsgStateAccept:
		return nil, c.sess.HandleAccept(env)

	case MsgStateReject:
		_, err := c.sess.HandleReject(env)
		return nil, err

	case MsgConflict:
		_, err := c.sess.HandleConflict(env)
		return nil, err

	case MsgHello, MsgClosing, MsgError:
		// Informational. Nothing money-bearing, so nothing to commit.
		return nil, nil
	}
	return nil, fmt.Errorf("coordinator: unhandled message %s", env.Type)
}

// ---- recovery ----------------------------------------------------------------

// Recover resolves a channel left mid-payment by a crash or a dropped
// connection, by asking the peer (§7) rather than guessing locally.
//
// Safe to call at any time. Adoption only ever moves forward: a strictly higher
// nonce that passes the complete validation, or nothing.
func (c *Coordinator) Recover(ctx context.Context, id [32]byte, peer Peer) (ResyncOutcome, error) {
	request, resync, err := c.sess.Resume(id)
	if err != nil {
		return "", err
	}
	if !resync {
		return ResyncSame, nil
	}
	reply, err := peer.Exchange(ctx, request)
	if err != nil {
		return "", err
	}
	if reply.Type != MsgStateResponse {
		return "", fmt.Errorf("coordinator: peer answered a state request with %s", reply.Type)
	}
	return c.sess.HandleResponse(reply)
}

// RecoverAll resolves every tracked channel. What a node does on startup.
func (c *Coordinator) RecoverAll(ctx context.Context, peer Peer) map[[32]byte]ResyncOutcome {
	out := map[[32]byte]ResyncOutcome{}
	for _, id := range c.store.IDs() {
		outcome, err := c.Recover(ctx, id, peer)
		if err != nil {
			// One unreachable peer must not stop the rest from recovering.
			out[id] = ResyncOutcome("ERROR: " + err.Error())
			continue
		}
		out[id] = outcome
	}
	return out
}

// ---- observation --------------------------------------------------------------

// Balances is what a caller may safely be told about a channel. Read-only, and
// derived from the persisted state rather than recomputed.
type Balances struct {
	ChannelID  [32]byte
	Mine       *big.Int
	Theirs     *big.Int
	Locked     *big.Int
	Nonce      uint64
	Conflicted bool
}

// Balances reports a channel's position. The HTTP layer's read path, so that it
// never needs the store.
func (c *Coordinator) Balances(id [32]byte) (Balances, error) {
	ch, ok := c.store.Get(id)
	if !ok {
		return Balances{}, ErrChannelNotAdopted
	}
	other := ch.PartyA
	if other == c.self {
		other = ch.PartyB
	}
	return Balances{
		ChannelID:  id,
		Mine:       ch.BalanceOf(c.self),
		Theirs:     ch.BalanceOf(other),
		Locked:     ch.Latest.State.lockedTotal(),
		Nonce:      ch.Latest.State.Nonce,
		Conflicted: ch.Conflict != nil,
	}, nil
}

// Channels lists what this node tracks.
func (c *Coordinator) Channels() [][32]byte { return c.store.IDs() }
