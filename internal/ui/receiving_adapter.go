package ui

// The only file in this package that knows what a channel is.
//
// Everything else in the dashboard works against the Receiving interface, so
// the payment machinery has exactly one door into the UI and it is this one.
// If a panel ever needs something the interface does not offer, the right move
// is to widen the interface here rather than to import the channel package
// somewhere else — the second import is how a view becomes a participant.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
)

var errNoSuchChannel = errors.New("receiving: no such channel")

// PaymentNode is the payment side of a recipient's node, as this adapter needs
// it. Satisfied by wiring a *channel.Coordinator and a *channel.PayoutWorker
// together; an interface so the dashboard can be exercised without one.
type PaymentNode struct {
	Coord  *channel.Coordinator
	Payout *channel.PayoutWorker
}

// NewPaymentNode wires the adapter.
func NewPaymentNode(coord *channel.Coordinator, payout *channel.PayoutWorker) *PaymentNode {
	return &PaymentNode{Coord: coord, Payout: payout}
}

// Channels renders every tracked channel for the panel.
func (p *PaymentNode) Channels(_ context.Context) ([]ReceivingChannel, error) {
	if p.Coord == nil {
		return nil, errors.New("receiving: no payment coordinator")
	}
	out := []ReceivingChannel{}
	for _, id := range p.Coord.Channels() {
		bal, err := p.Coord.Balances(id)
		if err != nil {
			// One unreadable channel must not blank the whole panel: an
			// operator with five channels and one problem needs to see the
			// other four.
			continue
		}
		row := ReceivingChannel{
			ID:         hex.EncodeToString(id[:]),
			Mine:       bal.Mine.String(),
			Theirs:     bal.Theirs.String(),
			Locked:     bal.Locked.String(),
			Nonce:      bal.Nonce,
			Conflicted: bal.Conflicted,
			Mode:       string(channel.PayoutOnClose),
			Phase:      string(channel.PhaseNone),
		}
		// The node works out what is claimable and what is merely in flight —
		// this only renders the answer. See internal/channel/locks.go for why
		// that decision does not live here.
		if exp, err := p.Coord.Exposure(id); err == nil {
			row.Mine, row.Incoming = exp.Available, exp.Incoming
			row.Outgoing, row.Total = exp.Outgoing, exp.Total
		}
		if locks, err := p.Coord.Locks(id); err == nil {
			for _, l := range locks {
				direction := "outgoing"
				if l.Incoming {
					direction = "incoming"
				}
				row.Locks = append(row.Locks, PendingLock{
					ID:        hex.EncodeToString(l.ID[:]),
					Direction: direction,
					Amount:    l.Amount,
					Status:    string(l.Status),
					Expiry:    l.Expiry,
					ExpiresIn: l.ExpiresIn,
				})
			}
		}
		if p.Payout != nil {
			if st, err := p.Payout.Status(id); err == nil {
				row.Mode = string(st.Mode)
				row.Phase = string(st.Phase)
				row.TxHash = st.TxHash
				row.DueAt = st.DueAt
				row.Attempts = st.Attempts
				row.LastError = st.LastError
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// SetPolicy records when the recipient wants value on chain.
//
// The mode strings are the dashboard's, validated here rather than trusted:
// a radio button is not an authorisation, and this is the boundary where a
// form value becomes a decision about money.
func (p *PaymentNode) SetPolicy(_ context.Context, id, mode string, intervalSeconds int64) error {
	if p.Payout == nil {
		return errors.New("receiving: no settlement worker")
	}
	parsed, err := parseChannelID(id)
	if err != nil {
		return err
	}

	policy := channel.PayoutPolicy{}
	switch channel.PayoutMode(mode) {
	case channel.PayoutOnClose:
		policy.Mode = channel.PayoutOnClose
	case channel.PayoutOnInterval:
		if intervalSeconds <= 0 {
			return errors.New("receiving: an interval policy needs a positive interval")
		}
		policy.Mode = channel.PayoutOnInterval
		policy.IntervalSeconds = intervalSeconds
	default:
		return fmt.Errorf("receiving: unknown settlement mode %q", mode)
	}
	return p.Payout.SetPolicy(parsed, policy)
}

// SettleNow advances a channel's settlement one step.
//
// Returns the OUTCOME as well as any error, because "not due yet" and "the RPC
// is unreachable" are both non-completions and an operator needs to tell them
// apart.
func (p *PaymentNode) SettleNow(ctx context.Context, id string) (string, error) {
	if p.Payout == nil {
		return "", errors.New("receiving: no settlement worker")
	}
	parsed, err := parseChannelID(id)
	if err != nil {
		return "", err
	}
	outcome, err := p.Payout.Settle(ctx, parsed)
	return string(outcome), err
}

// Close asks for the money now, whatever the schedule says.
func (p *PaymentNode) Close(ctx context.Context, id string) (string, error) {
	if p.Payout == nil {
		return "", errors.New("receiving: no settlement worker")
	}
	parsed, err := parseChannelID(id)
	if err != nil {
		return "", err
	}
	if err := p.Payout.RequestClose(parsed); err != nil {
		return "", err
	}
	outcome, err := p.Payout.Settle(ctx, parsed)
	return string(outcome), err
}

func parseChannelID(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("receiving: channel id must be 32 hex bytes")
	}
	copy(out[:], raw)
	return out, nil
}

var _ Receiving = (*PaymentNode)(nil)
