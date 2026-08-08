package p2p

import (
	"errors"
	"testing"
	"time"
)

// A peer that keeps refusing must stop winning candidate slots. Measured on
// production: three refusing peers held every object at "placed 6, failed 3"
// while seven healthy nodes were available, because candidates are ranked by
// ADVERTISED free space and a refusing peer advertises plenty.
func TestAPeerThatKeepsRefusingStopsBeingACandidate(t *testing.T) {
	n := &Node{}
	const peer = "12D3KooWRefusesEverything"

	for i := 1; i < refusalsBeforeSkipping; i++ {
		n.noteRefusal(peer)
		if n.refusingPeer(peer) {
			t.Fatalf("skipped after only %d refusals; a peer having one bad round must not be dropped", i)
		}
	}
	n.noteRefusal(peer)
	if !n.refusingPeer(peer) {
		t.Fatalf("still a candidate after %d refusals", refusalsBeforeSkipping)
	}

	// Any success means whatever it was refusing over is gone.
	n.noteAccepted(peer)
	if n.refusingPeer(peer) {
		t.Error("a peer that accepted a shard is still being skipped")
	}
}

// The cooldown is what lets a fixed peer back in with nobody intervening -- a
// permanent blacklist would shrink the network every time a volunteer had a bad
// hour. RKLs refused every lease until its binary was replaced, then was fine.
func TestRefusalsExpireSoAFixedPeerReturns(t *testing.T) {
	n := &Node{}
	const peer = "12D3KooWWasBrokenNowFixed"
	for i := 0; i < refusalsBeforeSkipping; i++ {
		n.noteRefusal(peer)
	}
	if !n.refusingPeer(peer) {
		t.Fatal("expected the peer to be skipped")
	}
	n.refusalMu.Lock()
	n.refusals[peer].last = time.Now().Add(-refusalCooldown - time.Minute)
	n.refusalMu.Unlock()
	if n.refusingPeer(peer) {
		t.Error("the refusal never expired, so a repaired peer could never rejoin")
	}
}

// Absence is not refusal. A dial that never completed says the network was
// busy, which is not predictive and not the volunteer's fault.
func TestOnlyAnsweredRefusalsCount(t *testing.T) {
	for _, answered := range []string{
		"node is cache-only and does not host shards",
		"storage capacity exceeded",
		"invalid coordinator lease signature",
	} {
		if !answeredNo(errors.New(answered)) {
			t.Errorf("an explicit refusal was not counted: %q", answered)
		}
	}
	for _, absent := range []string{
		"failed to dial: all dials failed",
		"context deadline exceeded",
		"stream reset",
		"i2p stream connect failed: CANT_REACH_PEER",
	} {
		if answeredNo(errors.New(absent)) {
			t.Errorf("an unreachable peer was counted as refusing: %q", absent)
		}
	}
	if answeredNo(nil) {
		t.Error("nil error counted as a refusal")
	}
}
