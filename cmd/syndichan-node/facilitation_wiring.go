package main

import (
	"context"
	"crypto/ed25519"
	"log"
	"path/filepath"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/facilitation"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// Wiring the node into Proof-of-Facilitation.
//
// This turns the audit machinery on in the one direction that is safe to enable
// unconditionally: ANSWERING challenges. A node that stores shards can prove it
// at any time, the proof costs a Merkle path over data already on disk, and
// being auditable is what makes the storage worth paying for.
//
// Issuing challenges is deliberately NOT started here. A challenger needs the
// network's assignment list — who is supposed to hold what — and no directory
// for that exists yet. Running the issuing side against a partial view would
// produce audits of a handful of visible peers and silently ignore everyone
// else, which is worse than not auditing: it would look like coverage.

type facilitationRuntime struct {
	agent     *facilitation.Agent
	scheduler *facilitation.Scheduler
	spool     *facilitation.ReceiptStore
}

// startFacilitation installs the challenge responder. Returns nil (and logs
// why) whenever the node is not in a position to be audited, rather than
// failing startup: earning credits is optional, serving the network is not.
func startFacilitation(ctx context.Context, cfg config.Config, node *p2p.Node,
	storageNode *store.Store, logger *log.Logger) *facilitationRuntime {
	if node == nil || storageNode == nil {
		return nil
	}

	pub, priv, err := loadNodeSigningKey(node)
	if err != nil {
		logger.Printf("proof-of-facilitation disabled: %v", err)
		return nil
	}
	agent := facilitation.NewAgent(pub, priv)

	// The node id the network knows must be the one derived from the libp2p
	// identity, or receipts would be attributed to a node nobody can find.
	if derived, err := node.LocalNodeID(); err == nil && derived != agent.NodeID() {
		logger.Printf("proof-of-facilitation disabled: node id mismatch between p2p identity and signing key")
		return nil
	}

	spool, err := facilitation.OpenReceiptStore(filepath.Join(cfg.DataDir, "facilitation"))
	if err != nil {
		logger.Printf("proof-of-facilitation disabled: receipt spool unavailable: %v", err)
		return nil
	}

	scheduler := &facilitation.Scheduler{
		Agent: agent,
		Store: spool,
		Transport: facilitation.P2PTransport{Send: func(ctx context.Context, target [32]byte, payload []byte) ([]byte, error) {
			peerID, ok := node.PeerForNodeID(target)
			if !ok {
				// Unreachable, NOT failed: the caller must not record an
				// offline peer as one that lost its data.
				return nil, facilitation.ErrPeerUnreachable
			}
			return node.SendChallenge(ctx, peerID, payload)
		}},
	}

	node.SetChallengeHandler(facilitation.ChallengeResponder(
		scheduler, facilitation.StoreShardLoader(storageNode)))

	assignments, err := facilitation.LocalAssignments(agent.NodeID(), storageNode)
	if err != nil {
		logger.Printf("proof-of-facilitation: could not enumerate shards: %v", err)
	} else {
		nodeID := agent.NodeID()
		logger.Printf("proof-of-facilitation: answering audits for %d shard(s) as node %x",
			len(assignments), nodeID[:8])
	}
	logger.Printf("proof-of-facilitation: not issuing challenges yet (no network assignment directory)")

	return &facilitationRuntime{agent: agent, scheduler: scheduler, spool: spool}
}

func (f *facilitationRuntime) Close() {
	if f == nil || f.spool == nil {
		return
	}
	_ = f.spool.Close()
}

// loadNodeSigningKey returns the ed25519 keypair backing the libp2p identity —
// the same key whose keccak256 is the node id, so a receipt's signature and the
// identity it claims cannot be separated.
func loadNodeSigningKey(node *p2p.Node) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return node.SigningKey()
}
