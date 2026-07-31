package main

import (
	"context"
	"crypto/ed25519"
	"log"
	"net/url"
	"path/filepath"
	"strings"
	"time"

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

	// Publish where earnings should go. Without this the node does the work and
	// the credits have nowhere to land, so it is announced loudly rather than
	// left as a silent default.
	if cfg.PayoutAddress == "" {
		logger.Printf("proof-of-facilitation: NO PAYOUT ADDRESS SET — this node will earn nothing. " +
			"Set one on the management page.")
	} else {
		declaration := facilitation.DeclarePayout(pub, priv, cfg.PayoutAddress, uint64(time.Now().Unix()))
		gateway := facilitation.NewGatewayClient(siteBaseURL(cfg))
		publishCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := gateway.PublishPayout(publishCtx, declaration); err != nil {
			// Not fatal: the node still serves and still earns receipts. The
			// declaration is retried next start, and until it lands the
			// aggregator falls back to the registry owner.
			logger.Printf("proof-of-facilitation: could not publish payout address (%v) — will retry next start", err)
		} else {
			logger.Printf("proof-of-facilitation: earnings will be paid to %s", cfg.PayoutAddress)
		}
		cancel()
	}

	assignments, err := facilitation.LocalAssignments(agent.NodeID(), storageNode)
	if err != nil {
		logger.Printf("proof-of-facilitation: could not enumerate shards: %v", err)
	} else {
		nodeID := agent.NodeID()
		logger.Printf("proof-of-facilitation: answering audits for %d shard(s) as node %x",
			len(assignments), nodeID[:8])
	}
	// The epoch loop: advertise, audit whoever we were drawn to audit, upload
	// what we earned. Runs in the background so a slow relay never delays the
	// node serving data.
	go facilitation.RunEpochLoop(ctx, facilitation.EpochLoopConfig{
		Agent:     agent,
		Scheduler: scheduler,
		Store:     storageNode,
		Spool:     spool,
		Gateway:   facilitation.NewGatewayClient(siteBaseURL(cfg)),
		Pub:       pub,
		Logger:    logger,
		Interval:  10 * time.Minute,
	})
	// The epoch number is not logged here: it is not knowable until the loop
	// has read the network's anchor, and printing a clock-derived guess would
	// put a number in the log that no other node agrees with.
	logger.Printf("proof-of-facilitation: epoch loop started")

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

// siteBaseURL derives the website root from the configured registration API, so
// there is one place to point a node at a different deployment rather than a
// second URL to keep in sync.
func siteBaseURL(cfg config.Config) string {
	raw := strings.TrimSpace(cfg.Gateway.RegistrationAPI)
	if raw == "" {
		return "https://syndichan.org"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "https://syndichan.org"
	}
	return parsed.Scheme + "://" + parsed.Host
}
