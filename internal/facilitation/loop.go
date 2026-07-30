package facilitation

import (
	"context"
	"crypto/ed25519"
	"log"
	"time"
)

// The epoch loop: what a node does, forever, to be paid.
//
// Each pass advertises what it holds, audits the peers it was drawn to audit,
// and uploads the receipts it earned. Everything it needs that it cannot know
// alone — the epoch randomness, the network's assignments — is fetched, and a
// pass that cannot fetch them does nothing rather than guessing.

// EpochLoopConfig is what the loop needs to run.
type EpochLoopConfig struct {
	Agent     *Agent
	Scheduler *Scheduler
	Store     ShardReader
	Spool     *ReceiptStore
	Gateway   *GatewayClient
	Pub       ed25519.PublicKey
	Logger    *log.Logger
	Interval  time.Duration // how often to run a pass
	EpochOf   func(time.Time) uint64
}

// DefaultEpochSeconds matches the roadmap's one-hour epochs. Long enough that
// settlement gas is amortised over real work, short enough that an operator
// sees earnings the same day.
const DefaultEpochSeconds = 3600

// EpochAt maps wall-clock time to an epoch number. Derived from the clock
// rather than counted locally so every node agrees without coordination; a node
// with a badly wrong clock audits the wrong epoch and its receipts are rejected,
// which is the correct outcome and visible in its logs.
func EpochAt(t time.Time) uint64 { return uint64(t.Unix()) / DefaultEpochSeconds }

// RunEpochLoop runs until the context is cancelled.
func RunEpochLoop(ctx context.Context, cfg EpochLoopConfig) {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Minute
	}
	if cfg.EpochOf == nil {
		cfg.EpochOf = EpochAt
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// One pass immediately: a node restarted mid-epoch should not sit idle
	// until the next tick, since unaudited time is unpaid time.
	runEpochPass(ctx, cfg)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runEpochPass(ctx, cfg)
		}
	}
}

func runEpochPass(ctx context.Context, cfg EpochLoopConfig) {
	logf := func(format string, args ...any) {
		if cfg.Logger != nil {
			cfg.Logger.Printf("proof-of-facilitation: "+format, args...)
		}
	}
	epoch := cfg.EpochOf(time.Now())

	// 1. Advertise what we hold, so others can audit us. Done first: being
	// auditable is what earns, and it costs nothing if the rest fails.
	assignments, err := LocalAssignments(cfg.Agent.NodeID(), cfg.Store)
	if err != nil {
		logf("could not enumerate local shards: %v", err)
	} else if err := cfg.Gateway.PublishAssignments(ctx, cfg.Pub, assignments); err != nil {
		logf("could not advertise %d shard(s): %v", len(assignments), err)
	}

	// 2. Upload receipts earned earlier. Before auditing, so a node that is
	// drawn for no duty this epoch still gets paid for the last one.
	if cfg.Spool != nil {
		if earned, err := cfg.Spool.ListEpoch(epoch - 1); err == nil && len(earned) > 0 {
			if stored, err := cfg.Gateway.UploadReceipts(ctx, earned); err != nil {
				logf("could not upload %d receipt(s) for epoch %d: %v", len(earned), epoch-1, err)
			} else if stored > 0 {
				logf("uploaded %d receipt(s) for epoch %d", stored, epoch-1)
			}
		}
	}

	// 3. Audit the peers we were drawn to audit.
	seed, err := cfg.Gateway.EpochRandomness(ctx, epoch)
	if err != nil {
		// No randomness means no legitimate draw. Skipping is the only safe
		// move: auditing on a guessed seed produces receipts whose witness sets
		// nobody else agrees with.
		logf("no randomness for epoch %d yet (%v) — skipping this pass", epoch, err)
		return
	}
	network, candidates, err := cfg.Gateway.FetchAssignments(ctx)
	if err != nil {
		logf("could not read the assignment directory: %v", err)
		return
	}
	if len(network) == 0 {
		logf("no assignments advertised network-wide yet — nothing to audit")
		return
	}

	results, err := cfg.Scheduler.RunEpoch(ctx, seed, epoch, network, candidates)
	if err != nil {
		logf("epoch %d audit run failed: %v", epoch, err)
		return
	}
	passed, failed, unreachable := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Passed:
			passed++
		case r.Err == ErrPeerUnreachable:
			unreachable++
		default:
			failed++
		}
	}
	if len(results) > 0 {
		// Unreachable is counted apart from failed on purpose: one is a peer
		// that was offline, the other is a peer that could not prove it still
		// holds the data, and conflating them would libel the first.
		logf("epoch %d: audited %d assignment(s) — %d passed, %d failed, %d unreachable",
			epoch, len(results), passed, failed, unreachable)
	}
}
