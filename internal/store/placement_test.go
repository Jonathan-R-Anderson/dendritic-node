package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// openProductionShapedStore uses the real 6+3 layout, because the durability
// arithmetic only means anything at the numbers production runs.
func openProductionShapedStore(t *testing.T) *Store {
	t.Helper()
	storage, err := Open(t.TempDir(), 6, 3, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if err := storage.CreateBucket("dispersal"); err != nil {
		t.Fatal(err)
	}
	return storage
}

// A write must succeed with nobody to send shards to -- the network is
// frequently empty and refusing uploads until it is not would be worse than
// storing one copy. What must NOT happen is the object claiming a durability it
// does not have.
func TestWriteWithZeroPeersSucceedsAndIsMarkedUnderReplicated(t *testing.T) {
	storage := openProductionShapedStore(t)
	// No distributor is set, which is exactly the peerless case: nothing will
	// ever be asked to place a shard.
	content := distinctBytes(11, 300<<10)
	manifest, err := storage.PutObject("dispersal", "lonely.bin", "application/octet-stream",
		bytes.NewReader(content))
	if err != nil {
		t.Fatalf("a write with no peers must still succeed: %v", err)
	}

	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatalf("the write was not enrolled in the placement ledger: %v", err)
	}
	if !row.UnderReplicated() {
		t.Fatal("an object with zero remote holders claimed to be durable")
	}
	if row.FullyDispersed() {
		t.Fatal("an object with zero remote holders claimed to be fully dispersed")
	}
	if got := row.WeakestChunk(); got != 0 {
		t.Fatalf("WeakestChunk = %d, want 0 remote shard indexes", got)
	}
	for _, shard := range row.Shards {
		if len(shard.Holders) != 0 {
			t.Fatalf("shard %s claims holders %v with no peers in existence",
				shard.ShardID, shard.Holders)
		}
		if !shard.Local {
			t.Fatalf("shard %s is not recorded as local, but local disk is the only copy", shard.ShardID)
		}
	}

	summary, err := storage.PlacementStatus()
	if err != nil {
		t.Fatal(err)
	}
	if summary.Objects != 1 || summary.UnderReplicated != 1 || summary.LocalOnly != 1 ||
		summary.FullyDispersed != 0 {
		t.Fatalf("summary %#v does not report the object as local-only and under-replicated", summary)
	}

	// And it is queued for dispersal, durably, so a later peer gets it.
	candidates, err := storage.DispersalCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].ObjectID != manifest.ObjectID {
		t.Fatalf("under-replicated object is not in the dispersal queue: %#v", candidates)
	}

	// The bytes are still readable from the one copy that exists.
	var recovered bytes.Buffer
	if _, err := storage.GetObject("dispersal", "lonely.bin", &recovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Bytes(), content) {
		t.Fatal("locally stored object did not read back")
	}
}

// The durability threshold: six of nine is where the promise becomes true, five
// is not a weaker promise but no promise at all.
func TestDurabilityThresholdIsDataShards(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "threshold.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(12, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) != 1 {
		t.Fatalf("expected a single chunk, got %d", len(manifest.Chunks))
	}
	for index, ref := range manifest.Chunks[0].Shards {
		row, err := storage.LoadObjectPlacement(manifest.ObjectID)
		if err != nil {
			t.Fatal(err)
		}
		if want := index >= DurableRemoteShards(6); row.UnderReplicated() == want {
			t.Fatalf("with %d remote shards UnderReplicated()=%v", index, row.UnderReplicated())
		}
		if err := storage.ConfirmShardHolder(manifest.ObjectID, ref.ID, "peer-"+ref.ID[:4]); err != nil {
			t.Fatal(err)
		}
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if row.UnderReplicated() || !row.FullyDispersed() {
		t.Fatalf("all nine shards placed on distinct peers should be durable and complete: %#v", row)
	}
	// A holder dropping out takes the object back below the line, which is the
	// signal repair keys off.
	if err := storage.DropShardHolder(manifest.ObjectID,
		manifest.Chunks[0].Shards[0].ID, "peer-"+manifest.Chunks[0].Shards[0].ID[:4]); err != nil {
		t.Fatal(err)
	}
	row, _ = storage.LoadObjectPlacement(manifest.ObjectID)
	if row.FullyDispersed() {
		t.Fatal("an object that lost a holder still claims full dispersal")
	}
	if row.WeakestChunk() != 8 {
		t.Fatalf("WeakestChunk = %d after one holder left, want 8", row.WeakestChunk())
	}
}

// Reconstruction from EXACTLY dataShards, with nothing local at all: this is
// what a read looks like once shards genuinely live on other nodes.
func TestReadReconstructsFromExactlySixRemoteShards(t *testing.T) {
	storage := openProductionShapedStore(t)
	content := distinctBytes(13, 40<<10)
	manifest, err := storage.PutObject("dispersal", "remote.bin", "application/octet-stream",
		bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Chunks) != 1 {
		t.Fatalf("expected a single chunk, got %d", len(manifest.Chunks))
	}

	// Stash every shard, then wipe local disk: the node now holds none of them.
	elsewhere := map[string][]byte{}
	for _, ref := range manifest.Chunks[0].Shards {
		value, err := storage.ReadShard(ref.ID)
		if err != nil {
			t.Fatal(err)
		}
		elsewhere[ref.ID] = value
		if err := os.Remove(storage.shardPath(ref.ID)); err != nil {
			t.Fatal(err)
		}
	}

	// The "network" serves exactly six of the nine, chosen to include parity so
	// the decode is a real reconstruction and not a concatenation.
	servable := map[string]bool{}
	for _, index := range []int{0, 1, 2, 3, 7, 8} {
		servable[manifest.Chunks[0].Shards[index].ID] = true
	}
	var mu sync.Mutex
	var served []string
	storage.SetShardFetcher(func(_ context.Context, shardID string, _ []string) ([]byte, error) {
		if !servable[shardID] {
			return nil, errors.New("holder is gone")
		}
		mu.Lock()
		served = append(served, shardID)
		mu.Unlock()
		return elsewhere[shardID], nil
	})

	var recovered bytes.Buffer
	if _, err := storage.GetObject("dispersal", "remote.bin", &recovered); err != nil {
		t.Fatalf("six of nine shards must reconstruct the object: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), content) {
		t.Fatal("object reconstructed from six remote shards does not match")
	}
	mu.Lock()
	count := len(served)
	mu.Unlock()
	if count != 6 {
		t.Fatalf("fetched %d shards to decode a 6+3 chunk, want exactly 6", count)
	}
}

// And five is not "almost": Reed-Solomon decodes from dataShards or from
// nothing, so a read must fail rather than emit a short object.
func TestReadFailsWithFiveOfNineShards(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "short.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(14, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := map[string][]byte{}
	for _, ref := range manifest.Chunks[0].Shards {
		value, _ := storage.ReadShard(ref.ID)
		elsewhere[ref.ID] = value
		if err := os.Remove(storage.shardPath(ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	servable := map[string]bool{}
	for _, index := range []int{0, 1, 2, 3, 4} {
		servable[manifest.Chunks[0].Shards[index].ID] = true
	}
	storage.SetShardFetcher(func(_ context.Context, shardID string, _ []string) ([]byte, error) {
		if !servable[shardID] {
			return nil, errors.New("holder is gone")
		}
		return elsewhere[shardID], nil
	})
	var out bytes.Buffer
	if _, err := storage.GetObject("dispersal", "short.bin", &out); err == nil {
		t.Fatal("a read with five of nine shards must fail, not return partial bytes")
	}
}

// A read that is fully served locally must not touch the network at all -- the
// common case, and the one where a stray fetch costs an I2P round trip.
func TestReadDoesNotFetchWhenSixShardsAreLocal(t *testing.T) {
	storage := openProductionShapedStore(t)
	content := distinctBytes(15, 40<<10)
	manifest, err := storage.PutObject("dispersal", "local.bin", "application/octet-stream",
		bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	// Drop the three parity shards: six data shards remain, which is exactly
	// enough and must be recognised as enough.
	for _, ref := range manifest.Chunks[0].Shards[6:] {
		if err := os.Remove(storage.shardPath(ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	var fetches int
	storage.SetShardFetcher(func(context.Context, string, []string) ([]byte, error) {
		fetches++
		return nil, errors.New("should not have been called")
	})
	var recovered bytes.Buffer
	if _, err := storage.GetObject("dispersal", "local.bin", &recovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Bytes(), content) {
		t.Fatal("object did not read back from six local shards")
	}
	if fetches != 0 {
		t.Fatalf("made %d network fetches with a local quorum in hand", fetches)
	}
}

// The read path passes the ledger's holders to the fetcher, so a miss goes
// straight to a node that confirmed the bytes instead of searching every peer
// that ever connected.
func TestReadPassesRecordedHoldersToTheFetcher(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "hinted.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(16, 40<<10)))
	if err != nil {
		t.Fatal(err)
	}
	ref := manifest.Chunks[0].Shards[0]
	if err := storage.ConfirmShardHolder(manifest.ObjectID, ref.ID, "peer-holding-it"); err != nil {
		t.Fatal(err)
	}
	// Four shards away, so five local copies remain: below the six-shard quorum,
	// which is the only condition under which the network is consulted at all.
	elsewhere := map[string][]byte{}
	for _, gone := range manifest.Chunks[0].Shards[:4] {
		value, err := storage.ReadShard(gone.ID)
		if err != nil {
			t.Fatal(err)
		}
		elsewhere[gone.ID] = value
		if err := os.Remove(storage.shardPath(gone.ID)); err != nil {
			t.Fatal(err)
		}
	}
	hinted := make(chan []string, 9)
	storage.SetShardFetcher(func(_ context.Context, shardID string, hints []string) ([]byte, error) {
		if shardID == ref.ID {
			hinted <- hints
		}
		value, ok := elsewhere[shardID]
		if !ok {
			return nil, errors.New("not available")
		}
		return value, nil
	})
	var out bytes.Buffer
	if _, err := storage.GetObject("dispersal", "hinted.bin", &out); err != nil {
		t.Fatal(err)
	}
	select {
	case hints := <-hinted:
		if len(hints) != 1 || hints[0] != "peer-holding-it" {
			t.Fatalf("fetcher was given hints %v, want the recorded holder", hints)
		}
	default:
		t.Fatal("the missing shard was never offered to the fetcher")
	}
}

// Objects that predate the ledger are enrolled, so the backlog on the running
// node becomes visible instead of invisible.
func TestEnrolMissingPlacementsPicksUpPreLedgerObjects(t *testing.T) {
	storage := openProductionShapedStore(t)
	var ids []string
	for i := 0; i < 3; i++ {
		manifest, err := storage.PutObject("dispersal", string(rune('a'+i))+".bin",
			"application/octet-stream", bytes.NewReader(distinctBytes(int64(20+i), 8<<10)))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, manifest.ObjectID)
		if err := storage.forgetPlacement(manifest.ObjectID); err != nil {
			t.Fatal(err)
		}
	}
	enrolled, pending, err := storage.EnrolMissingPlacements(2)
	if err != nil {
		t.Fatal(err)
	}
	if enrolled != 2 || pending != 1 {
		t.Fatalf("enrolled %d with %d pending, want 2 and 1", enrolled, pending)
	}
	enrolled, pending, err = storage.EnrolMissingPlacements(10)
	if err != nil {
		t.Fatal(err)
	}
	if enrolled != 1 || pending != 0 {
		t.Fatalf("second pass enrolled %d with %d pending, want 1 and 0", enrolled, pending)
	}
	for _, id := range ids {
		if _, err := storage.LoadObjectPlacement(id); err != nil {
			t.Fatalf("object %s was never enrolled: %v", id, err)
		}
	}
}

// A deleted object must leave the queue, or the pass spends forever trying to
// place shards of something that no longer exists.
func TestDeletingAnObjectForgetsItsPlacement(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "gone.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(21, 8<<10)))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.DeleteObject("dispersal", "gone.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.LoadObjectPlacement(manifest.ObjectID); err == nil {
		t.Fatal("the placement row outlived the object")
	}
	candidates, err := storage.DispersalCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("deleted object is still queued for dispersal: %#v", candidates)
	}
}

// The queue must rotate. An object attempted a moment ago stands aside so the
// next one is tried, otherwise a handful of undispersable objects starve
// everything behind them.
func TestDispersalQueueRotatesOnCooldown(t *testing.T) {
	storage := openProductionShapedStore(t)
	var ids []string
	for i := 0; i < 3; i++ {
		manifest, err := storage.PutObject("dispersal", "q"+string(rune('a'+i))+".bin",
			"application/octet-stream", bytes.NewReader(distinctBytes(int64(30+i), 8<<10)))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, manifest.ObjectID)
	}
	first, err := storage.DispersalCandidates(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("queue returned %d candidates, want 1", len(first))
	}
	if err := storage.MarkPlacementAttempt(first[0].ObjectID); err != nil {
		t.Fatal(err)
	}
	second, err := storage.DispersalCandidates(1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 {
		t.Fatalf("queue returned %d candidates on the second pass, want 1", len(second))
	}
	if second[0].ObjectID == first[0].ObjectID {
		t.Fatal("the queue handed back the object it had just attempted; the rest would starve")
	}
	_ = ids
}

// Repair must audit objects that currently look perfect, because "fully
// dispersed" is a record of the past and a holder going away is the event
// repair exists to catch. The dispersal queue is right to skip them; the audit
// queue must not.
func TestAuditQueueIncludesHealthyObjectsThatDispersalSkips(t *testing.T) {
	storage := openProductionShapedStore(t)
	manifest, err := storage.PutObject("dispersal", "healthy.bin", "application/octet-stream",
		bytes.NewReader(distinctBytes(40, 8<<10)))
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			if err := storage.ConfirmShardHolder(manifest.ObjectID, ref.ID,
				"peer-"+ref.ID[:6]); err != nil {
				t.Fatal(err)
			}
		}
	}
	row, err := storage.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.FullyDispersed() {
		t.Fatal("test setup did not reach full dispersal")
	}
	dispersal, err := storage.DispersalCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(dispersal) != 0 {
		t.Fatalf("dispersal queue still holds a fully dispersed object: %#v", dispersal)
	}
	audit, err := storage.AuditCandidates(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 || audit[0].ObjectID != manifest.ObjectID {
		t.Fatal("a fully dispersed object is never audited, so a lost holder would go unnoticed")
	}
}
