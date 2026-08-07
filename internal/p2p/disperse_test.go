package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// stubCoordinator signs whatever lease is asked for, so a test exercises
// placement rather than the lease service.
func stubCoordinator(t *testing.T, nodes ...*Node) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		node.coordKey = publicKey
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request leaseRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxHeaderBytes)).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lease := Lease{
			Version: 1, ObjectID: request.ObjectID, ShardID: request.ShardID,
			Size: request.Size, Recipient: request.Recipient,
			ExpiresAt: time.Now().Unix() + 300,
		}
		lease.Signature = base64.RawStdEncoding.EncodeToString(
			ed25519.Sign(privateKey, leaseMessage(lease)),
		)
		_ = json.NewEncoder(w).Encode(lease)
	}))
	t.Cleanup(server.Close)
	previous := leaseURL
	leaseURL = server.URL
	t.Cleanup(func() { leaseURL = previous })
}

// varyingBytes is deterministic pseudo-random content. Uniform content matters:
// shards are content-addressed, so a chunk of identical bytes produces IDENTICAL
// data shards that dedup into one file on disk, and a test that deletes "two
// shards" would delete one.
func varyingBytes(seed int64, size int) []byte {
	buf := make([]byte, size)
	mathrand.New(mathrand.NewSource(seed)).Read(buf)
	return buf
}

// shardFileOf is where the store keeps a shard on disk. Spelled out here rather
// than exported from the store: tests need to simulate a lost shard, production
// code has no business unlinking one.
func shardFileOf(dir, shardID string) string {
	return filepath.Join(dir, "storage", "shards", shardID[:2], shardID)
}

func openTestNode(t *testing.T, ctx context.Context, dataShards, parityShards int) (*Node, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	storage, err := store.Open(dir+"/storage", dataShards, parityShards, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	node, err := openNode(ctx, dir, []string{"/ip4/127.0.0.1/tcp/0"}, storage,
		log.New(io.Discard, "", 0), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })
	return node, storage, dir
}

// THE REQUIREMENT. Losing one node must cost at most one shard per chunk.
//
// The old distributor used `peers[shardNumber%len(peers)]`, which gives distinct
// holders only by accident when there happen to be at least as many peers as
// shards. This asserts the property directly, end to end over real libp2p hosts:
// every shard of the chunk landed, and no host holds two of them.
func TestDispersalPutsEachShardOfAChunkOnADistinctNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, _ := openTestNode(t, ctx, dataShards, parityShards)

	targets := make([]*Node, 0, dataShards+parityShards)
	stores := make([]*store.Store, 0, dataShards+parityShards)
	for i := 0; i < dataShards+parityShards; i++ {
		node, storage, _ := openTestNode(t, ctx, dataShards, parityShards)
		targets = append(targets, node)
		stores = append(stores, storage)
	}
	stubCoordinator(t, append([]*Node{source}, targets...)...)
	for _, target := range targets {
		if err := source.host.Connect(ctx, peer.AddrInfo{
			ID: target.host.ID(), Addrs: target.host.Addrs(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := sourceStore.CreateBucket("spread"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("spread", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(1, 8000)))
	if err != nil {
		t.Fatal(err)
	}
	result := source.DisperseObject(ctx, *manifest)
	if result.Placed != len(manifest.Chunks)*(dataShards+parityShards) {
		t.Fatalf("placed %d shards, want %d", result.Placed,
			len(manifest.Chunks)*(dataShards+parityShards))
	}
	if !result.Durable || !result.Complete {
		t.Fatalf("dispersal onto %d distinct peers reported %#v", len(targets), result)
	}

	// What the peers actually hold, measured from their own disks rather than
	// from the sender's opinion.
	for _, chunk := range manifest.Chunks {
		holdersOfChunk := map[int]int{}
		for _, ref := range chunk.Shards {
			carriers := 0
			for index, storage := range stores {
				value, err := storage.ReadShard(ref.ID)
				if err != nil {
					continue
				}
				expected, err := sourceStore.ReadShard(ref.ID)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(value, expected) {
					t.Fatalf("node %d stored different bytes for shard %s", index, ref.ID[:12])
				}
				carriers++
				holdersOfChunk[index]++
			}
			if carriers == 0 {
				t.Fatalf("shard %d of chunk %d reached no peer at all", ref.Index, chunk.Index)
			}
		}
		for index, count := range holdersOfChunk {
			if count > 1 {
				t.Fatalf("node %d holds %d shards of chunk %d; one node loss would cost %d of %d parity",
					index, count, chunk.Index, count, parityShards)
			}
		}
	}

	// And the ledger agrees, because repair and the read path both key off it.
	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if row.UnderReplicated() || !row.FullyDispersed() {
		t.Fatalf("ledger reports %#v after a complete dispersal", row)
	}
	for _, chunkIndex := range row.ChunkIndexes() {
		seen := map[string]string{}
		for _, shard := range row.PlacementSnapshot(chunkIndex) {
			if len(shard.Holders) != 1 {
				t.Fatalf("shard %d of chunk %d has holders %v, want exactly one",
					shard.Index, chunkIndex, shard.Holders)
			}
			if previous, clash := seen[shard.Holders[0]]; clash {
				t.Fatalf("ledger puts shards %s and %s of chunk %d on the same node",
					previous, shard.ID[:12], chunkIndex)
			}
			seen[shard.Holders[0]] = shard.ID[:12]
		}
	}
}

// With fewer peers than shards, the honest outcome is fewer placements and an
// object that still says it is under-replicated -- not shards stacked two to a
// host under a durability claim that does not hold.
func TestDispersalWithTooFewPeersRefusesToDoubleUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, _ := openTestNode(t, ctx, dataShards, parityShards)
	targetA, storeA, _ := openTestNode(t, ctx, dataShards, parityShards)
	targetB, storeB, _ := openTestNode(t, ctx, dataShards, parityShards)
	stubCoordinator(t, source, targetA, targetB)
	for _, target := range []*Node{targetA, targetB} {
		if err := source.host.Connect(ctx, peer.AddrInfo{
			ID: target.host.ID(), Addrs: target.host.Addrs(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sourceStore.CreateBucket("cramped"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("cramped", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(2, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	result := source.DisperseObject(ctx, *manifest)
	if result.Placed != 2 {
		t.Fatalf("placed %d shards on 2 peers, want 2", result.Placed)
	}
	if result.Unassignable != 3 {
		t.Fatalf("reported %d unassignable shards, want the 3 with nowhere distinct to go",
			result.Unassignable)
	}
	if result.Durable {
		t.Fatal("2 of 3 data shards off-node was reported as durable; it cannot be decoded")
	}
	for name, storage := range map[string]*store.Store{"A": storeA, "B": storeB} {
		held := 0
		for _, ref := range manifest.Chunks[0].Shards {
			if _, err := storage.ReadShard(ref.ID); err == nil {
				held++
			}
		}
		if held > 1 {
			t.Fatalf("peer %s holds %d shards of one chunk", name, held)
		}
	}
}

// Repair is triggered by the periodic pass, by a dispersal that finds a chunk
// short, and by overlapping runs of either; shard ids are shared between objects
// because shards are content-addressed. Two concurrent repairs of one shard
// would regenerate the same bytes twice, take two coordinator leases, and race
// into the ledger.
func TestRepairDoesNotRunTwiceForTheSameShardConcurrently(t *testing.T) {
	node := &Node{repairing: make(map[string]struct{})}
	const shardID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	const racers = 64
	var (
		start   sync.WaitGroup
		done    sync.WaitGroup
		mu      sync.Mutex
		granted int
		inside  int
		peak    int
	)
	start.Add(1)
	for i := 0; i < racers; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			if !node.beginRepair(shardID) {
				return
			}
			mu.Lock()
			granted++
			inside++
			if inside > peak {
				peak = inside
			}
			mu.Unlock()
			// Hold the slot long enough that a broken gate would overlap.
			time.Sleep(time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			node.endRepair(shardID)
		}()
	}
	start.Done()
	done.Wait()

	if peak > 1 {
		t.Fatalf("%d goroutines repaired the same shard at once", peak)
	}
	if granted == 0 {
		t.Fatal("no goroutine was ever allowed to repair the shard")
	}
	// The slot is released, so a later pass can repair it again.
	if !node.beginRepair(shardID) {
		t.Fatal("the repair slot was never released")
	}
	node.endRepair(shardID)

	// A different shard is never blocked by an in-flight repair of another.
	if !node.beginRepair(shardID) {
		t.Fatal("could not claim the first shard")
	}
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if !node.beginRepair(other) {
		t.Fatal("an unrelated shard was blocked by another shard's repair")
	}
	if node.beginRepair(shardID) {
		t.Fatal("the same shard was claimed twice")
	}
	node.endRepair(shardID)
	node.endRepair(other)
}

// The other half of the user's request: when a node drops out, the pieces it
// held are rebuilt from the survivors.
func TestRepairRebuildsShardsLostWithAHolder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, sourceDir := openTestNode(t, ctx, dataShards, parityShards)
	if err := sourceStore.CreateBucket("repair"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("repair", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(3, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := manifest.Chunks[0]

	// Two shards are gone: the holder that had them is gone and the local copies
	// went with a disk. Three survive, which is exactly dataShards.
	lost := chunk.Shards[:2]
	originals := map[string][]byte{}
	for _, ref := range lost {
		value, err := sourceStore.ReadShard(ref.ID)
		if err != nil {
			t.Fatal(err)
		}
		originals[ref.ID] = value
		if err := os.Remove(shardFileOf(sourceDir, ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	for _, ref := range lost {
		if _, err := sourceStore.ReadShard(ref.ID); err == nil {
			t.Fatal("test setup did not actually remove the shard")
		}
	}

	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	budget := 16
	restored, err := source.restoreChunkBytes(ctx, *manifest, chunk.Index,
		row.PlacementSnapshot(chunk.Index), &budget)
	if err != nil {
		t.Fatal(err)
	}
	if restored != 2 {
		t.Fatalf("rebuilt %d shards, want 2", restored)
	}
	if budget != 14 {
		t.Fatalf("repair budget is %d, want it charged for 2 shards", budget)
	}
	for _, ref := range lost {
		rebuilt, err := sourceStore.ReadShard(ref.ID)
		if err != nil {
			t.Fatalf("shard %s was not rebuilt: %v", ref.ID[:12], err)
		}
		if !bytes.Equal(rebuilt, originals[ref.ID]) {
			t.Fatalf("rebuilt shard %s differs from the original", ref.ID[:12])
		}
	}
}

// The storm brake. A netsplit makes every holder unreachable at once, so an
// unbudgeted repair would try to rebuild the whole catalogue at the moment the
// network can least carry it.
func TestRepairBudgetCapsShardsRebuiltInOnePass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, sourceDir := openTestNode(t, ctx, dataShards, parityShards)
	if err := sourceStore.CreateBucket("budget"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("budget", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(4, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := manifest.Chunks[0]
	for _, ref := range chunk.Shards[:2] {
		if err := os.Remove(shardFileOf(sourceDir, ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	budget := 1
	restored, err := source.restoreChunkBytes(ctx, *manifest, chunk.Index,
		row.PlacementSnapshot(chunk.Index), &budget)
	if err != nil {
		t.Fatal(err)
	}
	if restored != 1 || budget != 0 {
		t.Fatalf("rebuilt %d shards with %d budget left; the cap did not hold", restored, budget)
	}
}

// Fewer than dataShards survivors is a lost chunk, and repair must say so
// rather than write out whatever Reconstruct returns.
func TestRepairRefusesToRebuildBelowDataShards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const dataShards, parityShards = 3, 2
	source, sourceStore, sourceDir := openTestNode(t, ctx, dataShards, parityShards)
	if err := sourceStore.CreateBucket("lost"); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceStore.PutObject("lost", "object.bin", "application/octet-stream",
		bytes.NewReader(varyingBytes(5, 4000)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := manifest.Chunks[0]
	for _, ref := range chunk.Shards[:3] {
		if err := os.Remove(shardFileOf(sourceDir, ref.ID)); err != nil {
			t.Fatal(err)
		}
	}
	row, err := sourceStore.LoadObjectPlacement(manifest.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	budget := 16
	if _, err := source.restoreChunkBytes(ctx, *manifest, chunk.Index,
		row.PlacementSnapshot(chunk.Index), &budget); err == nil {
		t.Fatal("repair claimed to rebuild a chunk with 2 of 3 data shards surviving")
	}
}
