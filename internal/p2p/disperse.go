package p2p

import (
	"bufio"
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/placement"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// DISPERSAL
// =========
// This replaces `target := peers[shardNumber%len(peers)]`.
//
// That line spread an object's shards across whatever libp2p happened to have a
// connection to -- gateway-only peers that never register the storage handler,
// cache-only peers that hard-refuse a store frame, probe nodes, the coordinator
// -- and with fewer than dataShards+parityShards of them it silently stacked
// several shards of one chunk on one host. Nothing recorded where anything
// went, nothing checked whether it arrived, and the caller marked the object
// done either way.
//
// Now: candidates are storage peers ranked by advertised free space, the
// assignment is computed by internal/placement (which cannot put two shards of
// a chunk on one node), every confirmed push is written to the ledger, and the
// result says how far it actually got.

const (
	// disperseConcurrency bounds simultaneous shard pushes. Each one is a lease
	// round trip over the I2P outproxy plus a stream, so this is about not
	// burying the lease service, not about local CPU.
	disperseConcurrency = 4
	// candidateLimit caps the DHT capacity lookup. More than this and the
	// lookup itself costs more than the placement it informs.
	candidateLimit = 32
	// candidateCacheTTL reuses a candidate set across the shards of one pass.
	// Rediscovering peers per chunk would issue a DHT query per megabyte.
	candidateCacheTTL = 2 * time.Minute
)

// DispersalResult reports what a dispersal pass achieved, per object.
//
// It exists because the old path returned nothing at all: DistributeManifest
// logged its failures and the caller then recorded the object as replicated
// regardless. That single fact explains the production symptom -- the backfill
// counter draining while every volunteer's shard directory stayed empty. The
// counter was measuring attempts.
type DispersalResult struct {
	// Placed is the number of shards a peer confirmed storing in THIS pass.
	Placed int
	// Failed is the number of attempted pushes that did not confirm.
	Failed int
	// Unassignable is the number of shards that had nowhere distinct to go,
	// because the network offered fewer usable peers than the chunk has shards.
	Unassignable int
	// WeakestChunk is the smallest number of distinct remotely-held shard
	// indexes across the object's chunks, after this pass. This is the object's
	// real durability: it is recoverable without this node only if this is at
	// least DataShards.
	WeakestChunk int
	// Durable is WeakestChunk >= store.DurableRemoteShards(DataShards).
	Durable bool
	// Complete is true when every shard of every chunk sits on some peer, which
	// is what buys tolerance of ParityShards simultaneous node losses.
	Complete bool
}

// candidateSource returns peers that can actually take a shard.
//
// Preference order is deliberate:
//  1. Peers advertising storage capacity at the DHT rendezvous. Those records
//     are published by nodes that run the storage role and have measured free
//     space, so a candidate from here is both willing and able.
//  2. Connected peers, with unknown free space. A young network has no capacity
//     records yet; refusing to disperse until the directory fills would mean
//     never dispersing on a fresh install.
//
// Peers that refuse are simply not confirmed and the ledger keeps the deficit,
// so a wrong guess in tier 2 costs one wasted attempt, never a false durability.
func (n *Node) storageCandidates(ctx context.Context) []placement.Candidate {
	n.candidateMu.Lock()
	if time.Since(n.candidateAt) < candidateCacheTTL && len(n.candidateCache) > 0 {
		cached := append([]placement.Candidate(nil), n.candidateCache...)
		n.candidateMu.Unlock()
		return cached
	}
	n.candidateMu.Unlock()

	byID := make(map[string]placement.Candidate)
	lookupCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	records, err := n.FindStoragePeers(lookupCtx, candidateLimit)
	cancel()
	if err == nil {
		now := time.Now()
		for _, record := range records {
			if !record.Fresh(now) || record.NodeID == n.host.ID().String() {
				continue
			}
			// Teach the host how to reach it, so the push does not fail on
			// "no addresses" for a peer we are not currently connected to.
			if _, dialErr := n.DialStoragePeer(ctx, record); dialErr != nil {
				continue
			}
			byID[record.NodeID] = placement.Candidate{
				PeerID: record.NodeID, FreeBytes: record.FreeBytes,
			}
		}
	}
	for _, connected := range n.host.Network().Peers() {
		if connected == n.host.ID() {
			continue
		}
		id := connected.String()
		if _, known := byID[id]; known {
			continue
		}
		byID[id] = placement.Candidate{PeerID: id}
	}

	out := make([]placement.Candidate, 0, len(byID))
	for _, candidate := range byID {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FreeBytes != out[j].FreeBytes {
			return out[i].FreeBytes > out[j].FreeBytes
		}
		return out[i].PeerID < out[j].PeerID
	})

	n.candidateMu.Lock()
	n.candidateCache, n.candidateAt = append([]placement.Candidate(nil), out...), time.Now()
	n.candidateMu.Unlock()
	return out
}

// DistributeManifest keeps its name and signature so the store's distributor
// hook and every existing caller stay wired, but it now disperses.
func (n *Node) DistributeManifest(ctx context.Context, manifest store.Manifest) {
	n.DisperseObject(ctx, manifest)
}

// DisperseObject places the shards of one object on distinct peers and returns
// how far it got.
func (n *Node) DisperseObject(ctx context.Context, manifest store.Manifest) DispersalResult {
	// Publish the chunk->shard map first, so a node holding none of the shards
	// can still locate them by bucket+key. Best-effort: a young network may have
	// nowhere to put it yet.
	if err := n.PublishManifest(ctx, manifest); err != nil {
		n.logger.Printf("could not publish manifest for %s: %v", shortID(manifest.ObjectID), err)
	}
	// The ledger row is normally written by putObject; an object stored before
	// this code existed has none, so create it here rather than skipping the
	// object forever.
	if _, err := n.store.LoadObjectPlacement(manifest.ObjectID); err != nil {
		if recordErr := n.store.RecordObjectPlacement(manifest); recordErr != nil {
			n.logger.Printf("could not open placement ledger for %s: %v",
				shortID(manifest.ObjectID), recordErr)
			return DispersalResult{}
		}
	}
	_ = n.store.MarkPlacementAttempt(manifest.ObjectID)

	candidates := n.storageCandidates(ctx)
	if len(candidates) == 0 {
		// NOT an error, and not a silent no-op either. A node with no peers must
		// still hold what it was given; it just must not pretend the object is
		// redundant. The ledger row stays under-replicated and the next pass
		// picks it up.
		row, err := n.store.LoadObjectPlacement(manifest.ObjectID)
		result := DispersalResult{}
		if err == nil {
			result.WeakestChunk = row.WeakestChunk()
			result.Durable = !row.UnderReplicated()
			result.Complete = row.FullyDispersed()
		}
		n.logger.Printf("object %s held locally and marked under-replicated; no storage peers available",
			shortID(manifest.ObjectID))
		return result
	}

	result := n.placeShards(ctx, manifest.ObjectID, candidates,
		func(shardID string) ([]byte, error) { return n.store.ReadShard(shardID) })

	row, err := n.store.LoadObjectPlacement(manifest.ObjectID)
	if err == nil {
		result.WeakestChunk = row.WeakestChunk()
		result.Durable = !row.UnderReplicated()
		result.Complete = row.FullyDispersed()
	}
	if !result.Durable {
		n.logger.Printf(
			"object %s is UNDER-REPLICATED: %d of %d distinct shard indexes are off this node (placed %d, failed %d, unassignable %d)",
			shortID(manifest.ObjectID), result.WeakestChunk,
			store.DurableRemoteShards(manifest.DataShards),
			result.Placed, result.Failed, result.Unassignable)
	}
	return result
}

// placeShards runs one placement round over every chunk of an object.
//
// read supplies the shard bytes. Dispersal reads them from local disk; repair
// hands in bytes it just regenerated, which is why this is a parameter and not
// a direct store call.
func (n *Node) placeShards(
	ctx context.Context,
	objectID string,
	candidates []placement.Candidate,
	read func(shardID string) ([]byte, error),
) DispersalResult {
	var result DispersalResult
	row, err := n.store.LoadObjectPlacement(objectID)
	if err != nil {
		return result
	}
	limit := make(chan struct{}, disperseConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, chunkIndex := range row.ChunkIndexes() {
		if ctx.Err() != nil {
			break
		}
		shards := row.PlacementSnapshot(chunkIndex)
		// One holder per shard: the redundancy comes from the erasure code, not
		// from copying each shard. dataShards+parityShards shards on that many
		// distinct nodes already tolerates parityShards losses; a second copy of
		// each would double the traffic to raise it no further.
		assignments := placement.Plan(shards, candidates, 1)
		unplaced := 0
		for _, shard := range shards {
			if len(shard.Holders) == 0 {
				unplaced++
			}
		}
		mu.Lock()
		if unplaced > len(assignments) {
			result.Unassignable += unplaced - len(assignments)
		}
		mu.Unlock()

		for _, assignment := range assignments {
			target, decodeErr := peer.Decode(assignment.Peer)
			if decodeErr != nil || target == n.host.ID() {
				mu.Lock()
				result.Failed++
				mu.Unlock()
				continue
			}
			wg.Add(1)
			go func(assignment placement.Assignment, target peer.ID) {
				defer wg.Done()
				select {
				case limit <- struct{}{}:
					defer func() { <-limit }()
				case <-ctx.Done():
					return
				}
				if err := n.placeOne(ctx, objectID, assignment.ShardID, target, read); err != nil {
					n.logger.Printf("shard %s not placed on %s: %v",
						shortID(assignment.ShardID), target, err)
					mu.Lock()
					result.Failed++
					mu.Unlock()
					return
				}
				mu.Lock()
				result.Placed++
				mu.Unlock()
			}(assignment, target)
		}
	}
	wg.Wait()
	return result
}

// placeOne pushes a single shard and records the holder only once the peer has
// confirmed it.
func (n *Node) placeOne(
	ctx context.Context, objectID, shardID string, target peer.ID,
	read func(string) ([]byte, error),
) error {
	value, err := read(shardID)
	if err != nil {
		return err
	}
	// Ask before sending. A peer that already has the shard (a retry, or a
	// content-addressed shard shared with another object) costs one small frame
	// instead of a full transfer plus a lease.
	if has, probeErr := n.PeerHasShard(ctx, target, shardID); probeErr == nil && has {
		return n.store.ConfirmShardHolder(objectID, shardID, target.String())
	}
	lease, err := n.requestLease(ctx, target, objectID, shardID, int64(len(value)))
	if err != nil {
		return err
	}
	if err := n.storeOnPeer(ctx, target, objectID, shardID, value, lease); err != nil {
		return err
	}
	return n.store.ConfirmShardHolder(objectID, shardID, target.String())
}

// PeerHasShard asks a peer whether it holds a shard.
//
// The "have" verb has been implemented server-side since the protocol was
// written and had no client anywhere. It is the cheap probe an audit needs: a
// repair loop that had to fetch a shard to find out whether it still existed
// would move the whole object to answer a yes/no question.
func (n *Node) PeerHasShard(ctx context.Context, target peer.ID, shardID string) (bool, error) {
	askCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stream, err := n.host.NewStream(askCtx, target, ProtocolID)
	if err != nil {
		return false, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{Operation: "have", ShardID: shardID}); err != nil {
		return false, err
	}
	var reply responseHeader
	if err := readJSONFrame(bufio.NewReader(stream), &reply); err != nil {
		return false, err
	}
	if !reply.OK {
		return false, errShardProbeRefused
	}
	return reply.Present, nil
}

// PlacementReport is what the operator sees. A node must never state a
// durability it does not have, so this reports the deficit as loudly as the
// success.
func (n *Node) PlacementReport() (store.PlacementSummary, error) {
	return n.store.PlacementStatus()
}

// shortID trims a content address for a log line.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// errShardProbeRefused means the peer answered the "have" frame with an error
// rather than a yes/no -- it is not a "no", and an audit must not treat it as
// one or a peer having a bad minute would look like a node that dropped out.
var errShardProbeRefused = errors.New("peer refused the shard probe")
