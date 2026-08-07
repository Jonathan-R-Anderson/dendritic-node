// Package placement decides WHICH node each shard of a chunk goes to.
//
// THE PROBLEM THIS FIXES
// ----------------------
// Erasure coding buys nothing unless the shards it produces end up in different
// failure domains. The node split every 1 MiB chunk into 6 data + 3 parity
// shards and then wrote all nine to its own disk; the later "distribute" pass
// handed them out with `peers[shardNumber % len(peers)]`, which only yields nine
// distinct holders by accident when nine or more peers happen to be connected.
// With five peers, peers 0..3 each received two shards of every chunk, so a
// single node loss consumed two of the three parity shards and two losses
// destroyed the object. The arithmetic looked like 6+3 and behaved like 6+1.
//
// WHAT THIS PACKAGE GUARANTEES
// ----------------------------
// Plan never assigns two shards of the SAME chunk to the same peer, and never
// assigns a shard to a peer already known to hold a shard of that chunk. If
// there are fewer usable peers than unplaced shards it returns FEWER
// assignments rather than doubling up: an unplaced shard is a visible deficit
// the repair loop can retire later, whereas a doubled-up shard is a durability
// claim that is quietly false.
//
// It is deliberately pure — no libp2p, no store, no I/O — because the property
// that matters ("no two shards of a chunk share a host") is a property of the
// assignment, and it should be testable without standing up a network.
package placement

import "sort"

// Candidate is a peer that could take a shard. FreeBytes comes from the DHT
// capacity record when one is available and is zero for a peer we only know is
// connected; zero sorts last but is still usable, so a young network with no
// capacity records yet still disperses.
type Candidate struct {
	PeerID    string
	FreeBytes int64
}

// Shard is one erasure shard of one chunk, as the planner sees it.
type Shard struct {
	// ID is the content address (sha256 hex) of the shard bytes.
	ID string
	// Index is the shard's position in the Reed-Solomon set: 0..DataShards-1 are
	// data, the rest parity. Needed because reconstruction is index-sensitive.
	Index int
	// Size in bytes, used for the capacity filter.
	Size int64
	// Holders are peers already confirmed to hold this shard.
	Holders []string
}

// Assignment binds one shard to one peer.
type Assignment struct {
	ShardID    string
	ShardIndex int
	Peer       string
}

// Plan assigns unplaced shards of a single chunk to distinct peers.
//
// wantHolders is how many distinct remote holders each shard should have; in
// practice 1, because the redundancy comes from the erasure code, not from
// copying each shard. A shard already at wantHolders is skipped.
//
// Candidates are tried emptiest-first so writes spread toward the nodes with
// room instead of repeatedly filling whichever peer answered first.
func Plan(shards []Shard, candidates []Candidate, wantHolders int) []Assignment {
	if wantHolders < 1 {
		wantHolders = 1
	}
	// Every peer that already holds ANY shard of this chunk is excluded from
	// taking another one. This is the whole point of the package: co-location
	// inside one chunk is what turns three tolerable losses into one.
	occupied := make(map[string]bool)
	for _, shard := range shards {
		for _, holder := range shard.Holders {
			occupied[holder] = true
		}
	}

	ranked := append([]Candidate(nil), candidates...)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].FreeBytes != ranked[j].FreeBytes {
			return ranked[i].FreeBytes > ranked[j].FreeBytes
		}
		// Deterministic tie-break so two nodes planning the same chunk from the
		// same inputs agree, and so tests are not flaky.
		return ranked[i].PeerID < ranked[j].PeerID
	})

	// Shards furthest from the target are served first, so a chunk with one
	// unplaced shard and eight placed ones does not lose its last slot to a
	// shard that is already covered.
	order := make([]int, 0, len(shards))
	for i := range shards {
		if len(shards[i].Holders) < wantHolders {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		return len(shards[order[a]].Holders) < len(shards[order[b]].Holders)
	})

	var out []Assignment
	for _, index := range order {
		shard := shards[index]
		need := wantHolders - len(shard.Holders)
		for need > 0 {
			picked := ""
			for _, candidate := range ranked {
				if occupied[candidate.PeerID] {
					continue
				}
				if candidate.FreeBytes > 0 && candidate.FreeBytes < shard.Size {
					continue
				}
				picked = candidate.PeerID
				break
			}
			if picked == "" {
				// Out of distinct peers. Leave the shard unplaced rather than
				// stacking it on a peer that already holds a sibling.
				break
			}
			occupied[picked] = true
			out = append(out, Assignment{ShardID: shard.ID, ShardIndex: shard.Index, Peer: picked})
			need--
		}
	}
	return out
}

// DistinctHolders counts the peers holding at least one shard of the chunk.
// This is the number that actually bounds survivability: a chunk whose nine
// shards sit on three peers survives one loss, not three, however many shards
// were "placed".
func DistinctHolders(shards []Shard) int {
	seen := make(map[string]bool)
	for _, shard := range shards {
		for _, holder := range shard.Holders {
			seen[holder] = true
		}
	}
	return len(seen)
}

// RemotelyRecoverable reports whether the shards held off this node are enough
// to rebuild the chunk WITHOUT the local copies — the only definition of
// redundancy that survives losing this node.
//
// It counts distinct shard INDEXES, not holders and not shards: Reed-Solomon
// needs dataShards distinct positions, and two copies of index 4 rebuild
// nothing that one copy does not.
func RemotelyRecoverable(shards []Shard, dataShards int) bool {
	return RemoteIndexCount(shards) >= dataShards
}

// RemoteIndexCount is the number of distinct shard indexes held by at least one
// remote peer.
func RemoteIndexCount(shards []Shard) int {
	seen := make(map[int]bool)
	for _, shard := range shards {
		if len(shard.Holders) > 0 {
			seen[shard.Index] = true
		}
	}
	return len(seen)
}
