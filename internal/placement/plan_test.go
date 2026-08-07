package placement

import (
	"fmt"
	"testing"
)

func chunkOf(count int, size int64) []Shard {
	shards := make([]Shard, count)
	for i := range shards {
		shards[i] = Shard{ID: fmt.Sprintf("shard-%02d", i), Index: i, Size: size}
	}
	return shards
}

func peers(count int) []Candidate {
	out := make([]Candidate, count)
	for i := range out {
		out[i] = Candidate{PeerID: fmt.Sprintf("peer-%02d", i), FreeBytes: int64(1_000_000 + i)}
	}
	return out
}

// THE property. Two shards of one chunk on one node means losing that node
// costs two of the three parity shards, so 6+3 silently becomes 6+1.
func TestPlanNeverPutsTwoShardsOfAChunkOnOneNode(t *testing.T) {
	for _, peerCount := range []int{1, 2, 3, 5, 8, 9, 12} {
		t.Run(fmt.Sprintf("%d-peers", peerCount), func(t *testing.T) {
			assignments := Plan(chunkOf(9, 175_000), peers(peerCount), 1)
			seen := map[string]string{}
			for _, assignment := range assignments {
				if previous, clash := seen[assignment.Peer]; clash {
					t.Fatalf("%s was given shard %s and shard %s of the same chunk",
						assignment.Peer, previous, assignment.ShardID)
				}
				seen[assignment.Peer] = assignment.ShardID
			}
			// Fewer peers than shards must yield FEWER assignments, never
			// doubled-up ones: an unplaced shard is a visible deficit the repair
			// loop retires, a doubled-up shard is a false durability claim.
			want := peerCount
			if want > 9 {
				want = 9
			}
			if len(assignments) != want {
				t.Fatalf("planned %d assignments for %d peers, want %d",
					len(assignments), peerCount, want)
			}
		})
	}
}

// A peer already holding a shard of the chunk must not be handed another one,
// which is the case repair hits: it re-places regenerated shards while the
// surviving holders are still in the ledger.
func TestPlanExcludesPeersAlreadyHoldingASibling(t *testing.T) {
	shards := chunkOf(9, 1000)
	shards[0].Holders = []string{"peer-00"}
	shards[1].Holders = []string{"peer-01"}
	shards[2].Holders = []string{"peer-02"}

	assignments := Plan(shards, peers(9), 1)
	if len(assignments) != 6 {
		t.Fatalf("planned %d assignments, want the 6 shards that have no holder", len(assignments))
	}
	for _, assignment := range assignments {
		switch assignment.Peer {
		case "peer-00", "peer-01", "peer-02":
			t.Fatalf("%s already holds a shard of this chunk", assignment.Peer)
		}
		if assignment.ShardIndex < 3 {
			t.Fatalf("shard %d already had a holder and was planned again", assignment.ShardIndex)
		}
	}
}

// A peer that cannot fit the shard is skipped rather than tried and failed.
// Zero free space means "unknown" (a connected peer with no capacity record),
// which stays usable so a young network with an empty directory still disperses.
func TestPlanSkipsPeersWithoutRoomButKeepsUnknownCapacity(t *testing.T) {
	candidates := []Candidate{
		{PeerID: "full", FreeBytes: 10},
		{PeerID: "unknown", FreeBytes: 0},
		{PeerID: "roomy", FreeBytes: 1 << 30},
	}
	assignments := Plan(chunkOf(3, 1_000_000), candidates, 1)
	if len(assignments) != 2 {
		t.Fatalf("planned %d assignments, want 2", len(assignments))
	}
	for _, assignment := range assignments {
		if assignment.Peer == "full" {
			t.Fatal("planned a shard onto a peer with 10 bytes free")
		}
	}
}

// Emptiest-first, so writes spread toward nodes with room instead of refilling
// whichever peer answered first.
func TestPlanPrefersTheEmptiestPeer(t *testing.T) {
	candidates := []Candidate{
		{PeerID: "small", FreeBytes: 1 << 20},
		{PeerID: "large", FreeBytes: 1 << 40},
	}
	assignments := Plan(chunkOf(1, 1000), candidates, 1)
	if len(assignments) != 1 || assignments[0].Peer != "large" {
		t.Fatalf("planned %#v, want the shard on the peer with the most room", assignments)
	}
}

// Durability is counted in distinct shard INDEXES held remotely, not in holders
// and not in shards. Two copies of index 4 rebuild nothing one copy does not.
func TestRemotelyRecoverableCountsDistinctIndexes(t *testing.T) {
	shards := chunkOf(9, 1000)
	for i := 0; i < 5; i++ {
		shards[i].Holders = []string{fmt.Sprintf("peer-%02d", i)}
	}
	if RemotelyRecoverable(shards, 6) {
		t.Fatal("5 remote indexes of a 6+3 object claimed to be recoverable")
	}
	shards[5].Holders = []string{"peer-05"}
	if !RemotelyRecoverable(shards, 6) {
		t.Fatal("6 remote indexes of a 6+3 object should be recoverable")
	}
	if got := DistinctHolders(shards); got != 6 {
		t.Fatalf("DistinctHolders = %d, want 6", got)
	}
}
