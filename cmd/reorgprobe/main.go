package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

func main() {
	// Long-running: elapsed observation IS the evidence here. Writes progress
	// continuously so a partial run is still usable.
	ctx := context.Background()
	endpoint := os.Getenv("ETH_RPC_URL")
	started := time.Now()

	obs, err := ethproof.ObserveReorgs(ctx, endpoint, 4*time.Second, 1_000_000)
	fmt.Printf("[%s] blocks=%d reorgs=%d maxdepth=%d interval=%s err=%v\n",
		time.Now().UTC().Format(time.RFC3339), obs.Blocks, obs.Reorgs,
		obs.MaxDepth, obs.BlockInterval, err)
	_, evErr := obs.AsEvidence(1, started.Unix())
	fmt.Printf("as evidence: %v\n", evErr)
}
