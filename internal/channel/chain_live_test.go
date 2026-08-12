package channel

import (
	"context"
	"os"
	"testing"
)

// Not part of the suite: needs the network. Run with CHAIN_PROBE=1.
func TestLiveChainReadAgainstTheDeployedContract(t *testing.T) {
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
	contract, err := ParseAddress("0xae70526931FF460894133201f6C8cA91bbA0E177")
	if err != nil {
		t.Fatal(err)
	}
	r := NewRPCChainReader(os.Getenv("ETH_RPC_URL"))
	// A channel that certainly does not exist: the getter answers all zeros,
	// which must decode as "not on chain" rather than as a zero-deposit channel.
	_, err = r.ReadChannel(context.Background(), contract, [32]byte{0xde, 0xad, 0xbe, 0xef})
	if err != ErrChannelNotOnChain {
		t.Fatalf("got %v, want ErrChannelNotOnChain", err)
	}
	t.Log("live eth_call reached the contract and decoded an empty channel correctly")
}
