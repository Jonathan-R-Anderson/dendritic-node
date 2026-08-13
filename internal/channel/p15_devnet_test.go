package channel

// P15 phase 3A — the real devnet join.
//
// The blocker this closes: every existing end-to-end test drives the production
// tip against NewFakeChain(). Real contracts were deployed in hardhat, real
// payments were exchanged in Go, and the two had never met.
//
// Here the recipient's node learns about its channel from the ACTUAL EVM at
// 127.0.0.1:8545, through the production RPCChainReader, and the tip is the
// production browser client. There is no FakeChain in this file, and it FAILS
// rather than falls back if the devnet is unreachable — a silent downgrade to
// FakeChain is exactly how this would come to claim more than it proved.
//
//	P15_DEVNET=1 P15_RPC=http://127.0.0.1:8545 \
//	P15_MANAGER=0x… P15_CHANNEL=0x… P15_CONTRIBUTOR=0x… P15_RECIPIENT_KEY=… \
//	  go test ./internal/channel/ -run TestP15Devnet -v

import (
	"context"
	"math/big"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func p15Env(t *testing.T, name string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		t.Skipf("set %s (see the phase 3A harness)", name)
	}
	return v
}

// TestP15DevnetLifecycle: real chain -> real node -> real tip -> Pool.View().
func TestP15DevnetLifecycle(t *testing.T) {
	if os.Getenv("P15_DEVNET") == "" {
		t.Skip("set P15_DEVNET=1 — this needs a hardhat node on 127.0.0.1:8545")
	}
	rpc := p15Env(t, "P15_RPC")
	manager := mustAddr(t, p15Env(t, "P15_MANAGER"))
	contributor := mustAddr(t, p15Env(t, "P15_CONTRIBUTOR"))
	recipientKeyHex := p15Env(t, "P15_RECIPIENT_KEY")
	tipperKey := p15Env(t, "P15_CONTRIBUTOR_KEY")

	var channelID [32]byte
	raw := strings.TrimPrefix(p15Env(t, "P15_CHANNEL"), "0x")
	for i := 0; i < 32 && i*2+1 < len(raw); i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := raw[i*2+j]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = c - 'A' + 10
			}
			b = b<<4 | v
		}
		channelID[i] = b
	}

	// ---- 1. THE GO SIDE READS THE REAL CHAIN --------------------------------
	//
	// Production RPCChainReader against the devnet. If this cannot reach the
	// EVM the test fails; it does not substitute anything.
	reader := NewRPCChainReader(rpc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	occ, err := reader.ReadChannel(ctx, manager, channelID)
	if err != nil {
		t.Fatalf("RPCChainReader could not read the devnet channel: %v", err)
	}
	if occ.Status != StatusOpen {
		t.Fatalf("the devnet channel is status %d, want open", occ.Status)
	}
	total := new(big.Int).Add(occ.DepositA, occ.DepositB)
	if total.Sign() == 0 {
		t.Fatal("the devnet channel holds no collateral; the deposit did not land")
	}
	t.Logf("READ FROM THE DEVNET: partyA=%s partyB=%s depositA=%s depositB=%s status=%d",
		occ.PartyA.Hex(), occ.PartyB.Hex(), occ.DepositA, occ.DepositB, occ.Status)

	// ---- 2. THE RECIPIENT NODE ADOPTS IT ------------------------------------
	recipientSigner := signerFromHex(t, recipientKeyHex)
	if recipientSigner.address() != occ.PartyA && recipientSigner.address() != occ.PartyB {
		t.Fatalf("the recipient key %s is not a party to the devnet channel",
			recipientSigner.address().Hex())
	}
	chainID := big.NewInt(31337)
	if v := os.Getenv("P15_CHAIN_ID"); v != "" {
		if n, ok := new(big.Int).SetString(v, 10); ok {
			chainID = n
		}
	}

	node := newWiredNode(t, recipientSigner, reader, manager)
	if err := node.store.TrackFromChain(chainID, manager, occ); err != nil {
		t.Fatalf("adopting the devnet channel: %v", err)
	}

	// ---- 3. THE POOL, BEFORE ------------------------------------------------
	pool := Pool{
		Name: "tips", Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID},
		Policy:  PoolPolicy{Enabled: true},
	}
	before, err := pool.View(node.store)
	if err != nil {
		t.Fatalf("pool view before: %v", err)
	}
	t.Logf("POOL VIEW BEFORE: withdrawable=%s members=%d",
		before.Withdrawable, before.Members)

	// ---- 4. THE REAL TIP, THROUGH THE PRODUCTION BROWSER CLIENT -------------
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	root, _ := filepath.Abs(filepath.Join("..", "..", "..", "proof-of-facilitation"))
	script := filepath.Join(root, "browser-test", "pay-node.mjs")

	wp := &WebPeer{Handler: node.coord, Timeout: 20 * time.Second}
	srv := httptest.NewServer(wp.HTTPHandler())
	defer srv.Close()

	amount := anon(25)
	cmd := exec.Command(nodeBin, script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SCPP_URL="+srv.URL+"/scpp/v1",
		"TIP_KEY="+tipperKey,
		"RECIPIENT="+recipientSigner.address().Hex(),
		"MANAGER="+manager.Hex(),
		"CHAIN_ID="+chainID.String(),
		"PARTY_A="+occ.PartyA.Hex(),
		"PARTY_B="+occ.PartyB.Hex(),
		"DEPOSIT_A="+occ.DepositA.String(),
		"DEPOSIT_B="+occ.DepositB.String(),
		"AMOUNT="+amount.String(),
	)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("the production browser client failed: %v\n%s", err, stderr)
	}
	t.Logf("TIP DRIVER: %s", strings.TrimSpace(string(out)))
	if !strings.Contains(string(out), "completed") {
		t.Fatalf("the tip did not complete: %s", out)
	}
	_ = contributor

	// ---- 5. THE POOL, AFTER -------------------------------------------------
	after, err := pool.View(node.store)
	if err != nil {
		t.Fatalf("pool view after: %v", err)
	}
	t.Logf("POOL VIEW AFTER: withdrawable=%s members=%d",
		after.Withdrawable, after.Members)

	gain := new(big.Int).Sub(after.Withdrawable, before.Withdrawable)
	if gain.Cmp(amount) != 0 {
		t.Fatalf("the pool grew by %s, want exactly the tip of %s", gain, amount)
	}

	// ---- 6. RECONSTRUCTION --------------------------------------------------
	// A fresh Pool over the same store. Nothing pool-shaped is persisted, so
	// this is the whole of "recovered after restart".
	rebuilt := Pool{
		Name: "tips", Recipient: recipientSigner.address(),
		Members: [][32]byte{channelID},
		Policy:  PoolPolicy{Enabled: true},
	}
	again, err := rebuilt.View(node.store)
	if err != nil {
		t.Fatalf("pool view after reconstruction: %v", err)
	}
	if again.Withdrawable.Cmp(after.Withdrawable) != 0 {
		t.Fatalf("reconstructed view %s differs from %s",
			again.Withdrawable, after.Withdrawable)
	}
	t.Logf("RECONSTRUCTED: withdrawable=%s (identical)", again.Withdrawable)
}

// signerFromHex builds the recipient wallet from a devnet key supplied at run
// time. Nothing is hardcoded and nothing is logged: the key arrives in the
// environment, is used to sign states, and never leaves this process.
func signerFromHex(t *testing.T, hexKey string) *signer {
	t.Helper()
	raw := strings.TrimPrefix(strings.TrimSpace(hexKey), "0x")
	b := make([]byte, len(raw)/2)
	for i := range b {
		var v byte
		for j := 0; j < 2; j++ {
			c := raw[i*2+j]
			var d byte
			switch {
			case c >= '0' && c <= '9':
				d = c - '0'
			case c >= 'a' && c <= 'f':
				d = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				d = c - 'A' + 10
			default:
				t.Fatalf("the supplied key is not hex")
			}
			v = v<<4 | d
		}
		b[i] = v
	}
	if len(b) != 32 {
		t.Fatalf("the supplied key is %d bytes, want 32", len(b))
	}
	return &signer{priv: secp256k1.PrivKeyFromBytes(b)}
}
