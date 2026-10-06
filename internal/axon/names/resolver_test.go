package names

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
)

// NodeHash must match the contract's keccak256(bytes(name)) keying. This expected
// value is what `cast call AxonTLD "nodeOf(string)" "ai.epin.axon"` returns.
func TestNodeHashMatchesContract(t *testing.T) {
	got := NodeHash("ai.epin.axon")
	want := "cc8efeb2dbc9ba52f80357c73a6aad0817d87c5a0f4de2740a623faa82b26174"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("NodeHash=%s want %s", hex.EncodeToString(got[:]), want)
	}
	// Case/space/trailing-dot insensitive.
	if NodeHash("  AI.EPIN.AXON.  ") != got {
		t.Fatal("NodeHash not normalized")
	}
}

// A name that is already self-certifying resolves to itself with no chain read.
func TestResolveSelfCertNeedsNoChain(t *testing.T) {
	r := New("", "") // not enabled, must still handle self-cert
	// Build a valid self-certifying address from a known 32-byte key.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	full := identity.FullAddress(key)
	got, err := r.Resolve(context.Background(), full)
	if err != nil {
		t.Fatalf("self-cert resolve: %v", err)
	}
	if got != full {
		t.Fatalf("self-cert resolve changed the address: %s != %s", got, full)
	}
}

// A name under .axon is looked up on-chain; a non-zero key becomes <56>.key.axon.
func TestResolveViaStubRegistry(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(200 - i)
	}
	// eth_call returns the ABI tuple (bytes32 key, address, uint64) = 3 words.
	result := "0x" + hex.EncodeToString(key) + strings.Repeat("00", 32) + strings.Repeat("00", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"` + result + `"}`))
	}))
	defer srv.Close()

	r := New(srv.URL, "0x000000000000000000000000000000000000dEaD")
	got, err := r.Resolve(context.Background(), "ai.epin.axon")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != identity.FullAddress(key) {
		t.Fatalf("resolve=%s want %s", got, identity.FullAddress(key))
	}
	if _, perr := identity.ParseAddress(got); perr != nil {
		t.Fatalf("resolved address does not parse: %v", perr)
	}
}

// A zero key means the name is not registered.
func TestResolveUnregistered(t *testing.T) {
	zero := "0x" + strings.Repeat("00", 96)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"` + zero + `"}`))
	}))
	defer srv.Close()
	r := New(srv.URL, "0x000000000000000000000000000000000000dEaD")
	if _, err := r.Resolve(context.Background(), "ghost.epin.axon"); err == nil {
		t.Fatal("want ErrNotRegistered, got nil")
	}
}

// A name outside the .axon root is refused before any chain read.
func TestResolveRejectsNonAxon(t *testing.T) {
	r := New("http://127.0.0.1:1", "0xdead")
	if _, err := r.Resolve(context.Background(), "example.com"); err == nil {
		t.Fatal("want error for non-.axon name")
	}
}
