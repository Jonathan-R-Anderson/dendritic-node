package names

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	// Case/trailing-dot insensitive; whitespace is rejected.
	if NodeHash("AI.EPIN.AXON.") != got {
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
	result := "0x" + hex.EncodeToString(key) + strings.Repeat("00", 31) + "01" + strings.Repeat("00", 32)
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

func lookupResponse(owner, count byte) []byte {
	b := make([]byte, 34*32)
	b[31] = owner
	b[len(b)-1] = count
	for i := 0; i < int(count) && i < 32; i++ {
		b[(i+1)*32+31] = byte(i + 1)
	}
	return b
}

func TestModernLookup(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
		want error
		bad  bool
	}{
		{"multiple", lookupResponse(1, 2), nil, false},
		{"unregistered", lookupResponse(0, 0), ErrNotRegistered, false},
		{"empty-owned", lookupResponse(1, 0), ErrNoDestination, false},
		{"ownerless-keys", lookupResponse(0, 1), nil, true},
		{"legacy-tuple", make([]byte, 96), nil, true},
		{"short", []byte{}, nil, true},
		{"oversize", lookupResponse(1, 33), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var in struct {
					Params []json.RawMessage `json:"params"`
				}
				json.NewDecoder(req.Body).Decode(&in)
				var call map[string]string
				json.Unmarshal(in.Params[0], &call)
				if !strings.HasPrefix(call["data"], "0x"+hex.EncodeToString(lookupSelector[:])) {
					t.Error("wrong selector")
				}
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":"0x%s"}`, hex.EncodeToString(tc.buf))
			}))
			defer srv.Close()
			r := NewWithPolicy(srv.URL, "0xdead", []string{"com"}, true, false)
			got, err := r.ResolveAll(context.Background(), "EXAMPLE.COM.")
			if tc.bad {
				if err == nil || errors.Is(err, ErrNotRegistered) {
					t.Fatalf("unsafe error %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %v want %v", err, tc.want)
			}
			if err == nil && len(got) != 2 {
				t.Fatalf("destinations %v", got)
			}
		})
	}
}

func TestRPCFailuresNeverMeanMissing(t *testing.T) {
	for _, body := range []string{`{`, `{"jsonrpc":"2.0","id":1,"result":"0xzz"}`, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unsupported"}}`, `{"jsonrpc":"2.0","id":2,"result":"0x"}`, `{"result":"0x"}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
		r := NewWithPolicy(srv.URL, "0xdead", []string{"com"}, true, false)
		_, err := r.ResolveAll(context.Background(), "example.com")
		if err == nil || errors.Is(err, ErrNotRegistered) {
			t.Errorf("unsafe error %v", err)
		}
		srv.Close()
	}
	r := NewWithPolicy("http://127.0.0.1:1", "0xdead", []string{"com"}, true, false)
	if _, err := r.ResolveAll(context.Background(), "example.com"); err == nil || errors.Is(err, ErrNotRegistered) {
		t.Fatal(err)
	}
}

func TestNamePolicy(t *testing.T) {
	for _, bad := range []string{"key.axon", "a.key.axon", " x.com", "x.com..", "x..com", "-x.com", "x-.com", "é.com", "K.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com"} {
		if _, err := ValidateName(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"EXAMPLE.COM.", "xn--bcher-kva.com", "a.axon"} {
		if _, err := ValidateName(good); err != nil {
			t.Fatal(err)
		}
	}
	r := NewWithPolicy("", "", []string{"com"}, false, false)
	if !r.Matches("a.com") || r.Matches("a.notcom") || r.Matches("com") || !r.Matches("a.axon.") {
		t.Fatal("suffix boundaries")
	}
	key := make([]byte, 32)
	key[0] = 1
	if got, err := r.ResolveAll(context.Background(), identity.FullAddress(key)); err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	r.Legacy = true
	if _, err := r.ResolveAll(context.Background(), "a.com"); err == nil || errors.Is(err, ErrNotRegistered) {
		t.Fatal(err)
	}
}
