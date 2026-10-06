// Package names resolves human `.axon` names to Layer-1 self-certifying addresses
// using an on-chain registry (contracts/tld/AxonTLD.sol).
//
// The dendritic network's addresses are self-certifying: `<56-base32>.key.axon`
// IS a public key, so no lookup is needed to reach one. Names are the convenience
// layer on top: a name like `ai.epin.axon` is owned on Ethereum and bound there to
// a 32-byte Ed25519 Layer-1 identity. This package turns a name into the canonical
// `<56-base32>.key.axon` the overlay dials, with a single `eth_call` to the registry:
//
//	name --keccak256--> node --resolve(node)--> key(32B) --FullAddress--> <56>.key.axon
//
// It is deliberately small and dependency-free (hand-rolled eth_call + ABI, like the
// rest of this repo's Ethereum code). A production deployment reads the same state
// trustlessly through internal/ethproof (eth_getProof against a verified header)
// instead of trusting the RPC; the wire shape of the call is identical.
package names

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/params"
)

// ErrNotRegistered is returned when a name has no key set in the registry.
var ErrNotRegistered = errors.New("axon/names: name is not registered")

// Resolver reads name→key bindings from an AxonTLD registry over JSON-RPC.
type Resolver struct {
	RPC      string // Ethereum JSON-RPC endpoint (e.g. http://127.0.0.1:8545)
	Contract string // AxonTLD contract address (0x...)
	HTTP     *http.Client
}

// New builds a resolver. rpc and contract must both be set for it to do anything.
func New(rpc, contract string) *Resolver {
	return &Resolver{RPC: rpc, Contract: contract, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// Enabled reports whether the resolver is configured to do lookups.
func (r *Resolver) Enabled() bool { return r != nil && r.RPC != "" && r.Contract != "" }

// NodeHash is keccak256(lowercased full name) -- the registry's record key. The
// contract keys records the same way (AxonTLD.nodeOf), so both sides agree.
func NodeHash(name string) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(normalize(name)))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// normalize lowercases and trims a trailing dot; it does not otherwise rewrite.
func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// resolveSelector is keccak256("resolve(bytes32)")[:4].
var resolveSelector = func() [4]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("resolve(bytes32)"))
	var s [4]byte
	copy(s[:], h.Sum(nil)[:4])
	return s
}()

// Resolve turns a name into the canonical <56-base32>.key.axon service address.
//
// A name that is ALREADY a self-certifying address (bare 56 chars, or the full
// <56>.key.axon form) is returned as-is with no chain read -- Layer 1 never needs
// the registry. Any other name under the `.axon` root is looked up on-chain.
func (r *Resolver) Resolve(ctx context.Context, name string) (string, error) {
	n := normalize(name)
	// Already self-certifying? Then there is nothing to resolve.
	if _, err := identity.ParseAddress(n); err == nil {
		return identity.FullAddress(mustPub(n)), nil
	}
	root := "." + params.RootSuffix
	if !strings.HasSuffix(n, root) && n != params.RootSuffix {
		return "", fmt.Errorf("axon/names: %q is not under .%s", name, params.RootSuffix)
	}
	if !r.Enabled() {
		return "", errors.New("axon/names: no registry configured (set axon.name_rpc and axon.name_contract)")
	}
	node := NodeHash(n)
	key, err := r.callResolve(ctx, node)
	if err != nil {
		return "", err
	}
	var zero [32]byte
	if key == zero {
		return "", fmt.Errorf("%w: %s", ErrNotRegistered, n)
	}
	return identity.FullAddress(ed25519.PublicKey(key[:])), nil
}

// callResolve does the eth_call to AxonTLD.resolve(node) and returns the 32-byte key.
func (r *Resolver) callResolve(ctx context.Context, node [32]byte) ([32]byte, error) {
	var key [32]byte
	data := make([]byte, 0, 4+32)
	data = append(data, resolveSelector[:]...)
	data = append(data, node[:]...)
	payload := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_call",
		"params": []any{
			map[string]string{"to": r.Contract, "data": "0x" + hex.EncodeToString(data)},
			"latest",
		},
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.RPC, bytes.NewReader(body))
	if err != nil {
		return key, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return key, fmt.Errorf("axon/names: registry RPC: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return key, fmt.Errorf("axon/names: bad RPC response: %w", err)
	}
	if out.Error != nil {
		return key, fmt.Errorf("axon/names: registry call reverted: %s", out.Error.Message)
	}
	hexstr := strings.TrimPrefix(strings.TrimSpace(out.Result), "0x")
	buf, err := hex.DecodeString(hexstr)
	if err != nil {
		return key, fmt.Errorf("axon/names: bad result hex: %w", err)
	}
	// Return tuple is (bytes32 key, address owner, uint64 updatedAt); the first word is the key.
	if len(buf) < 32 {
		return key, fmt.Errorf("axon/names: short result (%d bytes)", len(buf))
	}
	copy(key[:], buf[:32])
	return key, nil
}

func mustPub(selfCert string) ed25519.PublicKey {
	pub, _ := identity.ParseAddress(selfCert)
	return pub
}
