// Package names reads registry state from a trusted RPC. It does not verify state proofs.
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
)

// ErrNotRegistered means the registry explicitly returned no owner and no records.
var ErrNotRegistered = errors.New("axon/names: name is not registered")
var ErrNoDestination = errors.New("axon/names: registered name has no AXON destination")

// Resolver reads name→key bindings from an AxonTLD registry over JSON-RPC.
type Resolver struct {
	RPC             string // Ethereum JSON-RPC endpoint (e.g. http://127.0.0.1:8545)
	Contract        string // AxonTLD contract address (0x...)
	Suffixes        []string
	MissingFallback bool
	Legacy          bool // Explicit compatibility mode: .axon only, single destination.
	HTTP            *http.Client
}

// New builds a resolver. rpc and contract must both be set for it to do anything.
func New(rpc, contract string) *Resolver {
	return &Resolver{RPC: rpc, Contract: contract, HTTP: &http.Client{Timeout: 15 * time.Second}}
}

// Enabled reports whether the resolver is configured to do lookups.
func (r *Resolver) Enabled() bool { return r != nil && r.RPC != "" && r.Contract != "" }

// NodeHash is keccak256(lowercased full name) -- the registry's record key. The
// contract keys valid names the same way. ValidateName must precede untrusted hashing.
func NodeHash(name string) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(normalize(name)))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// normalize lowercases and trims a trailing dot; it does not otherwise rewrite.
func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
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
	if _, err := ValidateName(name); err != nil {
		return "", err
	}
	if !r.Matches(n) {
		return "", fmt.Errorf("axon/names: unsupported suffix")
	}
	if !r.Enabled() {
		return "", errors.New("axon/names: no registry configured (set axon.name_rpc and axon.name_contract)")
	}
	node := NodeHash(n)
	buf, err := r.call(ctx, resolveSelector, node)
	if err != nil {
		return "", err
	}
	if len(buf) != 96 || !zero(buf[32:44]) || !zero(buf[64:88]) {
		return "", errors.New("invalid legacy tuple")
	}
	if zero(buf[32:64]) {
		if !zero(buf[:32]) {
			return "", errors.New("key without owner")
		}
		return "", ErrNotRegistered
	}
	if zero(buf[:32]) {
		return "", ErrNoDestination
	}
	return identity.FullAddress(ed25519.PublicKey(buf[:32])), nil
}

func (r *Resolver) call(ctx context.Context, selector [4]byte, node [32]byte) ([]byte, error) {
	data := append(selector[:], node[:]...)
	payload := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": []any{map[string]string{"to": r.Contract, "data": "0x" + hex.EncodeToString(data)}, "latest"}}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.RPC, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := r.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry HTTP status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  string          `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.JSONRPC != "2.0" || out.ID != 1 || (len(out.Error) > 0 && string(out.Error) != "null") || !strings.HasPrefix(out.Result, "0x") {
		return nil, errors.New("invalid or reverted registry RPC response")
	}
	return hex.DecodeString(out.Result[2:])
}

func zero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ValidateName mirrors AxonTLD.nodeOf. No implicit whitespace trimming or IDNA conversion.
func ValidateName(name string) (string, error) {
	for _, c := range []byte(name) {
		if c > 127 {
			return "", errors.New("ASCII LDH required")
		}
	}
	n := normalize(name)
	if len(n) == 0 || len(n) > 253 {
		return "", errors.New("invalid name length")
	}
	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return "", errors.New("domain needs TLD")
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("invalid label")
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("ASCII LDH required")
			}
		}
	}
	if n == "key.axon" || strings.HasSuffix(n, ".key.axon") {
		return "", errors.New("reserved namespace")
	}
	return n, nil
}

func ValidateSuffix(s string) error {
	if s != strings.ToLower(s) || strings.Contains(s, ".") {
		return errors.New("suffix must be a lowercase single label without dots")
	}
	_, err := ValidateName("test." + s)
	return err
}
func (r *Resolver) Matches(host string) bool {
	// Classify even malformed final dots as aliases so validation fails closed.
	n := strings.TrimRight(strings.ToLower(host), ".")
	if strings.HasSuffix(n, ".axon") || n == "axon" {
		return true
	}
	if r != nil {
		for _, suffix := range r.Suffixes {
			if strings.HasSuffix(n, "."+suffix) {
				return true
			}
		}
	}
	return false
}
func NewWithPolicy(rpc, contract string, suffixes []string, fallback, legacy bool) *Resolver {
	r := New(rpc, contract)
	r.Suffixes = suffixes
	r.MissingFallback = fallback
	r.Legacy = legacy
	return r
}

var lookupSelector = func() [4]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("lookupAxon(bytes32)"))
	var s [4]byte
	copy(s[:], h.Sum(nil))
	return s
}()

// ResolveAll requires the new lookup ABI unless legacy mode was explicitly selected.
func (r *Resolver) ResolveAll(ctx context.Context, name string) ([]string, error) {
	n := normalize(name)
	if pub, err := identity.ParseAddress(n); err == nil {
		return []string{identity.FullAddress(pub)}, nil
	}
	if _, err := ValidateName(name); err != nil {
		return nil, err
	}
	if !r.Matches(n) || !r.Enabled() {
		return nil, errors.New("registry unavailable or suffix unsupported")
	}
	if r.Legacy {
		if !strings.HasSuffix(n, ".axon") {
			return nil, errors.New("legacy contract cannot resolve additional suffixes")
		}
		dest, err := r.Resolve(ctx, n)
		if err != nil {
			return nil, err
		}
		return []string{dest}, nil
	}
	buf, err := r.call(ctx, lookupSelector, NodeHash(n))
	if err != nil {
		return nil, err
	}
	if len(buf) != 34*32 || !zero(buf[:12]) || !zero(buf[33*32:34*32-1]) || buf[len(buf)-1] > 32 {
		return nil, errors.New("invalid lookup tuple or unsupported registry")
	}
	count := int(buf[len(buf)-1])
	destinations := make([]string, 0, count)
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		key := buf[(i+1)*32 : (i+2)*32]
		if i >= count {
			if !zero(key) {
				return nil, errors.New("nonzero unused key")
			}
			continue
		}
		if zero(key) || seen[string(key)] {
			return nil, errors.New("invalid AXON key list")
		}
		seen[string(key)] = true
		destinations = append(destinations, identity.FullAddress(ed25519.PublicKey(key)))
	}
	if zero(buf[:32]) {
		if count != 0 {
			return nil, errors.New("keys without owner")
		}
		return nil, ErrNotRegistered
	}
	if count == 0 {
		return nil, ErrNoDestination
	}
	return destinations, nil
}

func mustPub(selfCert string) ed25519.PublicKey {
	pub, _ := identity.ParseAddress(selfCert)
	return pub
}
