package policyauthority

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
)

func word(n uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], n)
	return b
}

func abiBytes32Array(keys [][32]byte) string {
	var b []byte
	b = append(b, word(32)...)                // offset to the data
	b = append(b, word(uint64(len(keys)))...) // length
	for _, k := range keys {
		b = append(b, k[:]...)
	}
	return "0x" + hex.EncodeToString(b)
}

func abiRecord(state, since, proposal uint64) string {
	var b []byte
	b = append(b, word(state)...)
	b = append(b, word(since)...)
	b = append(b, word(proposal)...)
	return "0x" + hex.EncodeToString(b)
}

func TestEthSuspensionSourceReadsAndMaps(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = 0x11 + byte(i)
	}
	wantAddr := strings.ToLower(identity.FullAddress(key[:]))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var callobj struct {
			Data string `json:"data"`
		}
		_ = json.Unmarshal(req.Params[0], &callobj)
		data := strings.TrimPrefix(callobj.Data, "0x")

		var result string
		switch len(data) {
		case 8: // blockedKeys() — selector only
			result = abiBytes32Array([][32]byte{key})
		default: // recordOf(bytes32) — selector + 32-byte key
			result = abiRecord(1, 123, 7) // SUSPENDED, since=123, proposalId=7
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	defer srv.Close()

	e := &EthSuspensionSource{RPC: srv.URL, Contract: "0xServiceSuspension"}
	m, err := e.Suspended(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s, ok := m[wantAddr]
	if !ok {
		t.Fatalf("suspended service %s not mapped; got %v", wantAddr, m)
	}
	if s.ProposalID != 7 || s.Since != 123 {
		t.Fatalf("record not decoded: proposal=%d since=%d", s.ProposalID, s.Since)
	}
	if s.Reason == "" {
		t.Fatal("suspension has no reason")
	}
}

func TestEmptyBlockedSetIsNoSuspensions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1,
			"result": abiBytes32Array(nil)}) // offset + length 0
	}))
	defer srv.Close()
	e := &EthSuspensionSource{RPC: srv.URL, Contract: "0x0"}
	m, err := e.Suspended(context.Background())
	if err != nil || len(m) != 0 {
		t.Fatalf("empty set should yield no suspensions: m=%v err=%v", m, err)
	}
}

func TestDecodeBytes32ArrayGuards(t *testing.T) {
	if got, err := decodeBytes32Array(nil); err != nil || got != nil {
		t.Fatalf("empty input should decode to nil: %v %v", got, err)
	}
	if _, err := decodeBytes32Array(make([]byte, 40)); err == nil {
		t.Fatal("a too-short array should be rejected")
	}
	// Valid: offset 32, length 1, one word.
	var b []byte
	b = append(b, word(32)...)
	b = append(b, word(1)...)
	b = append(b, word(0xBEEF)...)
	got, err := decodeBytes32Array(b)
	if err != nil || len(got) != 1 {
		t.Fatalf("valid single-element array failed: %v %v", got, err)
	}
}
