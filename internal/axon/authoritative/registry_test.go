package authoritative

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/names"
)

func abiBytes(data []byte) []byte {
	b := word(uint64(len(data)))
	b = append(b, data...)
	for len(b)%32 != 0 {
		b = append(b, 0)
	}
	return b
}
func abiArray(items ...[]byte) []byte {
	b := append(word(32), word(uint64(len(items)))...)
	offset := len(items) * 32
	for _, item := range items {
		b = append(b, word(uint64(offset))...)
		offset += len(item)
	}
	for _, item := range items {
		b = append(b, item...)
	}
	return b
}
func abiEntry(r Record) []byte {
	b := append(word(1), word(uint64(r.Kind))...)
	b = append(b, word(uint64(r.TTL))...)
	b = append(b, word(128)...)
	return append(b, abiBytes(r.Data)...)
}
func TestFinalizedSnapshotEnumeration(t *testing.T) {
	hash := "0x" + strings.Repeat("12", 32)
	root := names.NodeHash("example.com")
	child := names.NodeHash("api.example.com")
	_, record, err := EncodeRR("api.example.com. 30 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		json.NewDecoder(req.Body).Decode(&in)
		var result any
		switch in.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_getBlockByNumber":
			if string(in.Params[0]) != `"finalized"` {
				t.Error("not finalized")
			}
			result = map[string]string{"hash": hash, "number": "0x10"}
		case "eth_call":
			calls++
			var call map[string]string
			json.Unmarshal(in.Params[0], &call)
			var pin struct {
				Hash      string `json:"blockHash"`
				Canonical bool   `json:"requireCanonical"`
			}
			json.Unmarshal(in.Params[1], &pin)
			if pin.Hash != hash || !pin.Canonical {
				t.Error("unpinned read")
			}
			data, _ := hex.DecodeString(strings.TrimPrefix(call["data"], "0x"))
			signature := hex.EncodeToString(data[:4])
			var out []byte
			switch signature {
			case hex.EncodeToString(selector("protocolVersion()")):
				out = word(3)
			case hex.EncodeToString(selector("resolve(bytes32)")):
				out = append(make([]byte, 32), word(1)...)
				out = append(out, word(1)...)
			case hex.EncodeToString(selector("recordsPage(bytes32,uint256,uint256)")):
				out = abiArray()
				if hex.EncodeToString(data[4:36]) == hex.EncodeToString(child[:]) {
					out = abiArray(abiEntry(record))
				}
			case hex.EncodeToString(selector("childrenPage(bytes32,uint256,uint256)")):
				out = abiArray()
				if hex.EncodeToString(data[4:36]) == hex.EncodeToString(root[:]) {
					out = abiArray(abiBytes([]byte("api.example.com")))
				}
			default:
				t.Error("unexpected selector", signature)
			}
			result = "0x" + hex.EncodeToString(out)
		default:
			t.Error("unexpected method", in.Method)
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	defer srv.Close()
	r := Registry{RPC: srv.URL, Contract: "0x" + strings.Repeat("01", 20), ChainID: 1}
	snapshot, err := r.Snapshot(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Registered || len(snapshot.Records) != 1 || snapshot.BlockHash != hash || calls != 7 {
		t.Fatalf("snapshot %+v calls %d", snapshot, calls)
	}
	r.ChainID = 2
	if _, err = r.Snapshot(context.Background(), "example.com"); err == nil {
		t.Fatal("wrong chain accepted")
	}
}
func TestMalformedABI(t *testing.T) {
	bad := [][]byte{nil, make([]byte, 64), append(abiArray(), word(0)...), abiArray([]byte{1})}
	for i, b := range bad {
		if _, err := decodeRecords(b); err == nil {
			t.Fatal(i)
		}
	}
	if _, err := decodeNames(abiArray(abiBytes([]byte("evil.com..")))); err == nil {
		t.Fatal("invalid name accepted")
	}
}
func TestRPCFailure(t *testing.T) {
	for _, body := range []string{`{`, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000}}`, `{"jsonrpc":"2.0","id":1,"result":null}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
		r := Registry{RPC: srv.URL}
		var out any
		if err := r.rpc(context.Background(), "x", nil, &out); err == nil {
			t.Fatal(body)
		}
		srv.Close()
	}
}
