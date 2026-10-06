package authoritative

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/names"
	"golang.org/x/crypto/sha3"
)

type Registry struct {
	RPC, Contract string
	ChainID       uint64
	HTTP          *http.Client
	MaxNames      int
}
type Snapshot struct {
	BlockHash   string
	BlockNumber uint64
	Registered  bool
	Records     []dns.RR
}

func (r *Registry) rpc(ctx context.Context, method string, params any, out any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, "POST", r.RPC, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := r.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("RPC HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("RPC response too large")
	}
	var reply struct {
		Version string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err = json.Unmarshal(data, &reply); err != nil {
		return err
	}
	if reply.Version != "2.0" || reply.ID != 1 || (len(reply.Error) > 0 && string(reply.Error) != "null") || len(reply.Result) == 0 || string(reply.Result) == "null" {
		return errors.New("invalid/reverted RPC response")
	}
	return json.Unmarshal(reply.Result, out)
}
func selector(signature string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(signature))
	return h.Sum(nil)[:4]
}
func word(v uint64) []byte { b := make([]byte, 32); binary.BigEndian.PutUint64(b[24:], v); return b }
func rawHex(s string, n int) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, errors.New("missing hex prefix")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, err
	}
	if n >= 0 && len(b) != n {
		return nil, errors.New("wrong hex length")
	}
	return b, nil
}
func (r *Registry) call(ctx context.Context, hash, signature string, args ...[]byte) ([]byte, error) {
	data := selector(signature)
	for _, a := range args {
		data = append(data, a...)
	}
	var result string
	err := r.rpc(ctx, "eth_call", []any{map[string]string{"to": r.Contract, "data": "0x" + hex.EncodeToString(data)}, map[string]any{"blockHash": hash, "requireCanonical": true}}, &result)
	if err != nil {
		return nil, err
	}
	return rawHex(result, -1)
}
func integer(b []byte, max uint64) (uint64, error) {
	if len(b) != 32 || !bytes.Equal(b[:24], make([]byte, 24)) {
		return 0, errors.New("malformed ABI integer")
	}
	n := binary.BigEndian.Uint64(b[24:])
	if n > max {
		return 0, errors.New("ABI bound exceeded")
	}
	return n, nil
}

// dynamicArray accepts canonical Solidity ABI only, with disjoint ordered elements.
func dynamicArray(b []byte, max uint64) ([][]byte, error) {
	if len(b) < 64 || len(b)%32 != 0 {
		return nil, errors.New("short ABI array")
	}
	off, err := integer(b[:32], 32)
	if err != nil || off != 32 {
		return nil, errors.New("invalid array offset")
	}
	n, err := integer(b[32:64], max)
	if err != nil {
		return nil, err
	}
	base := b[64:]
	if uint64(len(base)) < n*32 {
		return nil, errors.New("short array head")
	}
	if n == 0 {
		if len(base) != 0 {
			return nil, errors.New("trailing array bytes")
		}
		return nil, nil
	}
	offsets := make([]uint64, n+1)
	offsets[n] = uint64(len(base))
	for i := uint64(0); i < n; i++ {
		offsets[i], err = integer(base[i*32:(i+1)*32], uint64(len(base)))
		if err != nil {
			return nil, err
		}
		if offsets[i]%32 != 0 {
			return nil, errors.New("unaligned offset")
		}
	}
	if offsets[0] != n*32 {
		return nil, errors.New("noncanonical array head")
	}
	out := make([][]byte, n)
	for i := uint64(0); i < n; i++ {
		if offsets[i] >= offsets[i+1] {
			return nil, errors.New("overlapping array")
		}
		out[i] = base[offsets[i]:offsets[i+1]]
	}
	return out, nil
}
func dynamicBytes(b []byte, max uint64) ([]byte, error) {
	if len(b) < 32 {
		return nil, errors.New("short bytes")
	}
	n, err := integer(b[:32], max)
	if err != nil {
		return nil, err
	}
	end := 32 + ((n+31)/32)*32
	if uint64(len(b)) != end || !bytes.Equal(b[32+n:], make([]byte, end-32-n)) {
		return nil, errors.New("invalid bytes padding")
	}
	return b[32 : 32+n], nil
}
func decodeRecords(b []byte) ([]Record, error) {
	items, err := dynamicArray(b, 32)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(items))
	ids := map[uint64]bool{}
	for _, item := range items {
		if len(item) < 160 {
			return nil, errors.New("short entry")
		}
		id, err := integer(item[:32], ^uint64(0))
		if err != nil || id == 0 || ids[id] {
			return nil, errors.New("invalid record ID")
		}
		ids[id] = true
		kind, err := integer(item[32:64], 4)
		if err != nil {
			return nil, err
		}
		ttl, err := integer(item[64:96], 604800)
		if err != nil {
			return nil, err
		}
		off, err := integer(item[96:128], 128)
		if err != nil || off != 128 {
			return nil, errors.New("invalid record offset")
		}
		data, err := dynamicBytes(item[128:], 4098)
		if err != nil {
			return nil, err
		}
		out = append(out, Record{ID: id, Kind: uint8(kind), TTL: uint32(ttl), Data: data})
	}
	return out, nil
}
func decodeNames(b []byte) ([]string, error) {
	items, err := dynamicArray(b, 128)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		data, err := dynamicBytes(item, 253)
		if err != nil {
			return nil, err
		}
		n, err := OwnerName(string(data))
		if err != nil || strings.TrimSuffix(n, ".") != string(data) {
			return nil, errors.New("noncanonical child name")
		}
		out = append(out, string(data))
	}
	return out, nil
}

// Snapshot pins every read to one finalized block hash (EIP-1898). Unsupported RPCs fail closed.
func (r *Registry) Snapshot(ctx context.Context, origin string) (Snapshot, error) {
	var out Snapshot
	n, err := OwnerName(origin)
	if err != nil {
		return out, err
	}
	origin = strings.TrimSuffix(n, ".")
	if strings.Contains(origin, "*") || strings.Contains(origin, "_") {
		return out, errors.New("zone apex must be a hostname")
	}
	if _, err = rawHex(r.Contract, 20); err != nil {
		return out, err
	}
	if r.ChainID == 0 {
		return out, errors.New("expected chain ID required")
	}
	var chain string
	if err = r.rpc(ctx, "eth_chainId", []any{}, &chain); err != nil {
		return out, err
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(chain, "0x"), 16, 64)
	if err != nil || id != r.ChainID {
		return out, errors.New("RPC chain ID mismatch")
	}
	var block struct {
		Hash   string `json:"hash"`
		Number string `json:"number"`
	}
	if err = r.rpc(ctx, "eth_getBlockByNumber", []any{"finalized", false}, &block); err != nil {
		return out, err
	}
	if _, err = rawHex(block.Hash, 32); err != nil {
		return out, err
	}
	out.BlockHash = block.Hash
	out.BlockNumber, err = strconv.ParseUint(strings.TrimPrefix(block.Number, "0x"), 16, 64)
	if err != nil {
		return out, err
	}
	version, err := r.call(ctx, block.Hash, "protocolVersion()")
	if err != nil {
		return out, err
	}
	v, err := integer(version, 3)
	if err != nil || v != 3 {
		return out, errors.New("registry requires authoritative protocol version 3")
	}
	max := r.MaxNames
	if max == 0 {
		max = 10000
	}
	queue := []string{origin}
	seen := map[string]bool{origin: true}
	enumerated := 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		node := names.NodeHash(current)
		tuple, err := r.call(ctx, block.Hash, "resolve(bytes32)", node[:])
		if err != nil {
			return out, err
		}
		if len(tuple) != 96 || !bytes.Equal(tuple[32:44], make([]byte, 12)) || !bytes.Equal(tuple[64:88], make([]byte, 24)) {
			return out, errors.New("malformed ownership tuple")
		}
		if bytes.Equal(tuple[32:64], make([]byte, 32)) {
			if !bytes.Equal(tuple, make([]byte, 96)) {
				return out, errors.New("unowned record data")
			}
			continue
		}
		if current == origin {
			out.Registered = true
		}
		payload, err := r.call(ctx, block.Hash, "recordsPage(bytes32,uint256,uint256)", node[:], word(0), word(32))
		if err != nil {
			return out, err
		}
		records, err := decodeRecords(payload)
		if err != nil {
			return out, err
		}
		for _, record := range records {
			rr, err := DecodeRR(current, record)
			if err != nil {
				return out, fmt.Errorf("%s: %w", current, err)
			}
			if rr == nil {
				continue
			}
			out.Records = append(out.Records, rr)
		}
		// Include children below cuts for glue; BIND enforces referral/zone-cut semantics.
		for offset := uint64(0); ; offset += 128 {
			payload, err = r.call(ctx, block.Hash, "childrenPage(bytes32,uint256,uint256)", node[:], word(offset), word(128))
			if err != nil {
				return out, err
			}
			children, err := decodeNames(payload)
			if err != nil {
				return out, err
			}
			enumerated += len(children)
			if enumerated > max {
				return out, errors.New("zone enumeration bound exceeded")
			}
			for _, child := range children {
				dot := strings.IndexByte(child, '.')
				if dot < 0 || child[dot+1:] != current || seen[child] {
					return out, errors.New("invalid child namespace")
				}
				seen[child] = true
				queue = append(queue, child)
			}
			if len(children) < 128 {
				break
			}
		}
	}
	return out, nil
}
