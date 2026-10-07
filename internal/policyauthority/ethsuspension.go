package policyauthority

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/servicepolicy"
)

// EthSuspensionSource reads the DAO's suspensions from the on-chain
// ServiceSuspension contract and maps each suspended service key to its
// .key.axon address, so a policy authority can fold on-chain votes into the
// signed document automatically. It reads over plain JSON-RPC eth_call (the same
// way the name resolver reads the TLD registry) — a trusted-RPC read, not a
// proof; run it against an RPC you control.
type EthSuspensionSource struct {
	RPC      string // Ethereum JSON-RPC endpoint
	Contract string // ServiceSuspension contract address (0x...)
	HTTP     *http.Client
}

// maxBlocked caps how many suspended keys we will read, so a malformed or
// hostile RPC answer cannot make us allocate without bound.
const maxBlocked = 100000

var (
	selBlockedKeys = selector("blockedKeys()")
	selRecordOf    = selector("recordOf(bytes32)")
)

func selector(sig string) [4]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(sig))
	var s [4]byte
	copy(s[:], h.Sum(nil))
	return s
}

// Suspended implements SuspensionSource.
func (e *EthSuspensionSource) Suspended(ctx context.Context) (map[string]servicepolicy.Suspension, error) {
	keys, err := e.blockedKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]servicepolicy.Suspension, len(keys))
	for _, k := range keys {
		addr := strings.ToLower(identity.FullAddress(k[:]))
		s := servicepolicy.Suspension{Reason: "DAO-suspended", Category: "dao"}
		// Enrich from recordOf when available; a failure here is non-fatal — the
		// service is suspended either way.
		if state, since, proposal, rerr := e.recordOf(ctx, k); rerr == nil {
			s.ProposalID = proposal
			s.Since = int64(since)
			if state == 2 { // BANNED
				s.Reason = "DAO-banned (permanent)"
			}
		}
		out[addr] = s
	}
	return out, nil
}

// blockedKeys reads ServiceSuspension.blockedKeys() -> bytes32[].
func (e *EthSuspensionSource) blockedKeys(ctx context.Context) ([][32]byte, error) {
	raw, err := e.call(ctx, selBlockedKeys[:])
	if err != nil {
		return nil, err
	}
	return decodeBytes32Array(raw)
}

// recordOf reads ServiceSuspension.recordOf(bytes32) -> (uint8 state, uint64
// since, uint256 proposalId), returning state, since and the low 64 bits of the
// proposal id.
func (e *EthSuspensionSource) recordOf(ctx context.Context, key [32]byte) (state uint8, since uint64, proposal uint64, err error) {
	data := append(append([]byte{}, selRecordOf[:]...), key[:]...)
	raw, cerr := e.call(ctx, data)
	if cerr != nil {
		return 0, 0, 0, cerr
	}
	if len(raw) < 96 {
		return 0, 0, 0, errors.New("policyauthority: short recordOf return")
	}
	state = raw[31]
	since = binary.BigEndian.Uint64(raw[56:64])    // last 8 bytes of word 1
	proposal = binary.BigEndian.Uint64(raw[88:96]) // last 8 bytes of word 2
	return state, since, proposal, nil
}

// call performs an eth_call with the given calldata and returns the raw return
// bytes. Cloned from the name resolver's JSON-RPC read.
func (e *EthSuspensionSource) call(ctx context.Context, data []byte) ([]byte, error) {
	payload := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_call",
		"params": []any{map[string]string{"to": e.Contract, "data": "0x" + hex.EncodeToString(data)}, "latest"}}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.RPC, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := e.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policyauthority: suspension RPC HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
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
	if out.JSONRPC != "2.0" || (len(out.Error) > 0 && string(out.Error) != "null") || !strings.HasPrefix(out.Result, "0x") {
		return nil, errors.New("policyauthority: invalid or reverted suspension RPC response")
	}
	return hex.DecodeString(out.Result[2:])
}

// decodeBytes32Array decodes an ABI-encoded bytes32[]: a 32-byte offset to the
// data, a 32-byte length, then that many 32-byte words.
func decodeBytes32Array(b []byte) ([][32]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if len(b) < 64 {
		return nil, errors.New("policyauthority: short bytes32[] return")
	}
	off := new(big.Int).SetBytes(b[0:32])
	if !off.IsUint64() || off.Uint64()+32 > uint64(len(b)) {
		return nil, errors.New("policyauthority: bad bytes32[] offset")
	}
	o := off.Uint64()
	n := new(big.Int).SetBytes(b[o : o+32])
	if !n.IsUint64() || n.Uint64() > maxBlocked {
		return nil, errors.New("policyauthority: bytes32[] length out of range")
	}
	count := n.Uint64()
	start := o + 32
	if start+count*32 > uint64(len(b)) {
		return nil, errors.New("policyauthority: truncated bytes32[] data")
	}
	out := make([][32]byte, count)
	for i := uint64(0); i < count; i++ {
		copy(out[i][:], b[start+i*32:start+(i+1)*32])
	}
	return out, nil
}
