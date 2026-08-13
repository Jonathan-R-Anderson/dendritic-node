package ethproof

// P14.5 — measurements for the proposed authenticated-receipts watchtower (C+E).
//
// MEASUREMENT ONLY. Nothing here is production code and nothing in the package
// is changed. It lives in a _test.go file deliberately: the design has NOT been
// approved for implementation, and a measurement harness that compiles into the
// binary is an implementation whatever the commit message says.
//
//	P145=1 CHAIN_PROBE=1 ETH_RPC_URL=... BEACON_API_URL=... MAINNET_CHECKPOINT=0x... \
//	  go test ./internal/ethproof/ -run TestP145 -v -timeout 30m
//
// WHAT THE HARNESS HAD TO SUPPLY, AND WHY THAT IS ITSELF A FINDING
// ----------------------------------------------------------------
// P12 has an RLP DECODER and an MPT proof VERIFIER. Neither is usable here.
// Verifying a proof walks one path a provider chose; rebuilding a receipts trie
// requires CONSTRUCTING every node from every receipt and encoding them exactly.
// So this file carries an RLP encoder, a trie builder and an EIP-2718 receipt
// encoder that do not exist in the codebase. Implementing C means writing all
// three for real — a cost the design document could not see before this ran.
//
// THE SHAPE OF THE TEST IS THE POINT
// ----------------------------------
// The tempting version compares our rebuilt root against the receiptsRoot the
// same RPC handed us in eth_getBlockByNumber. That is a closed loop: a decoder
// with a consistent bug agrees with itself, and the provider supplied both
// halves. So the reference root here comes from the BEACON chain — proven into a
// finalised beacon header through the SSZ execution branch — and the receipts
// come from the execution RPC. Two providers, and the one that supplies the data
// does not get to say whether the data is right.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func p145Skip(t *testing.T) {
	t.Helper()
	if os.Getenv("P145") == "" {
		t.Skip("set P145=1 to run the P14.5 receipts measurements")
	}
	if os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set CHAIN_PROBE=1")
	}
}

// ---------------------------------------------------------------------------
// RLP ENCODER — does not exist in the package (rlp.go decodes only).
// ---------------------------------------------------------------------------

// rlpHeader builds the length prefix. base is 0x80 for strings, 0xC0 for lists;
// the long form is base+55+len(lengthBytes), which is 0xB7/0xF7 respectively.
func rlpHeader(base byte, n int) []byte {
	if n <= 55 {
		return []byte{base + byte(n)}
	}
	var be []byte
	for v := n; v > 0; v >>= 8 {
		be = append([]byte{byte(v)}, be...)
	}
	return append([]byte{base + 55 + byte(len(be))}, be...)
}

// rlpBytes encodes a byte string. The single-byte-below-0x80 case encodes
// itself; emitting 0x81 0x05 instead of 0x05 is a different encoding of the same
// value and therefore a different hash.
func rlpBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	return append(rlpHeader(0x80, len(b)), b...)
}

// rlpListOf concatenates ALREADY-ENCODED items under a list header.
func rlpListOf(items ...[]byte) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, it...)
	}
	return append(rlpHeader(0xC0, len(body)), body...)
}

// rlpUint encodes an integer as a minimal big-endian string. Zero is the EMPTY
// string, not a zero byte — the commonest RLP mistake and one that changes the
// root.
func rlpUint(v uint64) []byte {
	if v == 0 {
		return []byte{0x80}
	}
	var be []byte
	for x := v; x > 0; x >>= 8 {
		be = append([]byte{byte(x)}, be...)
	}
	return rlpBytes(be)
}

// rlpBig encodes a big integer the same way, for header fields that exceed 64
// bits (difficulty, and base fee in principle).
func rlpBig(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return []byte{0x80}
	}
	return rlpBytes(v.Bytes())
}

// ---------------------------------------------------------------------------
// MERKLE-PATRICIA TRIE BUILDER — also absent; proof.go verifies, never builds.
// ---------------------------------------------------------------------------

type trieEntry struct {
	path  []byte // nibbles of the RAW key; receipts keys are NOT hashed
	value []byte
}

// packHexPrefix is the inverse of proof.go's hexPrefix: nibbles -> packed bytes
// with the leaf/odd flags in the top nibble.
func packHexPrefix(path []byte, isLeaf bool) []byte {
	flag := byte(0)
	if isLeaf {
		flag = 2
	}
	var nib []byte
	if len(path)%2 == 1 {
		nib = append([]byte{flag + 1}, path...)
	} else {
		nib = append([]byte{flag, 0}, path...)
	}
	out := make([]byte, len(nib)/2)
	for i := range out {
		out[i] = nib[2*i]<<4 | nib[2*i+1]
	}
	return out
}

// nodeRef is how a parent points at a child: the hash for nodes of 32 bytes or
// more, and the node ITSELF inlined for smaller ones. Getting this wrong yields
// a self-consistent trie that matches no block on Ethereum.
func nodeRef(encoded []byte) []byte {
	if len(encoded) < 32 {
		return encoded
	}
	return rlpBytes(Keccak256(encoded))
}

// encodeTrieNode builds the subtree covering entries, which all share the first
// `depth` nibbles. Entries must be sorted by path.
func encodeTrieNode(entries []trieEntry, depth int) []byte {
	if len(entries) == 1 {
		e := entries[0]
		return rlpListOf(rlpBytes(packHexPrefix(e.path[depth:], true)), rlpBytes(e.value))
	}

	// How far does the shared prefix run past depth?
	cpl := depth
	for {
		if cpl >= len(entries[0].path) {
			break
		}
		c, same := entries[0].path[cpl], true
		for _, e := range entries[1:] {
			if cpl >= len(e.path) || e.path[cpl] != c {
				same = false
				break
			}
		}
		if !same {
			break
		}
		cpl++
	}
	if cpl > depth {
		child := encodeTrieNode(entries, cpl)
		return rlpListOf(rlpBytes(packHexPrefix(entries[0].path[depth:cpl], false)), nodeRef(child))
	}

	// Branch: seventeen slots, the last holding a value whose key ends here.
	var items [17][]byte
	for i := range items {
		items[i] = []byte{0x80}
	}
	var groups [16][]trieEntry
	for _, e := range entries {
		if len(e.path) == depth {
			items[16] = rlpBytes(e.value)
			continue
		}
		n := e.path[depth]
		groups[n] = append(groups[n], e)
	}
	for n := range groups {
		if len(groups[n]) > 0 {
			items[n] = nodeRef(encodeTrieNode(groups[n], depth+1))
		}
	}
	return rlpListOf(items[:]...)
}

// trieRoot is the root hash of a trie holding exactly these entries.
func trieRoot(entries []trieEntry) []byte {
	if len(entries) == 0 {
		return Keccak256([]byte{0x80}) // the empty-trie root
	}
	sorted := make([]trieEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].path, sorted[j].path) < 0
	})
	return Keccak256(encodeTrieNode(sorted, 0))
}

// ---------------------------------------------------------------------------
// EIP-2718 RECEIPTS
// ---------------------------------------------------------------------------

type measLog struct {
	Address []byte
	Topics  [][]byte
	Data    []byte
}

type measReceipt struct {
	TxIndex uint64
	Type    uint64
	Status  uint64
	HasRoot bool // pre-Byzantium receipts carry a state root instead
	Root    []byte
	CumGas  uint64
	Bloom   []byte // 256 bytes
	Logs    []measLog
}

// encode produces the exact bytes the receipts trie stores.
//
// Legacy (type 0) receipts are the bare RLP list. EIP-2718 typed receipts are
// the type byte PREPENDED to that list — not wrapped in it, and not an RLP
// string containing it.
func (r measReceipt) encode() []byte {
	logs := make([][]byte, 0, len(r.Logs))
	for _, l := range r.Logs {
		topics := make([][]byte, 0, len(l.Topics))
		for _, t := range l.Topics {
			topics = append(topics, rlpBytes(t))
		}
		logs = append(logs, rlpListOf(rlpBytes(l.Address), rlpListOf(topics...), rlpBytes(l.Data)))
	}
	first := rlpUint(r.Status)
	if r.HasRoot {
		first = rlpBytes(r.Root)
	}
	body := rlpListOf(first, rlpUint(r.CumGas), rlpBytes(r.Bloom), rlpListOf(logs...))
	if r.Type == 0 {
		return body
	}
	return append([]byte{byte(r.Type)}, body...)
}

// receiptsTrieRoot rebuilds the whole trie. The key is RLP(transactionIndex) —
// the DECLARED index, so a provider reordering the array changes nothing and a
// provider renumbering it changes the root.
func receiptsTrieRoot(rs []measReceipt) []byte {
	entries := make([]trieEntry, 0, len(rs))
	for _, r := range rs {
		entries = append(entries, trieEntry{path: nibbles(rlpUint(r.TxIndex)), value: r.encode()})
	}
	return trieRoot(entries)
}

// ---------------------------------------------------------------------------
// BLOOM — 2048 bits, three positions per item, from the low end of the array.
// ---------------------------------------------------------------------------

func bloomAdd(bloom []byte, item []byte) {
	h := Keccak256(item)
	for i := 0; i < 6; i += 2 {
		bit := (uint(h[i])<<8 | uint(h[i+1])) & 0x7FF
		bloom[256-1-int(bit/8)] |= 1 << (bit % 8)
	}
}

func bloomHas(bloom []byte, item []byte) bool {
	h := Keccak256(item)
	for i := 0; i < 6; i += 2 {
		bit := (uint(h[i])<<8 | uint(h[i+1])) & 0x7FF
		if bloom[256-1-int(bit/8)]&(1<<(bit%8)) == 0 {
			return false
		}
	}
	return true
}

func bloomBitsSet(bloom []byte) int {
	n := 0
	for _, b := range bloom {
		for i := 0; i < 8; i++ {
			n += int(b>>i) & 1
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// RPC plumbing
// ---------------------------------------------------------------------------

// THROTTLING IS ITSELF A FINDING. The first run of this harness was refused by
// the provider for exceeding compute units per second — eth_getBlockReceipts is
// a heavyweight call, and a watchtower sweeping every 30 seconds would live
// inside that limit permanently. Recorded rather than worked around silently:
// the retries below make the measurement possible and are counted, so no latency
// figure quietly includes a backoff.
var (
	p145Gate     = make(chan struct{}, 1)
	p145Retries  int
	p145Throttle = 250 * time.Millisecond
	p145LastCall time.Time
)

func p145RPC(t *testing.T, method string, params ...any) json.RawMessage {
	t.Helper()
	raw, retried, _ := p145RPCTimed(t, method, params...)
	if retried > 0 {
		p145Retries += retried
	}
	return raw
}

// p145RPCTimed returns the result, how many times the provider refused before
// answering, and the NETWORK time alone.
//
// The network time excludes this harness's own throttle sleep. Timing the whole
// call would fold our rate limiting into the provider's latency and report a
// number that says more about p145Throttle than about Ethereum — the first run
// of this measurement did exactly that and reported 355ms for a call whose real
// cost is different.
func p145RPCTimed(t *testing.T, method string, params ...any) (json.RawMessage, int, time.Duration) {
	t.Helper()
	url := os.Getenv("ETH_RPC_URL")
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})

	backoff := 2 * time.Second
	for attempt := 0; ; attempt++ {
		p145Gate <- struct{}{}
		if wait := p145Throttle - time.Since(p145LastCall); wait > 0 {
			time.Sleep(wait)
		}
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			<-p145Gate
			t.Fatalf("%s: %v", method, err)
		}
		req.Header.Set("Content-Type", "application/json")
		netStart := time.Now()
		resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
		netTime := time.Since(netStart)
		p145LastCall = time.Now()
		<-p145Gate
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		var out struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&out)
		netTime = time.Since(netStart) // includes reading the body off the wire
		resp.Body.Close()
		if decErr != nil {
			t.Fatalf("%s: decode: %v", method, decErr)
		}
		if out.Error != nil {
			if attempt < 6 && strings.Contains(out.Error.Message, "compute units") {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			t.Fatalf("%s: rpc error: %s", method, out.Error.Message)
		}
		return out.Result, attempt, netTime
	}
}

type jsonRPCReceipt struct {
	Type             string `json:"type"`
	Status           string `json:"status"`
	Root             string `json:"root"`
	CumulativeGas    string `json:"cumulativeGasUsed"`
	LogsBloom        string `json:"logsBloom"`
	TransactionIndex string `json:"transactionIndex"`
	Logs             []struct {
		Address string   `json:"address"`
		Topics  []string `json:"topics"`
		Data    string   `json:"data"`
	} `json:"logs"`
}

func hexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func hexToUint(t *testing.T, s string) uint64 {
	t.Helper()
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	if err != nil {
		t.Fatalf("hex uint %q: %v", s, err)
	}
	return v
}

// convert turns the RPC's JSON into the typed form. This is the "decode" phase
// the measurement times separately.
func convertReceipts(t *testing.T, raw []jsonRPCReceipt) []measReceipt {
	t.Helper()
	out := make([]measReceipt, 0, len(raw))
	for _, r := range raw {
		m := measReceipt{
			TxIndex: hexToUint(t, r.TransactionIndex),
			Type:    hexToUint(t, r.Type),
			CumGas:  hexToUint(t, r.CumulativeGas),
			Bloom:   hexToBytes(t, r.LogsBloom),
		}
		if r.Root != "" {
			m.HasRoot, m.Root = true, hexToBytes(t, r.Root)
		} else {
			m.Status = hexToUint(t, r.Status)
		}
		for _, l := range r.Logs {
			lg := measLog{Address: hexToBytes(t, l.Address), Data: hexToBytes(t, l.Data)}
			for _, tp := range l.Topics {
				lg.Topics = append(lg.Topics, hexToBytes(t, tp))
			}
			m.Logs = append(m.Logs, lg)
		}
		out = append(out, m)
	}
	return out
}

func fetchReceipts(t *testing.T, block uint64) []jsonRPCReceipt {
	t.Helper()
	var raw []jsonRPCReceipt
	res := p145RPC(t, "eth_getBlockReceipts", fmt.Sprintf("0x%x", block))
	if err := json.Unmarshal(res, &raw); err != nil {
		t.Fatalf("block %d receipts: %v", block, err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATED REFERENCE — beacon side, not the RPC.
// ---------------------------------------------------------------------------

// authenticatedPayload returns the execution payload header of the FINALISED
// beacon block, proven into that block through the SSZ execution branch.
//
// The receiptsRoot it carries is authenticated by the same branch that
// authenticates the stateRoot P12 already relies on, because HashTreeRoot
// merkleises both — that is the claim the design rests on and this is where it
// is exercised against real data rather than asserted.
func authenticatedPayload(t *testing.T) (ExecutionPayloadHeader, uint64) {
	t.Helper()
	beaconURL := os.Getenv("BEACON_API_URL")
	if beaconURL == "" {
		t.Skip("set BEACON_API_URL to a node serving /eth/v1/beacon/light_client/*")
	}
	if execURL := os.Getenv("ETH_RPC_URL"); execURL != "" && sameProvider(beaconURL, execURL) {
		t.Fatalf("BEACON_API_URL and ETH_RPC_URL are the same provider (%s); "+
			"the reference root must not come from whoever supplies the receipts",
			providerOf(beaconURL))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	final, err := NewBeaconClient(beaconURL).FinalityUpdate(ctx)
	if err != nil {
		t.Fatalf("finality update: %v", err)
	}
	if final.FinalizedExecution == nil {
		t.Skip("this beacon node serves no execution payload on the finalised header")
	}

	// The SSZ branch is what ties the payload to the beacon block. Verified here
	// rather than trusted: without it the "authenticated" root would be just
	// another provider's JSON.
	payload := *final.FinalizedExecution
	root, err := payload.HashTreeRoot(SpecAltair)
	if err != nil {
		t.Fatalf("payload hash tree root: %v", err)
	}
	if err := VerifyBranch(root, final.FinalizedExecutionBranch,
		ExecutionPayloadIndex, final.FinalizedHeader.BodyRoot); err != nil {
		t.Fatalf("execution branch does not place this payload in the finalised "+
			"beacon block: %v", err)
	}
	t.Logf("AUTHENTICATED payload: beacon slot %d, execution block %d, receiptsRoot %x",
		final.FinalizedHeader.Slot, payload.BlockNumber, payload.ReceiptsRoot[:8])
	return payload, payload.BlockNumber
}

// ---------------------------------------------------------------------------
// MEASUREMENT 6 — the end-to-end round trip, against the AUTHENTICATED root.
// ---------------------------------------------------------------------------

func TestP145EndToEndAuthenticatedReceiptsRoot(t *testing.T) {
	p145Skip(t)
	payload, blockNumber := authenticatedPayload(t)

	raw := fetchReceipts(t, blockNumber)
	if len(raw) == 0 {
		t.Skip("finalised block has no receipts")
	}
	receipts := convertReceipts(t, raw)

	got := receiptsTrieRoot(receipts)
	if !bytes.Equal(got, payload.ReceiptsRoot[:]) {
		t.Fatalf("REBUILD DOES NOT MATCH THE AUTHENTICATED ROOT\n"+
			"  block      %d\n  rebuilt    %x\n  authentic  %x\n"+
			"  receipts   %d",
			blockNumber, got, payload.ReceiptsRoot[:], len(receipts))
	}

	types := map[uint64]int{}
	logs := 0
	for _, r := range receipts {
		types[r.Type]++
		logs += len(r.Logs)
	}
	t.Logf("ROUND TRIP EXACT: block %d, %d receipts, %d logs, types %v",
		blockNumber, len(receipts), logs, types)
	t.Logf("  rebuilt root %x", got)
	t.Logf("  equals the root proven into finalised beacon block — the RPC that " +
		"supplied the receipts did not supply the root they were checked against")

	// The block-level bloom is the OR of the receipt blooms, and it too is
	// authenticated. An independent check on the same data.
	union := make([]byte, 256)
	for _, r := range receipts {
		for i := range union {
			union[i] |= r.Bloom[i]
		}
	}
	if !bytes.Equal(union, payload.LogsBloom[:]) {
		t.Errorf("union of receipt blooms does not equal the authenticated logsBloom")
	} else {
		t.Logf("  union of receipt blooms also equals the authenticated logsBloom")
	}
}

// Every receipt type present on mainnet must round-trip, not just the common one.
func TestP145TypedReceiptCoverage(t *testing.T) {
	p145Skip(t)
	_, head := authenticatedPayload(t)

	seen := map[uint64]int{}
	blocksNeeded := 12
	for i := 0; i < blocksNeeded; i++ {
		n := head - uint64(i)
		raw := fetchReceipts(t, n)
		if len(raw) == 0 {
			continue
		}
		receipts := convertReceipts(t, raw)
		for _, r := range receipts {
			seen[r.Type]++
		}
		// Each block is verified against the block's own receiptsRoot from the
		// execution header. That header is NOT authenticated, so this is a
		// consistency check across many blocks, not a trust claim — the trust
		// claim is the single authenticated block above.
		var hdr struct {
			ReceiptsRoot string `json:"receiptsRoot"`
		}
		if err := json.Unmarshal(p145RPC(t, "eth_getBlockByNumber",
			fmt.Sprintf("0x%x", n), false), &hdr); err != nil {
			t.Fatalf("header %d: %v", n, err)
		}
		if got := receiptsTrieRoot(receipts); !bytes.Equal(got, hexToBytes(t, hdr.ReceiptsRoot)) {
			t.Fatalf("block %d rebuild mismatch: got %x want %s", n, got, hdr.ReceiptsRoot)
		}
	}
	t.Logf("TYPE COVERAGE over %d blocks: %v", blocksNeeded, seen)
	for _, want := range []uint64{0, 2} {
		if seen[want] == 0 {
			t.Errorf("no type 0x%x receipts encountered — coverage incomplete", want)
		}
	}
	t.Logf("  legacy=0x0 1559=0x2 blob=0x3 setcode=0x4; every type present " +
		"round-tripped through the same encoder")
}

// NEGATIVE TESTS. A rebuild that matched no matter what would prove nothing.
func TestP145AlteredReceiptsAreRejected(t *testing.T) {
	p145Skip(t)
	payload, blockNumber := authenticatedPayload(t)
	base := convertReceipts(t, fetchReceipts(t, blockNumber))
	if len(base) < 3 {
		t.Skip("need at least three receipts")
	}
	want := payload.ReceiptsRoot[:]
	if !bytes.Equal(receiptsTrieRoot(base), want) {
		t.Fatalf("baseline does not match; the negative tests would be meaningless")
	}

	clone := func() []measReceipt {
		out := make([]measReceipt, len(base))
		for i, r := range base {
			c := r
			c.Bloom = append([]byte(nil), r.Bloom...)
			c.Logs = append([]measLog(nil), r.Logs...)
			for j, l := range c.Logs {
				nl := l
				nl.Address = append([]byte(nil), l.Address...)
				nl.Data = append([]byte(nil), l.Data...)
				// Each topic copied INDIVIDUALLY. Copying the slice of slices
				// alone shares every topic's bytes, so a mutation case would
				// silently corrupt the baseline it is measured against — which
				// is exactly what the first run of this test did.
				nl.Topics = make([][]byte, len(l.Topics))
				for k, tp := range l.Topics {
					nl.Topics[k] = append([]byte(nil), tp...)
				}
				c.Logs[j] = nl
			}
			out[i] = c
		}
		return out
	}

	// Find a receipt carrying at least one log with at least one topic.
	withLog := -1
	for i, r := range base {
		if len(r.Logs) > 0 && len(r.Logs[0].Topics) > 0 {
			withLog = i
			break
		}
	}

	cases := []struct {
		name   string
		break_ func([]measReceipt) []measReceipt
	}{
		{"status flipped", func(rs []measReceipt) []measReceipt {
			rs[0].Status ^= 1
			return rs
		}},
		{"cumulativeGasUsed off by one", func(rs []measReceipt) []measReceipt {
			rs[1].CumGas++
			return rs
		}},
		{"one bloom bit flipped", func(rs []measReceipt) []measReceipt {
			rs[0].Bloom[100] ^= 0x01
			return rs
		}},
		{"transaction type changed 0x2->0x3", func(rs []measReceipt) []measReceipt {
			for i := range rs {
				if rs[i].Type == 2 {
					rs[i].Type = 3
					break
				}
			}
			return rs
		}},
		{"receipt OMITTED", func(rs []measReceipt) []measReceipt {
			return append(rs[:1], rs[2:]...)
		}},
		{"transaction index renumbered", func(rs []measReceipt) []measReceipt {
			rs[0].TxIndex, rs[1].TxIndex = rs[1].TxIndex, rs[0].TxIndex
			return rs
		}},
		{"receipt duplicated over another index", func(rs []measReceipt) []measReceipt {
			rs[1] = rs[0]
			rs[1].TxIndex = rs[0].TxIndex + 1
			return rs
		}},
	}
	if withLog >= 0 {
		cases = append(cases,
			struct {
				name   string
				break_ func([]measReceipt) []measReceipt
			}{"log address changed", func(rs []measReceipt) []measReceipt {
				rs[withLog].Logs[0].Address[0] ^= 0xFF
				return rs
			}},
			struct {
				name   string
				break_ func([]measReceipt) []measReceipt
			}{"log topic changed", func(rs []measReceipt) []measReceipt {
				rs[withLog].Logs[0].Topics[0][31] ^= 0x01
				return rs
			}},
			struct {
				name   string
				break_ func([]measReceipt) []measReceipt
			}{"log dropped from a receipt", func(rs []measReceipt) []measReceipt {
				rs[withLog].Logs = rs[withLog].Logs[1:]
				return rs
			}},
		)
	}

	for _, c := range cases {
		got := receiptsTrieRoot(c.break_(clone()))
		if bytes.Equal(got, want) {
			t.Errorf("NOT CAUGHT: %s produced the authenticated root", c.name)
		} else {
			t.Logf("caught: %-38s root %x != %x", c.name, got[:6], want[:6])
		}
	}

	// The baseline must still be intact. If a mutation case reached through a
	// shared slice into `base`, every result above was measured against a moving
	// target and the whole test means nothing.
	if !bytes.Equal(receiptsTrieRoot(base), want) {
		t.Fatalf("the baseline was mutated by one of the cases above — clone() is " +
			"not deep enough, and the results are not trustworthy")
	}

	// The one alteration that MUST NOT change the root: reordering the array
	// while keeping the declared indices. A trie is a set, not a sequence.
	shuffled := clone()
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	if !bytes.Equal(receiptsTrieRoot(shuffled), want) {
		t.Errorf("reversing the receipt ARRAY changed the root; the key must be " +
			"the declared transactionIndex, not the array position")
	} else {
		t.Logf("unchanged by array order, as a set should be")
	}
}

// ---------------------------------------------------------------------------
// MEASUREMENT 2 — rebuild cost, phase by phase, over consecutive blocks.
// ---------------------------------------------------------------------------

func TestP145RebuildCost(t *testing.T) {
	p145Skip(t)
	_, head := authenticatedPayload(t)

	const blocks = 20
	var fetchD, decodeD, encodeD, buildD, verifyD []time.Duration
	var totalReceipts, totalLogs, totalBytes int

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	cpu0 := cpuTime()
	wall0 := time.Now()

	for i := 0; i < blocks; i++ {
		n := head - uint64(i)

		res, retried, took := p145RPCTimed(t, "eth_getBlockReceipts", fmt.Sprintf("0x%x", n))
		var raw []jsonRPCReceipt
		if err := json.Unmarshal(res, &raw); err != nil {
			t.Fatalf("block %d receipts: %v", n, err)
		}
		// A sample that waited on a backoff measures the provider's rate limit,
		// not its latency, and averaging the two together would understate both.
		if retried == 0 {
			fetchD = append(fetchD, took)
		}
		if len(raw) == 0 {
			continue
		}

		start := time.Now()
		receipts := convertReceipts(t, raw)
		decodeD = append(decodeD, time.Since(start))

		// Encoding measured on its own: it is the part that must be EXACT, and
		// the part a future fork changes.
		start = time.Now()
		entries := make([]trieEntry, 0, len(receipts))
		for _, r := range receipts {
			v := r.encode()
			totalBytes += len(v)
			entries = append(entries, trieEntry{path: nibbles(rlpUint(r.TxIndex)), value: v})
		}
		encodeD = append(encodeD, time.Since(start))

		start = time.Now()
		root := trieRoot(entries)
		buildD = append(buildD, time.Since(start))

		var hdr struct {
			ReceiptsRoot string `json:"receiptsRoot"`
		}
		if err := json.Unmarshal(p145RPC(t, "eth_getBlockByNumber",
			fmt.Sprintf("0x%x", n), false), &hdr); err != nil {
			t.Fatalf("header %d: %v", n, err)
		}
		start = time.Now()
		ok := bytes.Equal(root, hexToBytes(t, hdr.ReceiptsRoot))
		verifyD = append(verifyD, time.Since(start))
		if !ok {
			t.Fatalf("block %d: rebuild mismatch", n)
		}

		totalReceipts += len(receipts)
		for _, r := range receipts {
			totalLogs += len(r.Logs)
		}
	}

	wall := time.Since(wall0)
	cpu := cpuTime() - cpu0
	runtime.ReadMemStats(&after)

	report := func(name string, d []time.Duration) {
		if len(d) == 0 {
			return
		}
		sortDurations(d)
		t.Logf("%-22s median %-10s p95 %-10s max %-10s (n=%d)",
			name, pct(d, 0.5), pct(d, 0.95), d[len(d)-1], len(d))
	}
	report("fetch (network only)", fetchD)
	report("decode JSON", decodeD)
	report("encode receipts", encodeD)
	report("trie construction", buildD)
	report("root verification", verifyD)

	// Local cost is what matters for the design: the fetch was measurement 1.
	var localMedian time.Duration
	if len(decodeD) > 0 {
		localMedian = pct(decodeD, 0.5) + pct(encodeD, 0.5) + pct(buildD, 0.5) + pct(verifyD, 0.5)
	}
	t.Logf("")
	t.Logf("LOCAL COST PER BLOCK (decode+encode+build+verify): %s median", localMedian)
	t.Logf("  %d blocks, %d receipts (%.0f/block), %d logs, %.1f MB of receipt bytes",
		blocks, totalReceipts, float64(totalReceipts)/float64(blocks), totalLogs,
		float64(totalBytes)/(1<<20))
	t.Logf("CPU: %s over %s wall (%.0f%% of one core)",
		cpu.Round(time.Millisecond), wall.Round(time.Millisecond),
		100*cpu.Seconds()/wall.Seconds())
	t.Logf("MEMORY: heap %d MB -> %d MB, total allocated %d MB over the run",
		before.HeapAlloc>>20, after.HeapAlloc>>20,
		(after.TotalAlloc-before.TotalAlloc)>>20)
	t.Logf("PER 30s SWEEP (~2.5 blocks): local %s + network (measurement 1)",
		(localMedian * 5 / 2).Round(time.Millisecond))
}

// cpuTime is user+system CPU for this process.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	tv := func(t syscall.Timeval) time.Duration {
		return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond
	}
	return tv(ru.Utime) + tv(ru.Stime)
}

// ---------------------------------------------------------------------------
// MEASUREMENT 3 — the bloom false-positive rate for OUR contract address.
// ---------------------------------------------------------------------------

const p145Contract = "0xae70526931FF460894133201f6C8cA91bbA0E177"

func TestP145BloomFalsePositiveRate(t *testing.T) {
	p145Skip(t)
	_, head := authenticatedPayload(t)
	addr := hexToBytes(t, p145Contract)

	const blocks = 100
	var hits, truePositives, falsePositives, misses int
	var bitsSet []int

	for i := 0; i < blocks; i++ {
		n := head - uint64(i)
		var hdr struct {
			LogsBloom    string `json:"logsBloom"`
			ReceiptsRoot string `json:"receiptsRoot"`
		}
		if err := json.Unmarshal(p145RPC(t, "eth_getBlockByNumber",
			fmt.Sprintf("0x%x", n), false), &hdr); err != nil {
			t.Fatalf("header %d: %v", n, err)
		}
		bloom := hexToBytes(t, hdr.LogsBloom)
		bitsSet = append(bitsSet, bloomBitsSet(bloom))

		if !bloomHas(bloom, addr) {
			misses++
			continue
		}
		hits++
		// A bloom hit is NOT an event. Confirm against the receipts — which is
		// exactly the rule the design must preserve.
		receipts := convertReceipts(t, fetchReceipts(t, n))
		found := false
		for _, r := range receipts {
			for _, l := range r.Logs {
				if bytes.EqualFold(l.Address, addr) {
					found = true
				}
			}
		}
		if found {
			truePositives++
		} else {
			falsePositives++
		}
	}

	avgBits := 0
	for _, b := range bitsSet {
		avgBits += b
	}
	avgBits /= max1(len(bitsSet))

	t.Logf("BLOOM over %d finalised-ish blocks for %s", blocks, p145Contract)
	t.Logf("  negative (block skipped outright): %d  (%.0f%%)",
		misses, 100*float64(misses)/float64(blocks))
	t.Logf("  positive: %d — of which %d true, %d FALSE",
		hits, truePositives, falsePositives)
	if hits > 0 {
		t.Logf("  false-positive rate among positives: %.1f%%",
			100*float64(falsePositives)/float64(hits))
	}
	t.Logf("  work avoided entirely: %.0f%% of blocks", 100*float64(misses)/float64(blocks))
	t.Logf("  average bloom saturation: %d/2048 bits (%.0f%%)",
		avgBits, 100*float64(avgBits)/2048)
	t.Logf("NOTE: a false positive costs one wasted receipts fetch. A false " +
		"NEGATIVE would be a missed close, and blooms have none — which is why " +
		"the skip is sound and the hit is not evidence.")
}

// ---------------------------------------------------------------------------
// MEASUREMENT 4 — catch-up after an outage.
// ---------------------------------------------------------------------------

// The execution block header, RLP-encoded. Needed because the light-client API
// serves the CURRENT finality update and one update per sync-committee period —
// it cannot hand back the payload header for an arbitrary past block. Catching
// up therefore means walking parentHash backwards from an authenticated block,
// which requires reproducing each header's hash exactly.
func fetchHeaderRLP(t *testing.T, n uint64) (encoded, hash, parent, bloom []byte, net time.Duration) {
	t.Helper()
	raw, _, netTime := p145RPCTimed(t, "eth_getBlockByNumber", fmt.Sprintf("0x%x", n), false)
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("header %d: %v", n, err)
	}
	encoded, hash, parent, bloom = encodeHeaderRLP(t, h)
	return encoded, hash, parent, bloom, netTime
}

// encodeHeaderRLP is split out so the batched path can reuse it without a
// second network call.
func encodeHeaderRLP(t *testing.T, h map[string]any) ([]byte, []byte, []byte, []byte) {
	t.Helper()
	str := func(k string) string {
		v, _ := h[k].(string)
		return v
	}
	b := func(k string) []byte { return hexToBytes(t, str(k)) }
	num := func(k string) []byte {
		s := strings.TrimPrefix(str(k), "0x")
		if s == "" {
			return rlpUint(0)
		}
		v := new(big.Int)
		v.SetString(s, 16)
		return rlpBig(v)
	}

	// Post-Prague field order. A wrong COUNT hashes to something real-looking
	// and matches nothing — the same fork trap as the SSZ payload header.
	items := [][]byte{
		rlpBytes(b("parentHash")), rlpBytes(b("sha3Uncles")), rlpBytes(b("miner")),
		rlpBytes(b("stateRoot")), rlpBytes(b("transactionsRoot")), rlpBytes(b("receiptsRoot")),
		rlpBytes(b("logsBloom")), num("difficulty"), num("number"), num("gasLimit"),
		num("gasUsed"), num("timestamp"), rlpBytes(b("extraData")),
		rlpBytes(b("mixHash")), rlpBytes(b("nonce")), num("baseFeePerGas"),
	}
	for _, k := range []string{"withdrawalsRoot"} {
		if str(k) != "" {
			items = append(items, rlpBytes(b(k)))
		}
	}
	for _, k := range []string{"blobGasUsed", "excessBlobGas"} {
		if str(k) != "" {
			items = append(items, num(k))
		}
	}
	for _, k := range []string{"parentBeaconBlockRoot", "requestsHash"} {
		if str(k) != "" {
			items = append(items, rlpBytes(b(k)))
		}
	}
	return rlpListOf(items...), b("hash"), b("parentHash"), b("logsBloom")
}

// p145RPCBatch issues one JSON-RPC batch. The parentHash chain is serial to
// VERIFY but not to FETCH — headers can be pulled in bulk and the chain checked
// locally afterwards, which is the difference between a catch-up bounded by
// round-trip latency and one bounded by throughput.
func p145RPCBatch(t *testing.T, from uint64, count int) ([]map[string]any, time.Duration) {
	t.Helper()
	reqs := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		reqs = append(reqs, map[string]any{
			"jsonrpc": "2.0", "id": i, "method": "eth_getBlockByNumber",
			"params": []any{fmt.Sprintf("0x%x", from-uint64(i)), false},
		})
	}
	body, _ := json.Marshal(reqs)
	req, err := http.NewRequest("POST", os.Getenv("ETH_RPC_URL"), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	p145Gate <- struct{}{}
	if wait := p145Throttle - time.Since(p145LastCall); wait > 0 {
		time.Sleep(wait)
	}
	start := time.Now()
	resp, err := (&http.Client{Timeout: 180 * time.Second}).Do(req)
	if err != nil {
		p145LastCall = time.Now()
		<-p145Gate
		t.Fatalf("batch: %v", err)
	}
	var out []struct {
		ID     int                       `json:"id"`
		Result map[string]any            `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	decErr := json.NewDecoder(resp.Body).Decode(&out)
	took := time.Since(start)
	resp.Body.Close()
	p145LastCall = time.Now()
	<-p145Gate
	if decErr != nil {
		return nil, 0
	}
	byID := make(map[int]map[string]any, len(out))
	for _, o := range out {
		if o.Error != nil || o.Result == nil {
			return nil, 0
		}
		byID[o.ID] = o.Result
	}
	ordered := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		if byID[i] == nil {
			return nil, 0
		}
		ordered = append(ordered, byID[i])
	}
	return ordered, took
}

func TestP145CatchUpCost(t *testing.T) {
	p145Skip(t)
	payload, head := authenticatedPayload(t)
	addr := hexToBytes(t, p145Contract)

	// Can a PAST block be authenticated at all? The light-client API serves the
	// CURRENT finality update and one update per sync-committee period; it
	// cannot hand back the execution payload for an arbitrary past block. So
	// catching up means walking parentHash backwards from an authenticated
	// block, re-encoding each header and checking it hashes to what the block
	// after it declared.
	const walk = 25
	expected := payload.BlockHash[:]
	var netD, localD []time.Duration
	verified, bloomHits := 0, 0
	for i := 0; i < walk; i++ {
		n := head - uint64(i)
		encoded, hash, parent, bloom, net := fetchHeaderRLP(t, n)
		start := time.Now()
		got := Keccak256(encoded)
		localD = append(localD, time.Since(start))
		netD = append(netD, net)
		if !bytes.Equal(got, expected) {
			t.Fatalf("block %d: header RLP hashes to %x, but the block after it "+
				"(or the authenticated payload) says %x — the backwards walk is "+
				"broken\n  rpc-reported hash %x", n, got, expected, hash)
		}
		if bloomHas(bloom, addr) {
			bloomHits++
		}
		verified++
		expected = parent
	}
	sortDurations(netD)
	sortDurations(localD)
	t.Logf("BACKWARDS HEADER WALK: %d consecutive headers re-encoded and hashed, "+
		"each matching the parentHash of the block after it, anchored at the "+
		"AUTHENTICATED block hash %x", verified, payload.BlockHash[:6])
	t.Logf("  per header: network %s median, local RLP+keccak %s median",
		pct(netD, 0.5), pct(localD, 0.5))
	t.Logf("  authenticated blooms hit for our contract: %d/%d", bloomHits, walk)

	// Batched: same headers, one request. The chain is still verified serially
	// and locally.
	batch, batchTook := p145RPCBatch(t, head, 100)
	var perHeaderBatched time.Duration
	if batch != nil {
		exp := payload.BlockHash[:]
		start := time.Now()
		for _, h := range batch {
			encoded, _, parent, _ := encodeHeaderRLP(t, h)
			if !bytes.Equal(Keccak256(encoded), exp) {
				t.Fatalf("batched walk broke at %v", h["number"])
			}
			exp = parent
		}
		verifyAll := time.Since(start)
		perHeaderBatched = (batchTook + verifyAll) / time.Duration(len(batch))
		t.Logf("BATCHED: %d headers in one request — fetch %s, verify %s, "+
			"= %s per header (%.0fx better than one-at-a-time)",
			len(batch), batchTook.Round(time.Millisecond),
			verifyAll.Round(time.Millisecond), perHeaderBatched.Round(time.Microsecond),
			float64(pct(netD, 0.5))/float64(perHeaderBatched))
	}

	var buildD []time.Duration
	for i := 0; i < 5; i++ {
		receipts := convertReceipts(t, fetchReceipts(t, head-uint64(i)))
		start := time.Now()
		_ = receiptsTrieRoot(receipts)
		buildD = append(buildD, time.Since(start))
	}
	sortDurations(buildD)

	serial := pct(netD, 0.5) + pct(localD, 0.5)
	rebuild := pct(buildD, 0.5) + 80*time.Millisecond // fetch + rebuild on a hit
	const bloomHitRate = 0.18                         // measurement 3
	t.Logf("")
	t.Logf("CATCH-UP, from measured per-block costs")
	t.Logf("  header, one at a time : %s/block", serial.Round(time.Millisecond))
	if perHeaderBatched > 0 {
		t.Logf("  header, batched 100   : %s/block", perHeaderBatched.Round(time.Microsecond))
	}
	t.Logf("  receipts on a bloom hit: %s (~18%% of blocks)", rebuild.Round(time.Millisecond))
	for _, o := range []struct {
		name   string
		blocks int
	}{{"1 hour", 300}, {"24 hours", 7200}, {"1 week", 50400}} {
		n := time.Duration(o.blocks)
		hits := time.Duration(float64(o.blocks) * bloomHitRate)
		one := n*serial + hits*rebuild
		line := fmt.Sprintf("  %-9s = %6d blocks: %s serial", o.name, o.blocks,
			one.Round(time.Second))
		if perHeaderBatched > 0 {
			bat := n*perHeaderBatched + hits*rebuild
			line += fmt.Sprintf("  |  %s batched", bat.Round(time.Second))
		}
		t.Log(line)
	}
	t.Logf("NOTE: the parentHash chain is serial to VERIFY but not to FETCH. "+
		"Verification is local and costs %s per header; the round trip is what "+
		"dominates, and batching removes it.", pct(localD, 0.5))
}
