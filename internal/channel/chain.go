package channel

// Where collateral comes from — roadmap invariant P5-1.
//
// THE ATTACK THIS EXISTS TO MAKE IMPOSSIBLE
// -----------------------------------------
// A peer announces a channel and says it holds 1,000 ANON. It then proposes a
// state of 900/100, correctly signed, correctly conserved against that 1,000,
// at a sensible nonce. Every check in Channel.Accept passes — and every one of
// them was checking a state against a number the attacker chose.
//
// On chain the deposit is 10.
//
// The state machine cannot catch this, and it is not supposed to: its job is to
// check a state against the deposits. The deposits were the lie. The subtler
// version never states a false figure at all, it just builds a consistent
// history on top of a fabricated opening balance.
//
// So a peer may supply a channel IDENTIFIER. It may not declare its own
// collateral.
//
// HOW THAT IS ENFORCED RATHER THAN DOCUMENTED
// -------------------------------------------
// OnChainChannel carries an unexported marker that only a chain read sets, and
// Store.TrackFromChain refuses a value without it. A caller outside this package
// cannot construct one — not by struct literal, not by conversion — so "the
// deposit came from a peer" is not a mistake that compiles.
//
// Inside the package, tests can build one through the fake reader below. That is
// the point: the guard is against an API that leaks trust, not against ourselves.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

var (
	ErrChannelNotOnChain = errors.New("chain: no such channel in ChannelManagerV2")
	ErrNotFromChain      = errors.New("chain: channel facts did not come from a chain read")
	ErrChainUnreachable  = errors.New("chain: could not read the contract")
)

// OnChainChannel is what ChannelManagerV2 says about a channel.
//
// Construct only through a ChainReader. The zero value is deliberately useless.
type OnChainChannel struct {
	ID       [32]byte
	PartyA   Address
	PartyB   Address
	DepositA *big.Int
	DepositB *big.Int
	Status   Status

	// fromChain is the guard. Unexported, so no package outside this one can
	// set it, and a hand-built OnChainChannel is rejected by TrackFromChain.
	fromChain bool
}

// ChainReader reads authoritative channel facts.
type ChainReader interface {
	ReadChannel(ctx context.Context, contract Address, id [32]byte) (OnChainChannel, error)
}

// ---- the real one ----------------------------------------------------------

// RPCChainReader reads through an Ethereum JSON-RPC endpoint.
type RPCChainReader struct {
	Endpoint string
	Client   *http.Client
}

// NewRPCChainReader builds a reader with a sane timeout. A payment path that
// blocks forever on an RPC is a payment path that stops.
func NewRPCChainReader(endpoint string) *RPCChainReader {
	return &RPCChainReader{
		Endpoint: endpoint,
		Client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// channelsSelector is keccak("channels(bytes32)")[:4] — the public mapping
// getter ChannelManagerV2 generates.
var channelsSelector = keccak([]byte("channels(bytes32)"))[:4]

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	Result string `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// ReadChannel calls channels(id) and decodes the struct.
//
// The layout is ChannelManagerV2.Channel, in declaration order, one 32-byte word
// each — partyA, partyB, depositA, depositB, status, balanceA, balanceB, nonce,
// challengeEnds, htlcRoot, lockedTotal. Only the first five are read here; the
// rest are the chain's view of a state, and this node's view of a state comes
// from signatures, not from whatever was last settled.
func (r *RPCChainReader) ReadChannel(ctx context.Context, contract Address, id [32]byte) (OnChainChannel, error) {
	data := "0x" + hex.EncodeToString(channelsSelector) + hex.EncodeToString(id[:])

	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", ID: 1, Method: "eth_call",
		Params: []any{
			map[string]string{"to": contract.Hex(), "data": data},
			"latest",
		},
	})
	if err != nil {
		return OnChainChannel{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint, bytes.NewReader(body))
	if err != nil {
		return OnChainChannel{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := r.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return OnChainChannel{}, fmt.Errorf("%w: %v", ErrChainUnreachable, err)
	}
	defer resp.Body.Close()

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return OnChainChannel{}, fmt.Errorf("%w: %v", ErrChainUnreachable, err)
	}
	if out.Error != nil {
		return OnChainChannel{}, fmt.Errorf("%w: %s", ErrChainUnreachable, out.Error.Message)
	}
	return decodeChannelsReturn(id, out.Result)
}

func decodeChannelsReturn(id [32]byte, result string) (OnChainChannel, error) {
	raw, err := hex.DecodeString(trim0x(result))
	if err != nil {
		return OnChainChannel{}, fmt.Errorf("%w: result is not hex", ErrChainUnreachable)
	}
	// Five words is the minimum this function reads; a shorter return means the
	// address is not the contract we think it is.
	if len(raw) < 5*32 {
		return OnChainChannel{}, fmt.Errorf("%w: short return (%d bytes)", ErrChainUnreachable, len(raw))
	}

	wordAt := func(i int) []byte { return raw[i*32 : (i+1)*32] }
	addrAt := func(i int) Address {
		var a Address
		copy(a[:], wordAt(i)[12:])
		return a
	}

	out := OnChainChannel{
		ID:        id,
		PartyA:    addrAt(0),
		PartyB:    addrAt(1),
		DepositA:  new(big.Int).SetBytes(wordAt(2)),
		DepositB:  new(big.Int).SetBytes(wordAt(3)),
		Status:    Status(new(big.Int).SetBytes(wordAt(4)).Uint64()),
		fromChain: true,
	}

	// Status None with zero parties is how the mapping answers for a channel
	// that was never opened. Treating that as a real channel with zero deposits
	// would let a peer name any id at all and have it accepted.
	if out.Status == StatusNone || (out.PartyA.IsZero() && out.PartyB.IsZero()) {
		return OnChainChannel{}, ErrChannelNotOnChain
	}
	// The chain sorts parties; if it did not, the id would not derive.
	if DeriveChannelID(out.PartyA, out.PartyB) != id {
		return OnChainChannel{}, fmt.Errorf(
			"%w: the contract's parties do not derive the id asked for", ErrChainUnreachable)
	}
	return out, nil
}

func trim0x(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}

// ---- the test one ----------------------------------------------------------

// FakeChain is an in-memory ChainReader for tests.
//
// It lives in the package rather than a test file because the guard it has to
// set is unexported — which is the same reason it cannot be abused from outside.
type FakeChain struct {
	mu       sync.Mutex
	Channels map[[32]byte]OnChainChannel
	Err      error
}

// NewFakeChain builds an empty one.
func NewFakeChain() *FakeChain {
	return &FakeChain{Channels: map[[32]byte]OnChainChannel{}}
}

// Add records a channel as the chain would report it.
func (f *FakeChain) Add(partyA, partyB Address, depositA, depositB *big.Int) [32]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, b := SortParties(partyA, partyB)
	id := DeriveChannelID(a, b)
	da, db := depositA, depositB
	if !partyA.Less(partyB) {
		da, db = depositB, depositA
	}
	f.Channels[id] = OnChainChannel{
		ID: id, PartyA: a, PartyB: b,
		DepositA: orZero(da), DepositB: orZero(db),
		Status: StatusOpen, fromChain: true,
	}
	return id
}

func (f *FakeChain) ReadChannel(_ context.Context, _ Address, id [32]byte) (OnChainChannel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return OnChainChannel{}, f.Err
	}
	ch, ok := f.Channels[id]
	if !ok {
		return OnChainChannel{}, ErrChannelNotOnChain
	}
	return ch, nil
}
