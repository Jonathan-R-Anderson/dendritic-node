package channel

// ChainWriter — roadmap P6. The first component here that spends money.
//
// WHY IT IS SEPARATE FROM ChainReader
// -----------------------------------
// Different capability, different failure modes, different requirements.
// Reading needs an RPC endpoint. Writing needs a key that can pay gas, a nonce
// to manage, and a view on what happens when a transaction is dropped or
// replaced. A component that only needs to look at the chain should not be
// handed the ability to spend from it, and the interfaces stay apart so that is
// enforced by what a caller was given rather than by discipline.
//
// WHAT A RETURNED HASH MEANS
// --------------------------
// Broadcast. Nothing else. Not mined, not confirmed, not final. Every method
// here returns a transaction hash and the caller learns what became of it by
// READING THE CHAIN — the same rule the transport layer follows one level up,
// where a successful write is not a completed payment.
//
// So this file deliberately has no "wait for confirmation" helper. Offering one
// would invite a worker to treat its return as proof, and the proof lives in
// the contract's own status.
//
// THE WORKER DOES NOT BUILD TRANSACTIONS
// --------------------------------------
// Everything about calldata, gas, nonces and signing lives behind this
// interface. The payout worker names an operation and a channel; it never
// encodes a function selector. That keeps the worker testable against a fake
// and keeps Ethereum's details out of the settlement logic.

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
	ErrNoSigningKey    = errors.New("chainwriter: no key configured; this node cannot send transactions")
	ErrWriterNotWired  = errors.New("chainwriter: no transaction sender configured")
	ErrNothingToSubmit = errors.New("chainwriter: channel has no fully signed state")
)

// ---- calldata ---------------------------------------------------------------

// Selectors for the operations settlement uses. Computed rather than pasted, so
// a signature change in the contract shows up as a failing call rather than as
// silently wrong calldata.
var (
	selCheckpoint       = keccak([]byte("checkpoint((bytes32,uint64,uint256,uint256,uint256,uint256),(bytes32,bytes32,uint256,uint256,bool)[],bytes,bytes)"))[:4]
	selCloseCooperative = keccak([]byte("closeCooperative(bytes32,uint64,uint256,uint256,bytes,bytes)"))[:4]
	selClaimLock        = keccak([]byte("claimLock(bytes32,(bytes32,bytes32,uint256,uint256,bool)[],uint256,bytes32)"))[:4]
	selExpireLock       = keccak([]byte("expireLock(bytes32,(bytes32,bytes32,uint256,uint256,bool)[],uint256)"))[:4]
)

// abiEncoder builds calldata one 32-byte word at a time.
//
// Hand-rolled rather than pulled from a binding library for the same reason the
// digest is: this has to agree with the contract exactly, and a dependency that
// agrees "usually" is worse than a hundred lines that can be read.
type abiEncoder struct{ head, tail []byte }

func (e *abiEncoder) word(b []byte) { e.head = append(e.head, word(b)...) }
func (e *abiEncoder) u256(n *big.Int) {
	if n == nil {
		n = new(big.Int)
	}
	e.head = append(e.head, word(n.Bytes())...)
}
func (e *abiEncoder) u64(n uint64)     { e.u256(new(big.Int).SetUint64(n)) }
func (e *abiEncoder) fixed(b [32]byte) { e.head = append(e.head, b[:]...) }
func (e *abiEncoder) boolean(v bool) {
	n := new(big.Int)
	if v {
		n.SetInt64(1)
	}
	e.u256(n)
}

// offset reserves a head slot for a dynamic value and returns its index.
func (e *abiEncoder) offset() int {
	e.head = append(e.head, make([]byte, 32)...)
	return len(e.head)/32 - 1
}

// patch writes the tail offset into a reserved head slot.
func (e *abiEncoder) patch(slot int, tailPos int) {
	off := len(e.head) + tailPos
	copy(e.head[slot*32:(slot+1)*32], word(big.NewInt(int64(off)).Bytes()))
}

func (e *abiEncoder) bytes() []byte { return append(e.head, e.tail...) }

// encodeBytes appends a dynamic bytes value to the tail, returning its position.
func (e *abiEncoder) encodeBytes(b []byte) int {
	pos := len(e.tail)
	e.tail = append(e.tail, word(big.NewInt(int64(len(b))).Bytes())...)
	padded := make([]byte, ((len(b)+31)/32)*32)
	copy(padded, b)
	e.tail = append(e.tail, padded...)
	return pos
}

// encodeLocks appends a Lock[] to the tail. Static struct elements, so the array
// is just a length followed by the members inline — the same canonical id order
// the contract requires.
func (e *abiEncoder) encodeLocks(locks []HTLC) int {
	pos := len(e.tail)
	e.tail = append(e.tail, word(big.NewInt(int64(len(locks))).Bytes())...)
	for _, l := range locks {
		e.tail = append(e.tail, l.ID[:]...)
		e.tail = append(e.tail, l.Hash[:]...)
		e.tail = append(e.tail, word(orZero(l.Amount).Bytes())...)
		e.tail = append(e.tail, word(big.NewInt(l.Expiry).Bytes())...)
		flag := new(big.Int)
		if l.PayerIsA {
			flag.SetInt64(1)
		}
		e.tail = append(e.tail, word(flag.Bytes())...)
	}
	return pos
}

// CheckpointCalldata builds a call to ChannelManagerV2.checkpoint.
//
// Exported so it can be tested against the contract's own ABI decoding rather
// than only against itself.
func CheckpointCalldata(ch *Channel) ([]byte, error) {
	if !ch.Latest.Complete() {
		return nil, ErrNothingToSubmit
	}
	st := ch.Latest.State

	e := &abiEncoder{}
	// CheckpointArgs is a STATIC struct, so it is inlined in the head rather
	// than referenced by offset. Getting this wrong shifts every later
	// parameter and the contract decodes garbage.
	e.fixed(st.Channel)
	e.u64(st.Nonce)
	e.u256(st.BalanceA)
	e.u256(st.BalanceB)
	e.u256(st.WithdrawA)
	e.u256(st.WithdrawB)

	locksSlot := e.offset()
	sigASlot := e.offset()
	sigBSlot := e.offset()

	locksPos := e.encodeLocks(st.Pending)
	sigAPos := e.encodeBytes(ch.Latest.SigA)
	sigBPos := e.encodeBytes(ch.Latest.SigB)

	e.patch(locksSlot, locksPos)
	e.patch(sigASlot, sigAPos)
	e.patch(sigBSlot, sigBPos)

	return append(append([]byte{}, selCheckpoint...), e.bytes()...), nil
}

// CloseCooperativeCalldata builds a call to ChannelManagerV2.closeCooperative.
func CloseCooperativeCalldata(ch *Channel) ([]byte, error) {
	if !ch.Latest.Complete() {
		return nil, ErrNothingToSubmit
	}
	st := ch.Latest.State
	if len(st.Pending) > 0 {
		return nil, ErrLocksUnresolved
	}

	e := &abiEncoder{}
	e.fixed(st.Channel)
	e.u64(st.Nonce)
	e.u256(st.BalanceA)
	e.u256(st.BalanceB)
	sigASlot := e.offset()
	sigBSlot := e.offset()
	sigAPos := e.encodeBytes(ch.Latest.SigA)
	sigBPos := e.encodeBytes(ch.Latest.SigB)
	e.patch(sigASlot, sigAPos)
	e.patch(sigBSlot, sigBPos)

	return append(append([]byte{}, selCloseCooperative...), e.bytes()...), nil
}

// ClaimLockCalldata builds a call to ChannelManagerV2.claimLock.
func ClaimLockCalldata(id [32]byte, locks []HTLC, index int, preimage [32]byte) []byte {
	e := &abiEncoder{}
	e.fixed(id)
	locksSlot := e.offset()
	e.u256(big.NewInt(int64(index)))
	e.fixed(preimage)
	locksPos := e.encodeLocks(locks)
	e.patch(locksSlot, locksPos)
	return append(append([]byte{}, selClaimLock...), e.bytes()...)
}

// ExpireLockCalldata builds a call to ChannelManagerV2.expireLock.
func ExpireLockCalldata(id [32]byte, locks []HTLC, index int) []byte {
	e := &abiEncoder{}
	e.fixed(id)
	locksSlot := e.offset()
	e.u256(big.NewInt(int64(index)))
	locksPos := e.encodeLocks(locks)
	e.patch(locksSlot, locksPos)
	return append(append([]byte{}, selExpireLock...), e.bytes()...)
}

// ---- sending -----------------------------------------------------------------

// TxSender puts signed calldata on chain and returns its hash.
//
// The narrowest possible seam. Key management, gas pricing, nonce handling and
// replacement are all behind it — decisions an operator makes once, not
// decisions settlement should be making per payout.
type TxSender interface {
	Send(ctx context.Context, to Address, data []byte) (string, error)
}

// RPCChainWriter builds calldata and hands it to a TxSender.
type RPCChainWriter struct {
	Sender TxSender
}

// NewRPCChainWriter wires one.
func NewRPCChainWriter(sender TxSender) *RPCChainWriter {
	return &RPCChainWriter{Sender: sender}
}

func (w *RPCChainWriter) send(ctx context.Context, contract Address, data []byte) (string, error) {
	if w.Sender == nil {
		return "", ErrWriterNotWired
	}
	return w.Sender.Send(ctx, contract, data)
}

func (w *RPCChainWriter) Checkpoint(ctx context.Context, contract Address, ch *Channel) (string, error) {
	data, err := CheckpointCalldata(ch)
	if err != nil {
		return "", err
	}
	return w.send(ctx, contract, data)
}

func (w *RPCChainWriter) CloseCooperative(ctx context.Context, contract Address, ch *Channel) (string, error) {
	data, err := CloseCooperativeCalldata(ch)
	if err != nil {
		return "", err
	}
	return w.send(ctx, contract, data)
}

func (w *RPCChainWriter) ClaimLock(ctx context.Context, contract Address, id [32]byte,
	locks []HTLC, index int, preimage [32]byte) (string, error) {
	return w.send(ctx, contract, ClaimLockCalldata(id, locks, index, preimage))
}

func (w *RPCChainWriter) ExpireLock(ctx context.Context, contract Address, id [32]byte,
	locks []HTLC, index int) (string, error) {
	return w.send(ctx, contract, ExpireLockCalldata(id, locks, index))
}

// ---- a sender that refuses to exist without a key ----------------------------

// RawTxSender submits pre-signed transactions through eth_sendRawTransaction.
//
// Signing is NOT implemented here. This node has a wallet elsewhere
// (internal/facilitation) and choosing which key pays for settlement is an
// operator decision with real consequences, so the signing function is injected
// rather than assumed. Without one this refuses to send, which is the correct
// failure: a settlement worker that silently cannot pay is worse than one that
// says so.
type RawTxSender struct {
	Endpoint string
	Client   *http.Client
	// SignTx turns a call into a signed raw transaction. Supplied by whatever
	// owns the key.
	SignTx func(ctx context.Context, to Address, data []byte) ([]byte, error)

	mu sync.Mutex
}

// NewRawTxSender builds one with a sane timeout.
func NewRawTxSender(endpoint string, sign func(context.Context, Address, []byte) ([]byte, error)) *RawTxSender {
	return &RawTxSender{
		Endpoint: endpoint,
		Client:   &http.Client{Timeout: 30 * time.Second},
		SignTx:   sign,
	}
}

func (s *RawTxSender) Send(ctx context.Context, to Address, data []byte) (string, error) {
	if s.SignTx == nil {
		return "", ErrNoSigningKey
	}
	// Serialised: two settlements racing would build two transactions from one
	// account nonce, and the second would be dropped as a replacement.
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := s.SignTx(ctx, to, data)
	if err != nil {
		return "", err
	}

	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", ID: 1, Method: "eth_sendRawTransaction",
		Params: []any{"0x" + hex.EncodeToString(raw)},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrChainUnreachable, err)
	}
	defer resp.Body.Close()

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("%w: %v", ErrChainUnreachable, err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("chainwriter: rejected: %s", out.Error.Message)
	}
	return out.Result, nil
}

// ---- a writer for tests --------------------------------------------------------

// FakeChainWriter records what would have been sent, and can be told to fail.
//
// In the package rather than a test file because the payout tests, the
// coordinator tests and any future settlement test all want the same one.
type FakeChainWriter struct {
	mu sync.Mutex
	// Sent is every call made, in order.
	Sent []FakeTx
	// FailWith, when set, makes every call fail. For the broadcast-failed path.
	FailWith error
	// OnSend, when set, runs before returning — the hook for "broadcast
	// succeeded and then the node died".
	OnSend func(FakeTx)
	// Chain, when set, is updated to reflect what the call would have done, so
	// a test can watch the worker converge against a moving chain.
	Chain *FakeChain
	next  int
}

// FakeTx is one recorded call.
type FakeTx struct {
	Op      string
	Channel [32]byte
	Nonce   uint64
	Hash    string
}

func (f *FakeChainWriter) record(op string, id [32]byte, nonce uint64) (string, error) {
	f.mu.Lock()
	if f.FailWith != nil {
		err := f.FailWith
		f.mu.Unlock()
		return "", err
	}
	f.next++
	tx := FakeTx{Op: op, Channel: id, Nonce: nonce, Hash: fmt.Sprintf("0x%064x", f.next)}
	f.Sent = append(f.Sent, tx)
	hook, chain := f.OnSend, f.Chain
	f.mu.Unlock()

	// The chain moves as the contract would, so a worker reading it afterwards
	// sees what really happened rather than what it hoped.
	if chain != nil {
		chain.mu.Lock()
		if occ, ok := chain.Channels[id]; ok {
			switch op {
			case "closeCooperative":
				occ.Status = StatusSettled
			case "checkpoint":
				// The channel stays OPEN — the whole point of a checkpoint.
				occ.Status = StatusOpen
			}
			chain.Channels[id] = occ
		}
		chain.mu.Unlock()
	}
	if hook != nil {
		hook(tx)
	}
	return tx.Hash, nil
}

func (f *FakeChainWriter) Checkpoint(_ context.Context, _ Address, ch *Channel) (string, error) {
	return f.record("checkpoint", ch.ID, ch.Latest.State.Nonce)
}

func (f *FakeChainWriter) CloseCooperative(_ context.Context, _ Address, ch *Channel) (string, error) {
	if !ch.Latest.Complete() {
		return "", ErrNothingToSubmit
	}
	return f.record("closeCooperative", ch.ID, ch.Latest.State.Nonce)
}

func (f *FakeChainWriter) ClaimLock(_ context.Context, _ Address, id [32]byte,
	_ []HTLC, _ int, _ [32]byte) (string, error) {
	return f.record("claimLock", id, 0)
}

func (f *FakeChainWriter) ExpireLock(_ context.Context, _ Address, id [32]byte,
	_ []HTLC, _ int) (string, error) {
	return f.record("expireLock", id, 0)
}

// Calls returns a copy of what was sent.
func (f *FakeChainWriter) Calls() []FakeTx {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FakeTx(nil), f.Sent...)
}
