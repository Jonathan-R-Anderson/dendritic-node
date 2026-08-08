package p2p

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// SHARD RECALL OVER THE PEER PROTOCOL
// ===================================
// /syndichan/storage/1.0.0 dispatched four operations -- have, get,
// pof-challenge, store -- and answered "unsupported operation" to everything
// else. A shard that reached a peer could therefore never be taken back, so a
// purge on the site was local-only and honestly reported the remote copies as
// unreachable. This file adds the fifth verb.
//
// AUTHORISATION IS THE ENTIRE PROBLEM
// -----------------------------------
// An unauthenticated delete verb is strictly worse than no delete verb: any peer
// on the network could wipe every other peer's disk one shard at a time, and
// `have` already tells an attacker exactly which shard ids to ask for. So the
// verb reuses the ONLY authority a peer already trusts -- the coordinator's
// ed25519 key, the same key it verifies before accepting a `store`. Nothing new
// has to be distributed, pinned, or rotated: a node that can be written to can
// already be revoked from, at zero additional trust cost.
//
// WHY NOT JUST REUSE THE LEASE
// ----------------------------
// Because a lease is a capability to WRITE and its signed message covers exactly
// (version, object_id, shard_id, size, recipient, expires_at) -- the same fields
// a revocation needs. Signing a revocation with the lease's domain prefix would
// make every lease the coordinator has ever issued a valid delete token for that
// shard on that peer, and every lease travels over the wire in the clear inside
// a store frame. Anyone who ever observed a placement would hold a delete token
// for it.
//
// So a revocation is a DIFFERENT token:
//
//   - a different domain prefix, "syndichan-storage-revocation-v1";
//   - a different field set (issued_at and a nonce; no size), so the two
//     messages cannot collide even if a future refactor got the prefix wrong;
//   - a REQUIRED recipient. A lease may name an empty recipient, which means
//     "any peer may accept these bytes". That is safe for a write and unsafe for
//     a delete, so validateRevocation refuses an empty recipient outright: a
//     token minted against peer A is inert at peer B.
//
// WHAT A HOLDER CHECKS, IN ORDER
//   - the token is version 1 and signed by the coordinator key it already pins;
//   - object_id and shard_id equal the request header's, so a token for shard A
//     cannot delete shard B;
//   - recipient is this node and nothing else;
//   - it has not expired, and its expiry is not absurdly far out;
//   - and only then, whether the shard may actually go (store.DeleteRemoteShard,
//     which refuses bytes another manifest still references).
//
// cacheOnly is deliberately NOT consulted. A cache-only node refuses new stores,
// but it can still be holding shards it accepted before the operator set that
// flag, and refusing to delete them because it refuses to accept new ones is
// exactly backwards.

// revocationURL is the coordinator endpoint that mints delete tokens. A var, so
// tests can point it at an httptest server, exactly like leaseURL.
var revocationURL = "https://syndichan.org/api/v1/storage/revocations"

const (
	// maxRevocationBatch bounds one coordinator request. A 40 MB object is 39
	// chunks x 9 shards x however many holders each, so the token count runs to
	// hundreds; asking for them one at a time would blow through the
	// coordinator's per-minute limit and take an hour of round trips.
	maxRevocationBatch = 128
	// recallConcurrency bounds simultaneous delete streams. One operation per
	// stream and a cold I2P dial of up to two minutes means sequential recall of
	// a large object takes hours; unbounded concurrency means hundreds of
	// simultaneous I2P tunnels.
	recallConcurrency = 8
	recallInterval    = 10 * time.Minute
	// recallCooldown keeps one object from being retried in a tight loop while
	// a holder is down. Shorter than the dispersal cooldown: a recall is an
	// operator-visible obligation, not background maintenance.
	recallCooldown = 2 * time.Minute
	recallBatch    = 20
)

// Revocation is a coordinator-signed authority to DELETE one shard from one
// peer. Deliberately not a Lease with a flag: the two are separate token types
// with separate signed messages so neither can be replayed as the other.
type Revocation struct {
	Version   int    `json:"version"`
	ObjectID  string `json:"object_id"`
	ShardID   string `json:"shard_id"`
	Recipient string `json:"recipient"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type revocationRequestShard struct {
	ShardID   string `json:"shard_id"`
	Recipient string `json:"recipient"`
}

type revocationRequest struct {
	Version   int                      `json:"version"`
	Requester string                   `json:"requester"`
	ObjectID  string                   `json:"object_id"`
	Shards    []revocationRequestShard `json:"shards"`
	Timestamp int64                    `json:"timestamp"`
	Nonce     string                   `json:"nonce"`
}

type revocationResponse struct {
	Revocations []Revocation `json:"revocations"`
}

// revocationMessage is the exact byte sequence the coordinator signs. Its Python
// twin is _revocation_message in backend/services/storage_coordination.py and
// the two must stay byte-identical.
func revocationMessage(revocation Revocation) []byte {
	return []byte(fmt.Sprintf(
		"syndichan-storage-revocation-v1\n%d\n%s\n%s\n%s\n%d\n%d\n%s",
		revocation.Version, revocation.ObjectID, revocation.ShardID,
		revocation.Recipient, revocation.IssuedAt, revocation.ExpiresAt,
		revocation.Nonce,
	))
}

// validateRevocation is the holder-side check. Mirrors validateLease, with the
// two deliberate differences documented at the top of this file: an empty
// recipient is refused, and the message it verifies is a different one.
func (n *Node) validateRevocation(revocation *Revocation, header requestHeader) error {
	if revocation == nil || revocation.Version != 1 {
		return errors.New("coordinator revocation required")
	}
	if revocation.ObjectID != header.ObjectID || revocation.ShardID != header.ShardID {
		return errors.New("revocation does not match the shard requested")
	}
	if len(revocation.ShardID) != 64 {
		return errors.New("invalid shard ID")
	}
	// A lease may be recipient-less. A revocation may not: without this, one
	// token would delete the same shard from every peer that holds it, and any
	// peer that saw it could replay it against all the others.
	if revocation.Recipient == "" || revocation.Recipient != n.host.ID().String() {
		return errors.New("revocation was issued to another node")
	}
	if len(revocation.Nonce) < 16 || len(revocation.Nonce) > 128 {
		return errors.New("invalid revocation nonce")
	}
	now := time.Now().Unix()
	if revocation.IssuedAt > now+300 {
		return errors.New("revocation is issued in the future")
	}
	if revocation.ExpiresAt <= now || revocation.ExpiresAt > now+3600 {
		return errors.New("revocation is expired or excessively long")
	}
	signature, err := base64.RawStdEncoding.DecodeString(revocation.Signature)
	if err != nil {
		return errors.New("invalid revocation signature encoding")
	}
	n.keyMu.RLock()
	key := append(ed25519.PublicKey(nil), n.coordKey...)
	n.keyMu.RUnlock()
	if len(key) != ed25519.PublicKeySize ||
		!ed25519.Verify(key, revocationMessage(*revocation), signature) {
		return errors.New("invalid coordinator revocation signature")
	}
	return nil
}

// handleDelete serves the delete verb. Every branch writes exactly one response
// frame, because the caller distinguishes "this peer refused" from "this peer
// never answered" by whether a frame came back at all.
func (n *Node) handleDelete(stream io.Writer, header requestHeader) {
	if err := n.validateRevocation(header.Revocation, header); err != nil {
		writeJSONFrame(stream, responseHeader{Refused: true, Error: err.Error()})
		return
	}
	removed, err := n.store.DeleteRemoteShard(header.ObjectID, header.ShardID)
	if err != nil {
		writeJSONFrame(stream, responseHeader{Refused: true, Error: err.Error()})
		return
	}
	if !removed {
		// Answered, authorised, and there was nothing here. Terminal and true:
		// the owner can stop chasing this peer for this shard.
		writeJSONFrame(stream, responseHeader{OK: true, Present: false})
		return
	}
	writeJSONFrame(stream, responseHeader{OK: true, Present: true, Deleted: true})
}

// recallFromPeer asks one peer to drop one shard and returns the store-level
// outcome constant, never an error: "the peer said no" and "the peer never
// answered" are both results, and collapsing them into one error would lose the
// distinction the purge report is built on.
func (n *Node) recallFromPeer(ctx context.Context, target peer.ID, revocation Revocation) (string, string) {
	stream, err := n.host.NewStream(ctx, target, ProtocolID)
	if err != nil {
		return store.RecallUnreachable, "could not open a stream: " + err.Error()
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{
		Operation: "delete", ObjectID: revocation.ObjectID,
		ShardID: revocation.ShardID, Revocation: &revocation,
	}); err != nil {
		return store.RecallUnreachable, "could not send the request: " + err.Error()
	}
	var response responseHeader
	if err := readJSONFrame(bufio.NewReader(stream), &response); err != nil {
		return store.RecallUnreachable, "no answer: " + err.Error()
	}
	switch {
	case response.OK && response.Deleted:
		return store.RecallDeleted, "the holder removed the shard and blocklisted it"
	case response.OK:
		return store.RecallAbsent, "the holder answered and no longer had the shard"
	default:
		detail := response.Error
		if detail == "" {
			detail = "refused without a reason"
		}
		return store.RecallRefused, detail
	}
}

// requestRevocations asks the coordinator to sign delete tokens for a batch of
// (shard, holder) pairs of ONE object.
//
// Batched on purpose. One token per shard per holder against a per-request
// endpoint would run to hundreds of HTTP calls for a large object and hit the
// coordinator's per-minute limit, which is per worker process and therefore
// lower in practice than its nominal value.
func (n *Node) requestRevocations(ctx context.Context, objectID string, shards []revocationRequestShard) ([]Revocation, error) {
	if len(shards) == 0 {
		return nil, nil
	}
	if len(shards) > maxRevocationBatch {
		shards = shards[:maxRevocationBatch]
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	payload := revocationRequest{
		Version: 1, Requester: n.host.ID().String(), ObjectID: objectID,
		Shards: shards, Timestamp: time.Now().UTC().Unix(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	privateKey := n.host.Peerstore().PrivKey(n.host.ID())
	if privateKey == nil {
		return nil, errors.New("node identity unavailable")
	}
	signature, err := privateKey.Sign(body)
	if err != nil {
		return nil, err
	}
	newRequest := func() (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, revocationURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("X-Syndichan-Node", n.host.ID().String())
		request.Header.Set("X-Syndichan-Signature", base64.RawStdEncoding.EncodeToString(signature))
		return request, nil
	}
	request, err := newRequest()
	if err != nil {
		return nil, err
	}
	response, err := n.http.Do(request)
	if err != nil && n.directHTTP != nil {
		// Same I2P-proxy-then-direct fallback as requestLease, for the same
		// reason: the outproxy is absent in the container deployment, and
		// without the fallback nothing would ever be recalled there.
		if direct, rerr := newRequest(); rerr == nil {
			if dresp, derr := n.directHTTP.Do(direct); derr == nil {
				response, err = dresp, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("revocation service returned HTTP %d", response.StatusCode)
	}
	var decoded revocationResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded.Revocations, nil
}

type recallTarget struct {
	shardID string
	peerID  string
	target  peer.ID
}

// RecallObject drives one pass of a recall tombstone: mint tokens, ask each
// holder, record every answer, and drop the tombstone once every holder has
// given a terminal one.
//
// shardFilter, when non-empty, restricts the pass to specific shard ids -- that
// is the per-shard delete the admin page offers. An empty filter means the whole
// object.
//
// Returns the tombstone AS IT STANDS AFTER the pass, so the caller reports what
// happened rather than what was asked for.
func (n *Node) RecallObject(ctx context.Context, objectID string, shardFilter map[string]bool) (*store.RecallRecord, error) {
	record, err := n.store.LoadRecall(objectID)
	if err != nil {
		return nil, err
	}
	_ = n.store.MarkRecallAttempt(objectID)

	var targets []recallTarget
	// Deduplicated by (shard, peer): one object can contain the same shard id
	// more than once, since a chunk of constant bytes erasure-codes into
	// identical data shards. Two streams asking the same peer to delete the same
	// bytes would have the second one answer "absent" and look like a partial
	// failure.
	queued := map[string]bool{}
	for _, shard := range record.Shards {
		if len(shardFilter) > 0 && !shardFilter[shard.ShardID] {
			continue
		}
		for _, holder := range shard.Holders {
			if holder.State == store.RecallDeleted || holder.State == store.RecallAbsent {
				continue
			}
			decoded, err := peer.Decode(holder.PeerID)
			if err != nil {
				_ = n.store.RecordRecallOutcome(objectID, shard.ShardID, holder.PeerID,
					store.RecallRefused, "ledger holds an unparseable peer id")
				continue
			}
			if decoded == n.host.ID() {
				// This node's own copy is handled by the local delete path.
				_ = n.store.RecordRecallOutcome(objectID, shard.ShardID, holder.PeerID,
					store.RecallAbsent, "this node is the owner, not a remote holder")
				continue
			}
			pair := shard.ShardID + "\x00" + holder.PeerID
			if queued[pair] {
				continue
			}
			queued[pair] = true
			targets = append(targets, recallTarget{shardID: shard.ShardID, peerID: holder.PeerID, target: decoded})
		}
	}
	if len(targets) == 0 {
		return n.finishRecall(objectID)
	}

	// Tokens first, in batches, so a coordinator outage costs one failed pass
	// rather than a half-recalled object with no record of which half.
	tokens := make(map[string]Revocation, len(targets))
	for start := 0; start < len(targets); start += maxRevocationBatch {
		end := start + maxRevocationBatch
		if end > len(targets) {
			end = len(targets)
		}
		batch := make([]revocationRequestShard, 0, end-start)
		for _, item := range targets[start:end] {
			batch = append(batch, revocationRequestShard{ShardID: item.shardID, Recipient: item.peerID})
		}
		granted, err := n.requestRevocations(ctx, objectID, batch)
		if err != nil {
			n.logger.Printf("recall: coordinator refused revocations for %s: %v", objectID, err)
			for _, item := range targets[start:end] {
				// NOT recorded as gone. A coordinator that is down is a retry,
				// and the whole point of the tombstone is that it survives to
				// be retried.
				_ = n.store.RecordRecallOutcome(objectID, item.shardID, item.peerID,
					store.RecallUnreachable, "no delete token: "+err.Error())
			}
			continue
		}
		for _, token := range granted {
			tokens[token.ShardID+"\x00"+token.Recipient] = token
		}
	}

	var wait sync.WaitGroup
	slots := make(chan struct{}, recallConcurrency)
	for _, item := range targets {
		token, ok := tokens[item.shardID+"\x00"+item.peerID]
		if !ok {
			continue
		}
		wait.Add(1)
		slots <- struct{}{}
		go func(item recallTarget, token Revocation) {
			defer wait.Done()
			defer func() { <-slots }()
			state, detail := n.recallFromPeer(ctx, item.target, token)
			_ = n.store.RecordRecallOutcome(objectID, item.shardID, item.peerID, state, detail)
			if state == store.RecallDeleted || state == store.RecallAbsent {
				// The PLACEMENT ledger has to stop naming this peer as a holder
				// too. Without this the ledger keeps claiming a durability that
				// no longer exists -- and for an object that still exists (a
				// per-shard recall, not a purge) repair would never notice the
				// deficit it was just asked to create.
				//
				// os.ErrNotExist here simply means the object was deleted and
				// its placement row already retired, which is the normal case.
				_ = n.store.DropShardHolder(objectID, item.shardID, item.peerID)
			}
		}(item, token)
	}
	wait.Wait()
	return n.finishRecall(objectID)
}

// finishRecall reloads the tombstone and drops it only when every holder has
// answered terminally. An unreachable holder is never terminal: recording it as
// gone would make the ledger lie in the dangerous direction.
func (n *Node) finishRecall(objectID string) (*store.RecallRecord, error) {
	record, err := n.store.LoadRecall(objectID)
	if err != nil {
		return nil, err
	}
	if record.Resolved() {
		_ = n.store.DropRecall(objectID)
	}
	return record, nil
}

// RecallForKey captures a tombstone for bucket/key (from the placement ledger,
// while it still exists) and runs a pass. This is the entry point the site's
// admin purge calls through the gateway.
func (n *Node) RecallForKey(ctx context.Context, bucket, key string, shardFilter map[string]bool, reason string) (*store.RecallRecord, error) {
	objectID, err := n.store.ObjectIDForKey(bucket, key)
	if err != nil {
		return nil, err
	}
	return n.RecallObjectID(ctx, objectID, shardFilter, reason)
}

// RecallObjectID captures then recalls, by object id.
func (n *Node) RecallObjectID(ctx context.Context, objectID string, shardFilter map[string]bool, reason string) (*store.RecallRecord, error) {
	if _, err := n.store.CaptureRecall(objectID, reason); err != nil {
		return nil, err
	}
	if _, err := n.store.LoadRecall(objectID); err != nil {
		// Nothing was ever confirmed on a peer, so there is nothing to recall.
		// An empty record is the honest answer, not an error.
		return &store.RecallRecord{ObjectID: objectID}, nil
	}
	return n.RecallObject(ctx, objectID, shardFilter)
}

// RecallStored retries outstanding tombstones in the background, so a holder
// that was down when the purge ran is still chased afterwards.
func (n *Node) RecallStored(ctx context.Context) {
	for {
		timer := time.NewTimer(recallInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		n.recallOnce(ctx)
	}
}

func (n *Node) recallOnce(ctx context.Context) {
	if len(n.host.Network().Peers()) == 0 {
		return
	}
	pending, err := n.store.PendingRecalls(recallBatch, recallCooldown)
	if err != nil || len(pending) == 0 {
		return
	}
	for _, record := range pending {
		if ctx.Err() != nil {
			return
		}
		after, err := n.RecallObject(ctx, record.ObjectID, nil)
		if err != nil || after == nil {
			continue
		}
		counts := after.Counts()
		n.logger.Printf(
			"recall: %s (%s/%s) deleted=%d absent=%d refused=%d unreachable=%d pending=%d",
			record.ObjectID, record.Bucket, record.Key,
			counts[store.RecallDeleted], counts[store.RecallAbsent],
			counts[store.RecallRefused], counts[store.RecallUnreachable],
			counts[store.RecallPending])
	}
}
