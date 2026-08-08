package p2p

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// The delete verb is the one operation on this protocol that DESTROYS data, so
// the tests here are about who is allowed to invoke it rather than about whether
// it works. An unauthenticated delete verb would be strictly worse than the
// "unsupported operation" it replaced: `have` already tells any peer which shard
// ids a node holds, so a forgeable delete would let one peer empty every other
// peer's disk.

type recallHarness struct {
	source, target *Node
	sourceStore    *store.Store
	targetStore    *store.Store
	coordinator    ed25519.PrivateKey
	ctx            context.Context
}

func newRecallHarness(t *testing.T) *recallHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	openStorage := func() (*store.Store, string) {
		dir := t.TempDir()
		storage, err := store.Open(dir+"/storage", 3, 2, 64<<10, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { storage.Close() })
		return storage, dir
	}
	sourceStore, sourceDir := openStorage()
	targetStore, targetDir := openStorage()
	logger := log.New(io.Discard, "", 0)
	source, err := openNode(ctx, sourceDir, []string{"/ip4/127.0.0.1/tcp/0"}, sourceStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	target, err := openNode(ctx, targetDir, []string{"/ip4/127.0.0.1/tcp/0"}, targetStore, logger, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	if err := source.host.Connect(ctx, peer.AddrInfo{ID: target.host.ID(), Addrs: target.host.Addrs()}); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	source.coordKey = publicKey
	target.coordKey = publicKey
	return &recallHarness{
		source: source, target: target, sourceStore: sourceStore,
		targetStore: targetStore, coordinator: privateKey, ctx: ctx,
	}
}

// plantShard puts bytes on the target as a shard held on somebody else's behalf,
// which is exactly the state a placed shard leaves a volunteer node in.
func (h *recallHarness) plantShard(t *testing.T, objectID string, value []byte) string {
	t.Helper()
	digest := sha256.Sum256(value)
	shardID := hex.EncodeToString(digest[:])
	err := h.targetStore.PutRemoteShard(store.RemoteShard{
		ID: shardID, ObjectID: objectID, Size: int64(len(value)),
	}, value)
	if err != nil {
		t.Fatal(err)
	}
	return shardID
}

func (h *recallHarness) sign(revocation Revocation) Revocation {
	revocation.Signature = base64.RawStdEncoding.EncodeToString(
		ed25519.Sign(h.coordinator, revocationMessage(revocation)))
	return revocation
}

func (h *recallHarness) token(objectID, shardID string) Revocation {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	return h.sign(Revocation{
		Version: 1, ObjectID: objectID, ShardID: shardID,
		Recipient: h.target.host.ID().String(),
		IssuedAt:  time.Now().Unix(), ExpiresAt: time.Now().Unix() + 300,
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
	})
}

// ask sends one delete frame and returns the peer's answer. A nil error with
// Refused set is a peer that said no; an error is a peer that said nothing, and
// the two must never be confused.
func (h *recallHarness) ask(t *testing.T, header requestHeader) responseHeader {
	t.Helper()
	stream, err := h.source.host.NewStream(h.ctx, h.target.host.ID(), ProtocolID)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(20 * time.Second))
	if err := writeJSONFrame(stream, header); err != nil {
		t.Fatal(err)
	}
	var response responseHeader
	if err := readJSONFrame(bufio.NewReader(stream), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func (h *recallHarness) stillHeld(shardID string) bool {
	_, err := h.targetStore.ReadShard(shardID)
	return err == nil
}

// A delete with no token at all, and a delete with a token signed by somebody
// who is not the coordinator, are both refused -- and the bytes survive.
func TestDeleteWithoutValidAuthorisationIsRefused(t *testing.T) {
	h := newRecallHarness(t)
	objectID := stringOf('a', 64)
	shardID := h.plantShard(t, objectID, bytes.Repeat([]byte("recall me"), 64))

	unauthorised := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID,
	})
	if unauthorised.OK || !unauthorised.Refused {
		t.Fatalf("an unauthorised delete was not refused: %#v", unauthorised)
	}
	if !h.stillHeld(shardID) {
		t.Fatal("an unauthorised delete removed the shard")
	}

	// Correctly shaped, correctly bound, signed by the wrong key.
	_, impostor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := h.token(objectID, shardID)
	forged.Signature = base64.RawStdEncoding.EncodeToString(
		ed25519.Sign(impostor, revocationMessage(forged)))
	answer := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &forged,
	})
	if answer.OK || !answer.Refused {
		t.Fatalf("a forged revocation was accepted: %#v", answer)
	}
	if !h.stillHeld(shardID) {
		t.Fatal("a forged revocation removed the shard")
	}

	// And the genuine article works, so the refusals above are about authority
	// and not about the verb being broken.
	valid := h.token(objectID, shardID)
	granted := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &valid,
	})
	if !granted.OK || !granted.Deleted {
		t.Fatalf("a valid revocation was not honoured: %#v", granted)
	}
	if h.stillHeld(shardID) {
		t.Fatal("the shard survived a valid revocation")
	}
}

// A token is bound to ONE shard. Presenting it for a different shard must not
// work, whichever way round the mismatch is arranged -- neither by lying in the
// header nor by lying in the token.
func TestRevocationForOneShardCannotDeleteAnother(t *testing.T) {
	h := newRecallHarness(t)
	objectID := stringOf('b', 64)
	victim := h.plantShard(t, objectID, bytes.Repeat([]byte("keep me"), 64))
	authorised := h.plantShard(t, objectID, bytes.Repeat([]byte("drop me"), 64))

	// The token names the shard it was issued for; the header asks for another.
	token := h.token(objectID, authorised)
	mismatch := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: victim, Revocation: &token,
	})
	if mismatch.OK || !mismatch.Refused {
		t.Fatalf("a token for another shard was accepted: %#v", mismatch)
	}
	if !h.stillHeld(victim) {
		t.Fatal("a token for another shard deleted the victim")
	}

	// Editing the token to name the victim breaks the signature, because the
	// shard id is inside the signed message.
	edited := token
	edited.ShardID = victim
	tampered := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: victim, Revocation: &edited,
	})
	if tampered.OK || !tampered.Refused {
		t.Fatalf("a tampered token was accepted: %#v", tampered)
	}
	if !h.stillHeld(victim) {
		t.Fatal("a tampered token deleted the victim")
	}
}

// Expiry, and the ceiling on expiry. A validly signed token that has run out is
// refused, and so is one whose expiry is absurdly far away -- otherwise a single
// leaked token is a permanent delete capability.
func TestExpiredRevocationIsRefused(t *testing.T) {
	h := newRecallHarness(t)
	objectID := stringOf('c', 64)
	shardID := h.plantShard(t, objectID, bytes.Repeat([]byte("expiry"), 64))

	expired := h.token(objectID, shardID)
	expired.ExpiresAt = time.Now().Unix() - 1
	expired = h.sign(expired)
	answer := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &expired,
	})
	if answer.OK || !answer.Refused {
		t.Fatalf("an expired revocation was accepted: %#v", answer)
	}
	if !h.stillHeld(shardID) {
		t.Fatal("an expired revocation deleted the shard")
	}

	eternal := h.token(objectID, shardID)
	eternal.ExpiresAt = time.Now().Unix() + 86400*365
	eternal = h.sign(eternal)
	forever := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &eternal,
	})
	if forever.OK || !forever.Refused {
		t.Fatalf("an eternal revocation was accepted: %#v", forever)
	}
	if !h.stillHeld(shardID) {
		t.Fatal("an eternal revocation deleted the shard")
	}
}

// A token minted for peer A is inert at peer B. This is why a revocation's
// recipient is REQUIRED where a lease's is optional: with an empty or foreign
// recipient, one observed token would delete the same shard everywhere.
func TestRevocationCannotBeReplayedAtAnotherPeer(t *testing.T) {
	h := newRecallHarness(t)
	objectID := stringOf('d', 64)
	shardID := h.plantShard(t, objectID, bytes.Repeat([]byte("replay"), 64))

	elsewhere := h.token(objectID, shardID)
	elsewhere.Recipient = h.source.host.ID().String()
	elsewhere = h.sign(elsewhere)
	answer := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &elsewhere,
	})
	if answer.OK || !answer.Refused {
		t.Fatalf("a token addressed to another peer was accepted: %#v", answer)
	}

	anyone := h.token(objectID, shardID)
	anyone.Recipient = ""
	anyone = h.sign(anyone)
	wildcard := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &anyone,
	})
	if wildcard.OK || !wildcard.Refused {
		t.Fatalf("a recipient-less token was accepted: %#v", wildcard)
	}
	if !h.stillHeld(shardID) {
		t.Fatal("a replayed token deleted the shard")
	}
}

// A lease and a revocation cover the same fields and are signed by the same key.
// If the revocation reused the lease's domain prefix, every lease ever issued --
// each of which travels in the clear inside a store frame -- would be a delete
// token. The two message encodings must not collide.
func TestLeaseIsNotAValidRevocation(t *testing.T) {
	h := newRecallHarness(t)
	objectID := stringOf('e', 64)
	shardID := h.plantShard(t, objectID, bytes.Repeat([]byte("domain"), 64))

	lease := Lease{
		Version: 1, ObjectID: objectID, ShardID: shardID, Size: 384,
		Recipient: h.target.host.ID().String(), ExpiresAt: time.Now().Unix() + 300,
	}
	leaseSignature := base64.RawStdEncoding.EncodeToString(
		ed25519.Sign(h.coordinator, leaseMessage(lease)))
	smuggled := Revocation{
		Version: 1, ObjectID: objectID, ShardID: shardID,
		Recipient: lease.Recipient, ExpiresAt: lease.ExpiresAt,
		IssuedAt: time.Now().Unix(), Nonce: "0123456789abcdef0123",
		Signature: leaseSignature,
	}
	answer := h.ask(t, requestHeader{
		Operation: "delete", ObjectID: objectID, ShardID: shardID, Revocation: &smuggled,
	})
	if answer.OK || !answer.Refused {
		t.Fatalf("a lease signature was accepted as a revocation: %#v", answer)
	}
	if !h.stillHeld(shardID) {
		t.Fatal("a lease signature deleted a shard")
	}

	// And the inverse: a revocation message must not verify as a lease.
	revocation := h.token(objectID, shardID)
	fakeLease := Lease{
		Version: 1, ObjectID: objectID, ShardID: shardID, Size: 384,
		Recipient: h.target.host.ID().String(), ExpiresAt: revocation.ExpiresAt,
		Signature: revocation.Signature,
	}
	if err := h.target.validateLease(&fakeLease, requestHeader{
		ObjectID: objectID, ShardID: shardID, Size: 384,
	}); err == nil {
		t.Fatal("a revocation signature verified as a storage lease")
	}
}

// A holder that answers "no" and a holder that never answers are different
// outcomes, and the recall client must report them differently -- the purge page
// prints one as refused and the other as unreachable, and both are true.
func TestRefusalAndSilenceAreDistinguishable(t *testing.T) {
	h := newRecallHarness(t)
	objectID := stringOf('f', 64)
	shardID := h.plantShard(t, objectID, bytes.Repeat([]byte("distinct"), 64))

	// Refusal: a token the holder will not honour (wrong recipient).
	refusable := h.token(objectID, shardID)
	refusable.Recipient = h.source.host.ID().String()
	refusable = h.sign(refusable)
	state, detail := h.source.recallFromPeer(h.ctx, h.target.host.ID(), refusable)
	if state != store.RecallRefused {
		t.Fatalf("expected a refusal, got %s (%s)", state, detail)
	}

	// Silence: a peer this node has never heard of and cannot dial.
	unreachableCtx, cancel := context.WithTimeout(h.ctx, 2*time.Second)
	defer cancel()
	stranger, err := peer.Decode("12D3KooWGRUts8ZckKrhVePMWnwLKrDMbYrgvXvJVwFHhPHu3EXV")
	if err != nil {
		t.Fatal(err)
	}
	state, detail = h.source.recallFromPeer(unreachableCtx, stranger, h.token(objectID, shardID))
	if state != store.RecallUnreachable {
		t.Fatalf("expected unreachable, got %s (%s)", state, detail)
	}
}
