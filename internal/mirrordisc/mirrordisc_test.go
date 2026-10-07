package mirrordisc

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type ident struct {
	key crypto.PrivKey
	id  peer.ID
}

func newIdent(t *testing.T) *ident {
	t.Helper()
	k, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(k.GetPublic())
	if err != nil {
		t.Fatal(err)
	}
	return &ident{key: k, id: id}
}

func (i *ident) ID() string                    { return i.id.String() }
func (i *ident) PublicKey() ([]byte, error)    { return crypto.MarshalPublicKey(i.key.GetPublic()) }
func (i *ident) Sign(m []byte) ([]byte, error) { return i.key.Sign(m) }

const origin = "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdea.key.axon"
const mirrorAddr = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.key.axon"

func signed(t *testing.T, id *ident, mutate func(*MirrorRecord)) (string, []byte, MirrorRecord) {
	t.Helper()
	rec := MirrorRecord{
		Origin: origin, MirrorAddr: mirrorAddr,
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
		Sequence: 1,
	}
	if mutate != nil {
		mutate(&rec)
	}
	rec, err := Sign(id, rec)
	if err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return MirrorDHTKey(rec.Origin, rec.NodeID), value, rec
}

func TestSignAndValidate(t *testing.T) {
	id := newIdent(t)
	key, value, rec := signed(t, id, nil)
	if rec.NodeID != id.ID() || rec.RecordType != "mirror" {
		t.Fatalf("Sign did not fill identity fields: %+v", rec)
	}
	if err := (DHTValidator{}).Validate(key, value); err != nil {
		t.Fatalf("a freshly signed record failed validation: %v", err)
	}
}

func TestRejectsWrongKey(t *testing.T) {
	id := newIdent(t)
	_, value, rec := signed(t, id, nil)
	// Right node, wrong origin in the key.
	wrongOrigin := MirrorDHTKey("someoneelse.key.axon", rec.NodeID)
	if err := (DHTValidator{}).Validate(wrongOrigin, value); err == nil {
		t.Fatal("record validated under a key for a different origin")
	}
	// Right origin, wrong node in the key.
	wrongNode := MirrorDHTKey(rec.Origin, "12D3KooWdifferent")
	if err := (DHTValidator{}).Validate(wrongNode, value); err == nil {
		t.Fatal("record validated under a key for a different node")
	}
}

func TestRejectsExpiredAndOverLong(t *testing.T) {
	id := newIdent(t)
	_, expValue, _ := signed(t, id, func(r *MirrorRecord) {
		r.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()
		r.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	})
	key := MirrorDHTKey(origin, id.ID())
	if err := (DHTValidator{}).Validate(key, expValue); err == nil {
		t.Fatal("expired record validated")
	}
	_, longValue, _ := signed(t, id, func(r *MirrorRecord) {
		r.IssuedAt = time.Now().Unix()
		r.ExpiresAt = time.Now().Add(48 * time.Hour).Unix() // beyond RecordTTL
	})
	if err := (DHTValidator{}).Validate(key, longValue); err == nil {
		t.Fatal("over-long record validated")
	}
}

func TestRejectsTamper(t *testing.T) {
	id := newIdent(t)
	key, value, rec := signed(t, id, nil)
	// Tamper the mirror address after signing.
	rec.MirrorAddr = "evilevilevilevilevilevilevilevilevilevilevilevilevilevi.key.axon"
	tampered, _ := json.Marshal(rec)
	if err := (DHTValidator{}).Validate(key, tampered); err == nil {
		t.Fatal("a tampered record validated")
	}
	// Control: the untampered value still validates.
	if err := (DHTValidator{}).Validate(key, value); err != nil {
		t.Fatalf("control value failed: %v", err)
	}
}

func TestSelectPrefersHighestSequence(t *testing.T) {
	id := newIdent(t)
	_, v1, _ := signed(t, id, func(r *MirrorRecord) { r.Sequence = 1 })
	_, v9, _ := signed(t, id, func(r *MirrorRecord) { r.Sequence = 9 })
	idx, err := (DHTValidator{}).Select("", [][]byte{v1, v9})
	if err != nil || idx != 1 {
		t.Fatalf("Select picked %d (err %v), want index 1 (seq 9)", idx, err)
	}
}

func TestOriginTagStableAndCaseInsensitive(t *testing.T) {
	a := OriginTag(origin)
	b := OriginTag(strings.ToUpper(origin))
	if a != b {
		t.Fatalf("OriginTag is case-sensitive: %s != %s", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("OriginTag length = %d, want 32", len(a))
	}
	if OriginTag("other.key.axon") == a {
		t.Fatal("different origins collide")
	}
}
