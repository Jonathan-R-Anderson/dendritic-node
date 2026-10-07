// Package mirrordisc is decentralized discovery of availability mirrors. A
// mirror announces, in the Kademlia-over-AXON DHT, that it holds a copy of a
// given origin hidden service; a client that wants a site the origin is no
// longer serving finds the mirrors for it with one DHT lookup. There is no
// central directory: it reuses exactly the multi-provider scheme the DCS worker
// and gateway registries already use.
//
// Each mirror both PUTs a signed record under its own per-(origin,node) key and
// PROVIDEs a per-origin rendezvous CID, because Kademlia cannot list a namespace
// on its own. A client FindProviders(rendezvous(origin)) to enumerate the
// mirrors, then reads and verifies each one's record. The record is signed by
// the mirror's node identity and stored under a key derived from that identity,
// so a peer cannot announce a mirror on someone else's behalf, and it expires
// so a dead mirror disappears on its own.
package mirrordisc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// DHTMirrorNamespace is the DHT key namespace for mirror records.
const DHTMirrorNamespace = "rabbiit-mirror"

// RecordTTL bounds how long a mirror announcement is valid; republish before it.
const RecordTTL = time.Hour

// Signer is the local node identity (satisfied by *p2p.Node): ID is the peer id
// string, PublicKey is the marshalled libp2p public key, Sign signs with the
// node key.
type Signer interface {
	ID() string
	PublicKey() ([]byte, error)
	Sign([]byte) ([]byte, error)
}

// MirrorRecord is one mirror's signed announcement that it mirrors Origin.
type MirrorRecord struct {
	RecordType string `json:"record_type"` // always "mirror"
	Origin     string `json:"origin"`      // mirrored service, <56 base32>.key.axon
	MirrorAddr string `json:"mirror_addr"` // this mirror's own <56 base32>.key.axon
	NodeID     string `json:"node_id"`
	PublicKey  string `json:"public_key"` // base64 raw, marshalled libp2p pubkey
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Sequence   uint64 `json:"sequence"`
	Signature  string `json:"signature"`
}

// OriginTag is the stable per-origin component of the DHT key: a hex SHA-256 of
// the lowercased origin, so the key is bounded and contains no odd characters.
func OriginTag(origin string) string {
	d := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(origin))))
	const hexdigits = "0123456789abcdef"
	b := make([]byte, 32)
	for i := 0; i < 16; i++ {
		b[i*2] = hexdigits[d[i]>>4]
		b[i*2+1] = hexdigits[d[i]&0xf]
	}
	return string(b)
}

// MirrorDHTKey is where one mirror's record for one origin is stored: one key
// per (origin, node), so each mirror is a single-writer of its own record.
func MirrorDHTKey(origin, nodeID string) string {
	return "/" + DHTMirrorNamespace + "/" + OriginTag(origin) + "/" + nodeID
}

// RendezvousLabel is the fixed label whose SHA-256 is the per-origin rendezvous
// CID every mirror of that origin provides. Any node computes the same label
// without coordination.
func RendezvousLabel(origin string) string {
	return "rabbiit-mirror-rendezvous/1:" + OriginTag(origin)
}

func keyNodeID(key string) (string, bool) {
	prefix := "/" + DHTMirrorNamespace + "/"
	if !strings.HasPrefix(key, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(key, prefix)
	slash := strings.LastIndex(rest, "/")
	if slash < 0 || slash == len(rest)-1 {
		return "", false
	}
	return rest[slash+1:], true // the nodeID is the last segment
}

// DHTValidator validates and selects mirror records in the DHT: a record is
// valid only if well-formed, unexpired, stored under its own node's key and
// origin, and signed by that node's key. Select prefers the highest Sequence.
type DHTValidator struct{ Now func() time.Time }

func (v DHTValidator) Validate(key string, value []byte) error {
	nodeID, ok := keyNodeID(key)
	if !ok {
		return errors.New("mirrordisc: invalid mirror DHT key")
	}
	var rec MirrorRecord
	if len(value) > 16<<10 || json.Unmarshal(value, &rec) != nil {
		return errors.New("mirrordisc: invalid mirror record encoding")
	}
	if rec.RecordType != "mirror" || rec.NodeID != nodeID {
		return errors.New("mirrordisc: mirror record stored under the wrong key")
	}
	if key != MirrorDHTKey(rec.Origin, rec.NodeID) {
		return errors.New("mirrordisc: mirror record origin does not match its key")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if rec.ExpiresAt <= now.Unix() || rec.ExpiresAt-rec.IssuedAt > int64(RecordTTL/time.Second) {
		return errors.New("mirrordisc: mirror record expired or over-long")
	}
	return verifySignature(rec)
}

func (v DHTValidator) Select(_ string, values [][]byte) (int, error) {
	best, bestSeq := -1, uint64(0)
	for i, value := range values {
		var rec MirrorRecord
		if json.Unmarshal(value, &rec) != nil {
			continue
		}
		if best == -1 || rec.Sequence > bestSeq {
			best, bestSeq = i, rec.Sequence
		}
	}
	if best < 0 {
		return 0, errors.New("mirrordisc: no valid mirror records")
	}
	return best, nil
}

// Sign fills NodeID, PublicKey and Signature over the record's other fields.
func Sign(signer Signer, rec MirrorRecord) (MirrorRecord, error) {
	pub, err := signer.PublicKey()
	if err != nil {
		return rec, err
	}
	rec.RecordType = "mirror"
	rec.NodeID = signer.ID()
	rec.PublicKey = base64.RawStdEncoding.EncodeToString(pub)
	rec.Signature = ""
	body, err := json.Marshal(rec)
	if err != nil {
		return rec, err
	}
	sig, err := signer.Sign(body)
	if err != nil {
		return rec, err
	}
	rec.Signature = base64.RawStdEncoding.EncodeToString(sig)
	return rec, nil
}

func verifySignature(rec MirrorRecord) error {
	rawKey, err := base64.RawStdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return errors.New("mirrordisc: invalid mirror public key")
	}
	key, err := crypto.UnmarshalPublicKey(rawKey)
	if err != nil {
		return errors.New("mirrordisc: invalid mirror public key")
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil || id.String() != rec.NodeID {
		return errors.New("mirrordisc: mirror key does not match node id")
	}
	rawSig, err := base64.RawStdEncoding.DecodeString(rec.Signature)
	if err != nil {
		return errors.New("mirrordisc: invalid mirror signature")
	}
	unsigned := rec
	unsigned.Signature = ""
	body, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	ok, err := key.Verify(body, rawSig)
	if err != nil || !ok {
		return errors.New("mirrordisc: invalid mirror signature")
	}
	return nil
}
