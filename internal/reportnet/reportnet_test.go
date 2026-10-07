package reportnet

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/dht"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/swarmscore"
)

func bytes32(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

// reporter makes a fresh ed25519 identity and its libp2p peer id.
func reporter(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lpk, err := crypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := peer.IDFromPublicKey(lpk)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, pid.String()
}

func signedReport(t *testing.T, priv ed25519.PrivateKey, subject []byte, seq uint64, mutate func(*dht.ContentReport)) (string, []byte, *dht.ContentReport) {
	t.Helper()
	rec := &dht.ContentReport{
		Ver: 1, NameHash: subject, ManifestCID: bytes32(9), Category: 1,
		Reason: "observed", Sequence: seq,
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(rec)
	}
	if err := dht.SignReport(rec, priv); err != nil {
		t.Fatal(err)
	}
	value, err := dht.Encode(rec)
	if err != nil {
		t.Fatal(err)
	}
	// Re-derive the reporter's node id from the key SignReport filled in.
	lpk, _ := crypto.UnmarshalEd25519PublicKey(rec.Reporter)
	pid, _ := peer.IDFromPublicKey(lpk)
	return ReportDHTKey(rec.NameHash, pid.String()), value, rec
}

func TestValidateAcceptsWellFormed(t *testing.T) {
	_, priv, _ := reporter(t)
	key, value, _ := signedReport(t, priv, bytes32(1), 1, nil)
	if err := (DHTValidator{}).Validate(key, value); err != nil {
		t.Fatalf("well-formed report rejected: %v", err)
	}
}

func TestRejectsWrongSubjectAndNode(t *testing.T) {
	_, priv, _ := reporter(t)
	_, value, rec := signedReport(t, priv, bytes32(1), 1, nil)
	lpk, _ := crypto.UnmarshalEd25519PublicKey(rec.Reporter)
	pid, _ := peer.IDFromPublicKey(lpk)

	wrongSubject := ReportDHTKey(bytes32(2), pid.String())
	if err := (DHTValidator{}).Validate(wrongSubject, value); err == nil {
		t.Fatal("validated under a key for a different subject")
	}
	wrongNode := ReportDHTKey(rec.NameHash, "12D3KooWsomeoneelse")
	if err := (DHTValidator{}).Validate(wrongNode, value); err == nil {
		t.Fatal("validated under a key for a different node")
	}
}

func TestRejectsExpiredAndTampered(t *testing.T) {
	_, priv, _ := reporter(t)
	key, value, _ := signedReport(t, priv, bytes32(1), 1, func(r *dht.ContentReport) {
		r.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()
		r.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	})
	if err := (DHTValidator{}).Validate(key, value); err == nil {
		t.Fatal("expired report validated")
	}
	// Tamper: flip a byte of a fresh report's encoding.
	key2, value2, _ := signedReport(t, priv, bytes32(3), 1, nil)
	value2[len(value2)-1] ^= 0xff
	if err := (DHTValidator{}).Validate(key2, value2); err == nil {
		t.Fatal("tampered report validated")
	}
}

func TestSelectHighestSequence(t *testing.T) {
	_, priv, _ := reporter(t)
	_, v1, _ := signedReport(t, priv, bytes32(1), 1, nil)
	_, v5, _ := signedReport(t, priv, bytes32(1), 5, nil)
	idx, err := (DHTValidator{}).Select("", [][]byte{v1, v5})
	if err != nil || idx != 1 {
		t.Fatalf("Select picked %d (err %v), want index 1 (seq 5)", idx, err)
	}
}

// The whole pipeline: a burst of distinct reporters against one subject, fed
// through the swarm grader, grades the subject poorly and flags it for the DAO.
func TestReportsFeedSwarmGrader(t *testing.T) {
	subject := bytes32(7)
	now := time.Unix(3_600_000_000+1800, 0)
	var reports []*dht.ContentReport
	// 24 reporters all filing in the most recent hour — a sharp burst.
	for i := 0; i < 24; i++ {
		_, priv, _ := reporter(t)
		rec := &dht.ContentReport{
			Ver: 1, NameHash: subject, ManifestCID: bytes32(9), Category: 2,
			Reason: "burst", Sequence: 1,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		}
		if err := dht.SignReport(rec, priv); err != nil {
			t.Fatal(err)
		}
		reports = append(reports, rec)
	}
	assessed := swarmscore.AssessAll(ToSwarmReports(reports), now, swarmscore.Params{Bucket: time.Hour, Window: 8})
	a, ok := assessed[SubjectTag(subject)]
	if !ok {
		t.Fatal("subject not graded")
	}
	if a.Grade > 40 || !a.ShouldPropose {
		t.Fatalf("a 24-reporter burst should grade poorly and propose: grade=%d propose=%v", a.Grade, a.ShouldPropose)
	}
}
