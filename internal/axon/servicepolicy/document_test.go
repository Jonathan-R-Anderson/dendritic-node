package servicepolicy

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

func signedDoc(t *testing.T, priv ed25519.PrivateKey, seq uint64, mutate func(*NetworkPolicy)) *NetworkPolicy {
	t.Helper()
	d := &NetworkPolicy{Schema: policySchema, Sequence: seq, IssuedAt: time.Now().Unix()}
	if mutate != nil {
		mutate(d)
	}
	if err := d.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	d := signedDoc(t, priv, 1, func(d *NetworkPolicy) {
		d.Grades = map[string]int{addr(t): 88}
	})
	if err := d.Verify(pub); err != nil {
		t.Fatalf("verify failed on a freshly signed doc: %v", err)
	}
	// Tamper after signing.
	d.Sequence = 999
	if err := d.Verify(pub); err == nil {
		t.Fatal("verify accepted a tampered document")
	}
	// Wrong key.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	d.Sequence = 1
	if err := d.Verify(other); err == nil {
		t.Fatal("verify accepted the wrong key")
	}
}

func TestLoaderInstallRejectsRollbackExpiryAndSchema(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := New(Options{Logger: log.New(io.Discard, "", 0)})
	l := &Loader{Key: pub, Policy: p, Logger: log.New(io.Discard, "", 0)}

	if err := l.install(signedDoc(t, priv, 5, nil)); err != nil {
		t.Fatalf("install seq 5 failed: %v", err)
	}
	if err := l.install(signedDoc(t, priv, 4, nil)); err == nil {
		t.Fatal("install accepted an older sequence (rollback)")
	}
	if err := l.install(signedDoc(t, priv, 6, nil)); err != nil {
		t.Fatalf("install seq 6 failed: %v", err)
	}
	// Expired.
	exp := signedDoc(t, priv, 7, func(d *NetworkPolicy) { d.ExpiresAt = time.Now().Add(-time.Hour).Unix() })
	if err := l.install(exp); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("install accepted an expired doc: %v", err)
	}
	// Wrong schema.
	bad := &NetworkPolicy{Schema: "nope", Sequence: 8}
	_ = bad.Sign(priv)
	if err := l.install(bad); err == nil {
		t.Fatal("install accepted an unexpected schema")
	}
	// Unsigned.
	if err := l.install(&NetworkPolicy{Schema: policySchema, Sequence: 9}); err == nil {
		t.Fatal("install accepted an unsigned doc")
	}
}

func TestCanonicalNormalizesBareLabels(t *testing.T) {
	full := addr(t) // "<56>.key.axon"
	bare := strings.TrimSuffix(full, ".key.axon")
	doc := &NetworkPolicy{Grades: map[string]int{bare: 91},
		Suspended: map[string]Suspension{strings.ToUpper(bare): {Reason: "x"}}}
	c := doc.canonical()
	if g := c.gradeOf(strings.ToLower(full)); g != 91 {
		t.Fatalf("grade not found under the full address after canonicalisation: %d", g)
	}
	if _, ok := c.suspension(strings.ToLower(full)); !ok {
		t.Fatal("suspension not found under the full address after canonicalisation")
	}
}

func TestInstalledDocumentDrivesDecisions(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	suspended := addr(t)
	p := New(Options{Enforce: true, Logger: log.New(io.Discard, "", 0)})
	l := &Loader{Key: pub, Policy: p, Logger: log.New(io.Discard, "", 0)}
	doc := signedDoc(t, priv, 1, func(d *NetworkPolicy) {
		d.Suspended = map[string]Suspension{suspended: {Reason: "fraud"}}
	})
	if err := l.install(doc); err != nil {
		t.Fatal(err)
	}
	if blocked, reason := p.Gate(suspended); !blocked || !strings.Contains(reason, "fraud") {
		t.Fatalf("installed suspension not enforced: blocked=%v reason=%q", blocked, reason)
	}
}
