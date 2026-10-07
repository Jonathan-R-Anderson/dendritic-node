package servicepolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// NetworkPolicy is the signed document that carries per-service grades and the
// DAO's suspension list to every node. It is published by a policy authority
// (the DAO's executor / a monitor quorum) and verified against a pubkey the
// operator pins, so a node applies grades and suspensions without reading the
// chain on the hot path -- the same shape as the gateway's signed snapshot
// manifest, including monotonic-sequence rollback protection.
//
// Addresses are full lowercase <56 base32>.key.axon strings. The loader
// canonicalises keys after verifying the signature, so the document may be
// authored with bare labels.
type NetworkPolicy struct {
	Schema    string                `json:"schema"`
	Sequence  uint64                `json:"sequence"`
	IssuedAt  int64                 `json:"issued_at"`
	ExpiresAt int64                 `json:"expires_at,omitempty"`
	Grades    map[string]int        `json:"grades,omitempty"`
	Suspended map[string]Suspension `json:"suspended,omitempty"`
	Signature []byte                `json:"signature,omitempty"`
}

// Suspension records that the DAO has suspended a service.
type Suspension struct {
	Reason      string `json:"reason,omitempty"`
	Category    string `json:"category,omitempty"`
	EvidenceCID string `json:"evidence_cid,omitempty"`
	ProposalID  uint64 `json:"proposal_id,omitempty"`
	Since       int64  `json:"since,omitempty"`
}

const policySchema = "rabbiit/service-policy/1"

func (d *NetworkPolicy) gradeOf(normAddr string) int {
	if d == nil || d.Grades == nil {
		return -1
	}
	g, ok := d.Grades[normAddr]
	if !ok {
		return -1
	}
	if g < 0 {
		return 0
	}
	if g > 100 {
		return 100
	}
	return g
}

func (d *NetworkPolicy) suspension(normAddr string) (Suspension, bool) {
	if d == nil || d.Suspended == nil {
		return Suspension{}, false
	}
	s, ok := d.Suspended[normAddr]
	return s, ok
}

// signingBytes is the canonical representation signed and verified: the JSON of
// the document with the signature field cleared. encoding/json sorts map keys,
// so this is deterministic.
func (d *NetworkPolicy) signingBytes() ([]byte, error) {
	c := *d
	c.Signature = nil
	return json.Marshal(&c)
}

// Sign fills in the signature with the authority's key.
func (d *NetworkPolicy) Sign(priv ed25519.PrivateKey) error {
	b, err := d.signingBytes()
	if err != nil {
		return err
	}
	d.Signature = ed25519.Sign(priv, b)
	return nil
}

// Verify checks the document's signature against the pinned authority key.
func (d *NetworkPolicy) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("servicepolicy: policy key is not a valid ed25519 public key")
	}
	if len(d.Signature) == 0 {
		return errors.New("servicepolicy: document is unsigned")
	}
	b, err := d.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, b, d.Signature) {
		return errors.New("servicepolicy: document signature does not verify")
	}
	return nil
}

// canonical returns a copy with addresses normalised to full lowercase
// .key.axon keys, dropping any that do not parse.
func (d *NetworkPolicy) canonical() *NetworkPolicy {
	out := &NetworkPolicy{
		Schema: d.Schema, Sequence: d.Sequence, IssuedAt: d.IssuedAt,
		ExpiresAt: d.ExpiresAt, Signature: d.Signature,
	}
	if len(d.Grades) > 0 {
		out.Grades = make(map[string]int, len(d.Grades))
		for a, g := range d.Grades {
			if norm, ok := normalizeAddr(a); ok {
				out.Grades[norm] = g
			}
		}
	}
	if len(d.Suspended) > 0 {
		out.Suspended = make(map[string]Suspension, len(d.Suspended))
		for a, s := range d.Suspended {
			if norm, ok := normalizeAddr(a); ok {
				out.Suspended[norm] = s
			}
		}
	}
	return out
}

// Loader fetches the signed policy document periodically, verifies it, enforces
// monotonic sequence and expiry, and installs it into the Policy. The HTTP
// client is supplied by the caller so the document can be served over clearnet
// or over the overlay (an .axon URL dialed through the runtime).
type Loader struct {
	URL     string
	Key     ed25519.PublicKey
	Client  *http.Client
	Poll    time.Duration
	Policy  *Policy
	Logger  *log.Logger
	MaxSize int64

	lastSeq uint64
}

// Run fetches once immediately, then on every Poll tick until ctx ends.
func (l *Loader) Run(ctx context.Context) {
	lg := l.Logger
	if lg == nil {
		lg = log.Default()
	}
	poll := l.Poll
	if poll <= 0 {
		poll = 10 * time.Minute
	}
	if err := l.fetchOnce(ctx); err != nil {
		lg.Printf("servicepolicy: initial document fetch failed: %v", err)
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.fetchOnce(ctx); err != nil {
				lg.Printf("servicepolicy: document refresh failed: %v", err)
			}
		}
	}
}

// fetchOnce retrieves, verifies and installs one document. A fetch that is
// older-or-equal by sequence, expired, or unverifiable is rejected and the
// current document is kept.
func (l *Loader) fetchOnce(ctx context.Context) error {
	client := l.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	maxSize := l.MaxSize
	if maxSize <= 0 {
		maxSize = 8 << 20
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("servicepolicy: document fetch returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return err
	}
	var doc NetworkPolicy
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("servicepolicy: malformed document: %w", err)
	}
	return l.install(&doc)
}

// install validates and applies a decoded document. Split out so tests can feed
// a document without a server.
func (l *Loader) install(doc *NetworkPolicy) error {
	if doc.Schema != policySchema {
		return fmt.Errorf("servicepolicy: unexpected schema %q", doc.Schema)
	}
	if err := doc.Verify(l.Key); err != nil {
		return err
	}
	if doc.ExpiresAt != 0 && time.Now().Unix() > doc.ExpiresAt {
		return errors.New("servicepolicy: document has expired")
	}
	if doc.Sequence < l.lastSeq {
		return fmt.Errorf("servicepolicy: document sequence %d is older than %d (rollback refused)",
			doc.Sequence, l.lastSeq)
	}
	l.lastSeq = doc.Sequence
	l.Policy.SetDocument(doc.canonical())
	return nil
}
