package policyauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/dht"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/servicepolicy"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/swarmscore"
)

type fakeReports map[string][]*dht.ContentReport // keyed by hex(subject)

func (f fakeReports) Reports(_ context.Context, subject []byte) ([]*dht.ContentReport, error) {
	return f[hex.EncodeToString(subject)], nil
}

type fakeSusp map[string]servicepolicy.Suspension

func (f fakeSusp) Suspended(context.Context) (map[string]servicepolicy.Suspension, error) {
	return f, nil
}

func addr(seed byte) string {
	k := make([]byte, 32)
	k[0] = seed
	return identity.FullAddress(k)
}

func burst(subject []byte, n int, at time.Time) []*dht.ContentReport {
	out := make([]*dht.ContentReport, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &dht.ContentReport{NameHash: subject, IssuedAt: at.Unix()})
	}
	return out
}

// The whole governance loop in one test: reports + a DAO suspension go in, a
// signed policy document comes out, and that document actually enforces through
// service policy — a hot service blocked, a calm one allowed, a suspended one
// blocked with its reason.
func TestAuthorityProducesEnforceableDocument(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(3_600_000_000+1800, 0)
	hot, calm, banned := addr(1), addr(2), addr(3)

	reports := fakeReports{
		hex.EncodeToString(SubjectHash(hot)):  burst(SubjectHash(hot), 24, now),                   // sharp burst
		hex.EncodeToString(SubjectHash(calm)): burst(SubjectHash(calm), 1, now.Add(-5*time.Hour)), // a single old report
	}
	susp := fakeSusp{banned: {Reason: "malware distribution", ProposalID: 7}}

	a := &Authority{
		Watchlist:   StaticWatchlist{hot, calm, banned},
		Reports:     reports,
		Suspensions: susp,
		Params:      swarmscore.Params{Bucket: time.Hour, Window: 8},
		Key:         priv,
		Logger:      log.New(io.Discard, "", 0),
	}

	doc, assessments, err := a.BuildOnce(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Verify(pub); err != nil {
		t.Fatalf("published document does not verify: %v", err)
	}
	if doc.Grades[hot] >= doc.Grades[calm] {
		t.Fatalf("hot service should grade worse than calm: hot=%d calm=%d", doc.Grades[hot], doc.Grades[calm])
	}
	if _, ok := doc.Suspended[banned]; !ok {
		t.Fatal("DAO suspension not carried into the document")
	}

	// End to end: feed the signed document into a node's policy and enforce.
	p := servicepolicy.New(servicepolicy.Options{Enforce: true, MinGrade: "C", Logger: log.New(io.Discard, "", 0)})
	p.SetDocument(doc)
	if blocked, _ := p.Gate(hot); !blocked {
		t.Fatalf("hot service (grade %d) should be blocked under a C floor", doc.Grades[hot])
	}
	if blocked, _ := p.Gate(calm); blocked {
		t.Fatalf("calm service (grade %d) should be allowed under a C floor", doc.Grades[calm])
	}
	if blocked, reason := p.Gate(banned); !blocked || !strings.Contains(reason, "malware") {
		t.Fatalf("suspended service not blocked with reason: blocked=%v reason=%q", blocked, reason)
	}

	// The burst is a DAO-proposal candidate.
	cands := swarmscore.ProposalCandidates(assessmentMap(assessments))
	if len(cands) != 1 || cands[0].Subject != hot {
		t.Fatalf("expected only the hot service as a proposal candidate, got %+v", cands)
	}
}

func TestSequenceIsMonotonicAcrossBuilds(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := &Authority{
		Watchlist: StaticWatchlist{addr(5)},
		Reports:   fakeReports{},
		Params:    swarmscore.Params{Bucket: time.Hour, Window: 8},
		Key:       priv,
		Logger:    log.New(io.Discard, "", 0),
	}
	d1, _, err := a.BuildOnce(context.Background(), time.Unix(3_600_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	d2, _, err := a.BuildOnce(context.Background(), time.Unix(3_600_000_050, 0))
	if err != nil {
		t.Fatal(err)
	}
	if d2.Sequence <= d1.Sequence {
		t.Fatalf("sequence not monotonic: %d then %d", d1.Sequence, d2.Sequence)
	}
}
