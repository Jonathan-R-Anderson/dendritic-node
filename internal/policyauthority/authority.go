// Package policyauthority is the component that closes the content-governance
// loop: it reads the content reports that propagate across the network, grades
// each watched service with the swarm/thermal model, folds in the DAO's
// on-chain suspensions, and signs the NetworkPolicy document that every node
// fetches and enforces at its dial gate.
//
// It is deliberately NOT a moderator. It computes grades with a deterministic
// function any node could run, and it only publishes signals — a node still
// decides for itself whether to honour them. An operator runs one (or several,
// pinned by different keys) to turn the raw report stream into the signed
// grade/suspension document that service policy consumes.
//
// The heavy pieces are injected, so the core is pure and testable: a Watchlist
// of the services to grade, a ReportFetcher (the node's FindReports over the
// DHT), and an optional SuspensionSource (the on-chain ServiceSuspension set).
package policyauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/dht"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/servicepolicy"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/swarmscore"
)

// SubjectHash is the report subject a service is reported under: the SHA-256 of
// its lowercased .key.axon address. Reporters set ContentReport.NameHash to this
// for a self-certifying service, so the authority can find a service's reports
// from its address and key the resulting grade back to that same address.
func SubjectHash(addr string) []byte {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(addr))))
	return h[:]
}

// Watchlist is the set of service addresses to grade this round. It can be a
// static operator list, the registered names from the TLD registry, the
// services the DAO has touched, or any union of those.
type Watchlist interface {
	Addresses(ctx context.Context) ([]string, error)
}

// ReportFetcher returns the reports about a subject — in production the node's
// FindReports over the DHT.
type ReportFetcher interface {
	Reports(ctx context.Context, subject []byte) ([]*dht.ContentReport, error)
}

// SuspensionSource returns the services the DAO has suspended, keyed by address.
// Optional: nil means the document carries grades only (no on-chain suspensions).
type SuspensionSource interface {
	Suspended(ctx context.Context) (map[string]servicepolicy.Suspension, error)
}

// StaticWatchlist is a fixed list of addresses.
type StaticWatchlist []string

func (s StaticWatchlist) Addresses(context.Context) ([]string, error) { return []string(s), nil }

// Authority builds and serves the signed policy document.
type Authority struct {
	Watchlist   Watchlist
	Reports     ReportFetcher
	Suspensions SuspensionSource // optional
	Params      swarmscore.Params
	Key         ed25519.PrivateKey
	DocTTL      time.Duration // how long a published document is valid (default 1h)
	Logger      *log.Logger

	seq     uint64
	latest  atomic.Pointer[[]byte] // the signed document JSON currently served
	mu      sync.Mutex             // serializes BuildOnce (seq increment)
	started time.Time
}

func (a *Authority) logger() *log.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return log.Default()
}

func (a *Authority) docTTL() time.Duration {
	if a.DocTTL > 0 {
		return a.DocTTL
	}
	return time.Hour
}

// BuildOnce grades every watched service and returns a freshly signed document
// plus the per-service assessments (for logging and DAO-proposal decisions). A
// service whose reports cannot be fetched is skipped, not failed, so one
// unreachable subject never blanks the whole document.
func (a *Authority) BuildOnce(ctx context.Context, now time.Time) (*servicepolicy.NetworkPolicy, []swarmscore.Assessment, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	addrs, err := a.Watchlist.Addresses(ctx)
	if err != nil {
		return nil, nil, err
	}
	grades := make(map[string]int, len(addrs))
	assessments := make([]swarmscore.Assessment, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if addr == "" {
			continue
		}
		reps, rerr := a.Reports.Reports(ctx, SubjectHash(addr))
		if rerr != nil {
			a.logger().Printf("policyauthority: reports for %s unavailable: %v", addr, rerr)
			continue
		}
		times := make([]time.Time, 0, len(reps))
		for _, r := range reps {
			if r != nil {
				times = append(times, time.Unix(r.IssuedAt, 0))
			}
		}
		asmt := swarmscore.Assess(addr, times, now, a.Params)
		grades[addr] = asmt.Grade
		assessments = append(assessments, asmt)
	}

	var susp map[string]servicepolicy.Suspension
	if a.Suspensions != nil {
		susp, err = a.Suspensions.Suspended(ctx)
		if err != nil {
			a.logger().Printf("policyauthority: suspension source unavailable, publishing grades only: %v", err)
			susp = nil
		}
	}

	// Seed the sequence from wall-clock on first use so a restart never
	// republishes an older sequence (nodes reject a rollback).
	if a.seq == 0 {
		a.seq = uint64(now.Unix())
	} else {
		a.seq++
	}
	doc, err := servicepolicy.NewSignedDocument(a.seq, now, now.Add(a.docTTL()), grades, susp, a.Key)
	if err != nil {
		return nil, nil, err
	}
	return doc, assessments, nil
}

// Run rebuilds and re-signs the document every interval until ctx ends, serving
// the newest from Handler. It builds once immediately.
func (a *Authority) Run(ctx context.Context, interval time.Duration) {
	a.started = time.Now()
	if interval <= 0 {
		interval = a.docTTL() / 2
	}
	a.refresh(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.refresh(ctx)
		}
	}
}

func (a *Authority) refresh(ctx context.Context) {
	doc, assessments, err := a.BuildOnce(ctx, time.Now())
	if err != nil {
		a.logger().Printf("policyauthority: build failed: %v", err)
		return
	}
	blob, err := json.Marshal(doc)
	if err != nil {
		a.logger().Printf("policyauthority: encode failed: %v", err)
		return
	}
	a.latest.Store(&blob)
	proposals := swarmscore.ProposalCandidates(assessmentMap(assessments))
	a.logger().Printf("policyauthority: published document seq=%d, graded=%d, proposal-candidates=%d",
		doc.Sequence, len(assessments), len(proposals))
	for _, p := range proposals {
		a.logger().Printf("policyauthority: DAO-proposal candidate %s (grade %s, temperature %.1f, suggest %s vote window)",
			p.Subject, servicepolicy.Letter(p.Grade), p.Temperature, p.RecommendedVoteWindow)
	}
}

// ServeHTTP serves the current signed document. This is the endpoint nodes point
// their axon.service_policy.policy_url at.
func (a *Authority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	blob := a.latest.Load()
	if blob == nil {
		http.Error(w, "policy document not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(*blob)
}

func assessmentMap(list []swarmscore.Assessment) map[string]swarmscore.Assessment {
	m := make(map[string]swarmscore.Assessment, len(list))
	for _, a := range list {
		m[a.Subject] = a
	}
	return m
}
