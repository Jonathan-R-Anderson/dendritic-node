package channel

// Measuring the chain terms — roadmap P12.
//
// The interesting tests here are the REFUSALS. A probe that turns a quiet
// afternoon into "reorg depth: validated" would defeat the gate more
// thoroughly than having no probe at all, because it would do it with evidence
// attached.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The easiest way to accidentally validate a term: watch a calm chain and
// conclude the worst case is zero.
func TestNoReorgsObservedIsNotEvidence(t *testing.T) {
	quiet := ReorgObservation{Blocks: 5000, Reorgs: 0, BlockInterval: 12 * time.Second}

	_, err := quiet.AsEvidence(1, time.Now().Unix())
	if err == nil {
		t.Fatal("5000 quiet blocks were accepted as bounding reorg depth")
	}
	if !strings.Contains(err.Error(), "does not bound") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

func TestAnObservedReorgIsEvidence(t *testing.T) {
	seen := ReorgObservation{
		Blocks: 2000, Reorgs: 3, MaxDepth: 2,
		BlockInterval: 12 * time.Second, MaxDepthTime: 24 * time.Second,
	}
	e, err := seen.AsEvidence(1, time.Now().Unix())
	if err != nil {
		t.Fatalf("AsEvidence: %v", err)
	}
	if e.Term != "reorg depth" || e.Measured != 24*time.Second {
		t.Errorf("evidence %+v", e)
	}
	// The method has to be specific enough to repeat.
	for _, want := range []string{"2000 blocks", "3 reorgs", "deepest 2"} {
		if !strings.Contains(e.Method, want) {
			t.Errorf("method %q is missing %q", e.Method, want)
		}
	}
	// And it must be filable against a budget that allows for it.
	v := NewValidatedBudget(1, MainnetChallengeBudget())
	e.Samples = MinEvidenceSamples
	if err := v.Record(e); err != nil {
		t.Fatalf("the evidence was rejected by the gate: %v", err)
	}
}

// The rpc term explicitly assumes failover is possible. One endpoint is not a
// smaller version of that assumption, it is the absence of it.
func TestASingleEndpointCannotValidateTheRPCTerm(t *testing.T) {
	single := FailoverObservation{
		Endpoints:     []EndpointHealth{{Endpoint: "https://one.example"}},
		WorstFailover: time.Second,
	}
	if _, err := single.AsEvidence(1, time.Now().Unix()); err == nil {
		t.Fatal("a single endpoint validated a term that assumes failover")
	}
}

// A round where nobody answered is an unbounded wait. It cannot be averaged
// away into a worst case.
func TestARoundWhereNobodyAnsweredBlocksValidation(t *testing.T) {
	flaky := FailoverObservation{
		Endpoints: []EndpointHealth{
			{Endpoint: "a", Attempts: 100}, {Endpoint: "b", Attempts: 100},
		},
		WorstFailover: 2 * time.Second,
		AllFailed:     1,
	}
	_, err := flaky.AsEvidence(1, time.Now().Unix())
	if err == nil {
		t.Fatal("a total outage was folded into a measured worst case")
	}
	if !strings.Contains(err.Error(), "unbounded") {
		t.Errorf("the refusal does not name the problem: %v", err)
	}
}

func TestHealthyFailoverIsEvidence(t *testing.T) {
	healthy := FailoverObservation{
		Endpoints: []EndpointHealth{
			{Endpoint: "a", Attempts: 60, WorstLatency: 400 * time.Millisecond},
			{Endpoint: "b", Attempts: 4, WorstLatency: 900 * time.Millisecond},
		},
		WorstFailover: 3 * time.Second,
	}
	e, err := healthy.AsEvidence(1, time.Now().Unix())
	if err != nil {
		t.Fatalf("AsEvidence: %v", err)
	}
	if e.Samples != 64 {
		t.Errorf("samples %d, want the 64 attempts made", e.Samples)
	}
}

// ---- the observer against a fake chain --------------------------------------

// fakeHead serves eth_getBlockByNumber from a script of (number, hash) pairs.
func fakeHead(t *testing.T, script [][2]string) *httptest.Server {
	t.Helper()
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step := script[i]
		if i < len(script)-1 {
			i++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]string{"number": step[0], "hash": step[1]},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The measurement itself: a height that comes back with a different hash means
// everything from there to the old head was discarded.
func TestTheObserverMeasuresReorgDepth(t *testing.T) {
	// Climb to 0x14, then 0x12 reappears with a different hash — a two-block
	// reorg (0x13 and 0x14 discarded, 0x12 rewritten).
	srv := fakeHead(t, [][2]string{
		{"0x10", "0xaa"},
		{"0x11", "0xbb"},
		{"0x12", "0xcc"},
		{"0x13", "0xdd"},
		{"0x14", "0xee"},
		{"0x12", "0xff"},
		{"0x15", "0x11"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, _ := ObserveReorgs(ctx, srv.URL, time.Millisecond, 6)

	if got.Reorgs == 0 {
		t.Fatal("the rewritten height was not noticed")
	}
	if got.MaxDepth != 3 {
		t.Errorf("depth %d, want 3 (0x12 through 0x14)", got.MaxDepth)
	}
}

// An endpoint that is simply down must not read as a quiet chain.
func TestABrokenEndpointIsNotAQuietChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got, err := ObserveReorgs(ctx, srv.URL, time.Millisecond, 100)

	if err == nil {
		t.Error("a dead endpoint produced no error")
	}
	// And critically, it cannot become evidence.
	if _, err := got.AsEvidence(1, time.Now().Unix()); err == nil {
		t.Fatal("an unreachable endpoint validated the reorg term")
	}
}

func TestFailoverPrefersTheFirstWorkingEndpoint(t *testing.T) {
	good := fakeHead(t, [][2]string{{"0x1", "0xaa"}})
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer dead.Close()

	got := ObserveFailover(context.Background(), []string{dead.URL, good.URL}, 5, 0)

	if got.AllFailed != 0 {
		t.Errorf("%d rounds went unanswered though a healthy endpoint was configured", got.AllFailed)
	}
	if got.Endpoints[0].Failures != 5 {
		t.Errorf("the dead endpoint recorded %d failures, want 5", got.Endpoints[0].Failures)
	}
	if got.Endpoints[1].Attempts != 5 {
		t.Errorf("the healthy endpoint was tried %d times, want 5", got.Endpoints[1].Attempts)
	}
}

func TestFailoverRecordsATotalOutage(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer dead.Close()

	got := ObserveFailover(context.Background(), []string{dead.URL, dead.URL}, 3, 0)
	if got.AllFailed != 3 {
		t.Fatalf("AllFailed %d, want 3", got.AllFailed)
	}
}
