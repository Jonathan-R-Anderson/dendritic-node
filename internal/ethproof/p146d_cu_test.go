package ethproof

// P14.6d — compute-unit accounting, and the post-upgrade catch-up measurement.
//
// MEASUREMENT ONLY. No production code is changed. The endpoint is configuration
// (ETH_RPC_URL); the verification path is byte-for-byte the same one P14.5
// shipped, and switching provider tiers touches none of it.
//
//	PROJECTION (runs anywhere, no network):
//	  go test ./internal/ethproof/ -run TestP146DProjectedMonthlyCU -v
//
//	MEASUREMENT (needs the upgraded endpoint):
//	  P146D=1 CHAIN_PROBE=1 ETH_RPC_URL=... BEACON_API_URL=... \
//	    P146D_BLOCKS=2000 go test ./internal/ethproof/ -run TestP146DCatchUp -v -timeout 60m
//
// WHY CU IS COUNTED HERE AND NOT IN RPCSource
// -------------------------------------------
// RPCSource.Stats() counts CALLS, and a batch of 25 headers is one call. Alchemy
// bills per METHOD INVOCATION, so a batch of 25 costs 25 units of billing and 1
// unit of "calls". Counting CU inside RPCSource would mean teaching production
// code a provider's price list, which is exactly the kind of coupling that goes
// stale silently. It lives in the test that cares.

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// Alchemy's published weights. BILLED CU is what appears on the invoice;
// THROUGHPUT CU is what the rate limiter charges against the per-second cap, and
// for eth_getBlockReceipts the two differ by 25x — which is the entire reason
// the free tier throttled us at one call per second.
const (
	cuBlockByNumber        = 20
	cuBlockReceipts        = 20
	cuGetProof             = 20
	cuThroughputReceipts   = 500
	cuThroughputPerSecFree = 500
	cuThroughputPerSecPAYG = 10000
	usdPerMillionCU        = 0.45
)

// cuCounter wraps a HeaderSource and counts METHOD INVOCATIONS, not requests.
type cuCounter struct {
	inner HeaderSource

	mu           sync.Mutex
	headerCalls  int
	receiptCalls int
}

func (c *cuCounter) HeadersDescending(ctx context.Context, from uint64, count int) ([]ExecutionHeader, error) {
	h, err := c.inner.HeadersDescending(ctx, from, count)
	c.mu.Lock()
	// Every header in the batch is a separate eth_getBlockByNumber invocation as
	// far as billing is concerned, whether or not they shared a request.
	c.headerCalls += count
	c.mu.Unlock()
	return h, err
}

func (c *cuCounter) ReceiptsByNumber(ctx context.Context, n uint64) ([]Receipt, error) {
	r, err := c.inner.ReceiptsByNumber(ctx, n)
	c.mu.Lock()
	c.receiptCalls++
	c.mu.Unlock()
	return r, err
}

func (c *cuCounter) totals() (headers, receipts, cu int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.headerCalls, c.receiptCalls,
		c.headerCalls*cuBlockByNumber + c.receiptCalls*cuBlockReceipts
}

// The projection, from measured parameters. Runs offline.
func TestP146DProjectedMonthlyCU(t *testing.T) {
	// MEASURED INPUTS, all from earlier P14 work:
	const (
		blocksPerDay  = 7200 // mainnet, 12s slots
		bloomHitRate  = 0.20 // P14.5 catch-up: 159/200 skipped
		watchtowers   = 2    // the declared P12-8 envelope
		daysPerMonth  = 30
		weekBlocks    = 50400
		perBlockMsPAY = 24.5 // P14.5 measured "actual work" without rate limits
	)

	headersDay := blocksPerDay
	receiptsDay := int(float64(blocksPerDay) * bloomHitRate)
	cuDay := headersDay*cuBlockByNumber + receiptsDay*cuBlockReceipts
	cuMonth := cuDay * daysPerMonth
	cuMonthFleet := cuMonth * watchtowers

	t.Logf("STEADY STATE, per watchtower")
	t.Logf("  finality advances one epoch (32 slots) every ~6.4 min; Advance makes")
	t.Logf("  ZERO Alchemy calls when the finalised head has not moved.")
	t.Logf("  headers  %6d/day x %d CU = %9d CU", headersDay, cuBlockByNumber, headersDay*cuBlockByNumber)
	t.Logf("  receipts %6d/day x %d CU = %9d CU  (%.0f%% bloom-hit, measured)",
		receiptsDay, cuBlockReceipts, receiptsDay*cuBlockReceipts, bloomHitRate*100)
	t.Logf("  = %d CU/day, %.2fM CU/month", cuDay, float64(cuMonth)/1e6)
	t.Logf("FLEET of %d watchtowers: %.2fM CU/month", watchtowers, float64(cuMonthFleet)/1e6)
	t.Logf("  against the free tier's 30M/month allowance: %.0f%% of it",
		100*float64(cuMonthFleet)/30e6)

	weekCU := weekBlocks*cuBlockByNumber + int(float64(weekBlocks)*bloomHitRate)*cuBlockReceipts
	t.Logf("")
	t.Logf("ONE-WEEK CATCH-UP: %d headers + %d receipt fetches = %.2fM CU = $%.2f",
		weekBlocks, int(float64(weekBlocks)*bloomHitRate), float64(weekCU)/1e6,
		float64(weekCU)/1e6*usdPerMillionCU)

	t.Logf("")
	t.Logf("COST at $%.2f/M CU (PAYG, first 300M):", usdPerMillionCU)
	t.Logf("  steady state, fleet : $%.2f/month", float64(cuMonthFleet)/1e6*usdPerMillionCU)
	t.Logf("  + one catch-up/month: $%.2f/month",
		(float64(cuMonthFleet)+float64(weekCU))/1e6*usdPerMillionCU)

	// THE POINT: volume was never the constraint. Throughput was.
	t.Logf("")
	t.Logf("WHY THE UPGRADE IS ABOUT THROUGHPUT, NOT VOLUME:")
	t.Logf("  eth_getBlockReceipts bills %d CU but costs %d THROUGHPUT CU",
		cuBlockReceipts, cuThroughputReceipts)
	t.Logf("  free tier %d CU/s  -> %.1f receipt fetches/sec",
		cuThroughputPerSecFree, float64(cuThroughputPerSecFree)/cuThroughputReceipts)
	t.Logf("  PAYG      %d CU/s -> %.0f receipt fetches/sec (%.0fx)",
		cuThroughputPerSecPAYG, float64(cuThroughputPerSecPAYG)/cuThroughputReceipts,
		float64(cuThroughputPerSecPAYG)/cuThroughputPerSecFree)

	// A runaway is the thing an alert has to catch, so size it here.
	runawayCUperSec := float64(cuThroughputPerSecPAYG) / cuThroughputReceipts * cuBlockReceipts
	runawayDay := runawayCUperSec * 86400
	t.Logf("")
	t.Logf("RUNAWAY CEILING (a loop fetching receipts flat out at PAYG throughput):")
	t.Logf("  %.0f CU/s = %.1fM CU/day = $%.2f/day = $%.0f/month",
		runawayCUperSec, runawayDay/1e6, runawayDay/1e6*usdPerMillionCU,
		runawayDay*30/1e6*usdPerMillionCU)
	t.Logf("  ALERT RECOMMENDATION: $25/month catches that within ~2 days while")
	t.Logf("  sitting ~5x above expected spend.")

	if cuMonthFleet > 30_000_000 {
		t.Errorf("projected fleet usage %.1fM CU/month exceeds even the FREE "+
			"allowance; the volume assumption needs revisiting", float64(cuMonthFleet)/1e6)
	}
}

// The post-upgrade measurement. Requires the higher-throughput endpoint.
//
// Deliberately measures the SAME shape as the P14.5 baseline (243 ms/block, 20
// rate-limit events over 200 blocks) so the before/after is like-for-like.
func TestP146DCatchUpOnUpgradedTier(t *testing.T) {
	if os.Getenv("P146D") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P146D=1 CHAIN_PROBE=1 — needs the UPGRADED endpoint")
	}
	rpc, beaconURL := os.Getenv("ETH_RPC_URL"), os.Getenv("BEACON_API_URL")
	if rpc == "" || beaconURL == "" {
		t.Skip("set ETH_RPC_URL and BEACON_API_URL")
	}
	if sameProvider(rpc, beaconURL) {
		t.Fatalf("consensus and execution are the same provider; the reference " +
			"root must not come from whoever supplies the receipts")
	}

	gap := 2000
	if v := os.Getenv("P146D_BLOCKS"); v != "" {
		fmt.Sscanf(v, "%d", &gap)
	}

	// NO THROTTLE. The whole point is to find out whether the limit still binds.
	// MaxRetries stays non-zero so a refusal is survivable, but every refusal is
	// counted and reported — if the result depends on them, the upgrade did not
	// solve the problem and the number must say so.
	src := &RPCSource{Endpoint: rpc, MaxRetries: 5, MinInterval: 0, MaxBatch: 100}
	counted := &cuCounter{inner: src}
	beacon := &BeaconFinalizedSource{Beacon: NewBeaconClient(beaconURL), Spec: SpecAltair}

	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	defer cancel()

	head, err := beacon.FinalizedBlock(ctx)
	if err != nil {
		t.Fatalf("finalized: %v", err)
	}

	// Walk back by HASH to find an honest checkpoint, exactly as catch-up does.
	headers, err := src.HeadersDescending(ctx, head.Number, gap+1)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	expected := head.Hash
	var startCP FollowerCheckpoint
	for i, h := range headers {
		fork, err := ExecutionForkAt(1, h.Time)
		if err != nil {
			t.Fatalf("fork at %d: %v", i, err)
		}
		b, err := BlockFromParentLink(h, fork, expected)
		if err != nil {
			t.Fatalf("walk at %d: %v", i, err)
		}
		expected = b.ParentHash
		startCP = FollowerCheckpoint{BlockNumber: b.Number, BlockHash: b.Hash}
	}

	store := &FileCheckpointStore{Path: t.TempDir() + "/cp.json"}
	f := &ChainFollower{
		ChainID: 1, Contract: addr20("ae70526931FF460894133201f6C8cA91bbA0E177"),
		Headers: counted, Finalized: beacon, Store: store, BatchSize: 100,
	}
	if err := f.InitializeAt(startCP); err != nil {
		t.Fatalf("init: %v", err)
	}

	src.ResetStats()
	start := time.Now()
	prog, err := f.Advance(ctx, func(AuthenticatedBlock, []Log) error { return nil })
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("catch-up failed after %s: %v", elapsed.Round(time.Second), err)
	}
	st := src.Stats()
	hdrCalls, rcptCalls, cu := counted.totals()

	per := elapsed / time.Duration(max2(1, prog.BlocksExamined))
	t.Logf("MEASURED CATCH-UP on the upgraded tier")
	t.Logf("  %d blocks in %s = %s/block", prog.BlocksExamined,
		elapsed.Round(time.Millisecond), per.Round(time.Microsecond))
	t.Logf("  bloom-skipped %d/%d (%.0f%%), receipts fetched %d",
		prog.BlocksSkipped, prog.BlocksExamined,
		100*float64(prog.BlocksSkipped)/float64(max2(1, prog.BlocksExamined)),
		prog.BlocksFetched)
	t.Logf("")
	t.Logf("  RATE-LIMIT EVENTS: %d   retries: %d   batch shrinks: %d",
		st.RateLimited, st.Retries, st.BatchShrinks)
	if st.RateLimited == 0 {
		t.Logf("  -> the provider limit NO LONGER BINDS this workload")
	} else {
		t.Errorf("  -> the limit STILL BINDS: %d refusals. The measured time "+
			"below still contains backoff and must not be reported as clean.",
			st.RateLimited)
	}
	t.Logf("")
	t.Logf("  ACTUAL CU: %d eth_getBlockByNumber + %d eth_getBlockReceipts = %d CU",
		hdrCalls, rcptCalls, cu)
	t.Logf("  = %.4f CU/block, $%.4f for this run",
		float64(cu)/float64(max2(1, prog.BlocksExamined)),
		float64(cu)/1e6*usdPerMillionCU)

	// Extrapolate to the outage durations, from THIS measured rate.
	t.Logf("")
	t.Logf("  EXTRAPOLATED from this measured per-block rate:")
	for _, o := range []struct {
		name   string
		blocks int
	}{{"1 hour", 300}, {"24 hours", 7200}, {"1 week", 50400}} {
		d := time.Duration(o.blocks) * per
		blockCU := float64(cu) / float64(max2(1, prog.BlocksExamined)) * float64(o.blocks)
		t.Logf("    %-9s = %6d blocks: %-10s  %.2fM CU  $%.2f", o.name, o.blocks,
			d.Round(time.Second), blockCU/1e6, blockCU/1e6*usdPerMillionCU)
	}
	t.Logf("")
	t.Logf("  BASELINE (free tier, P14.5): 243 ms/block, 20 rate-limit events " +
		"over 200 blocks, 1 week = 3h24m")
	t.Logf("  IMPROVEMENT: %.1fx", 243.0/float64(per.Milliseconds()|1))
	t.Log("")
	t.Log("  THE OUTAGE BUDGET IS NOT VALIDATED BY THIS NUMBER. This measures " +
		"catch-up throughput against one provider on one day. The 4-hour Outage " +
		"term and challengePeriod remain exactly as they were.")
}

// ---------------------------------------------------------------------------
// P14.6e — what throughput does the CURRENT plan ACTUALLY provide?
//
// The published figure is 500 CU/s and eth_getBlockReceipts is documented at 500
// throughput CU, implying exactly one call per second. That is a documented
// number, not a measured one, and the two need not agree — a burst probe already
// showed 13 of 25 concurrent requests succeeding, which one-per-second does not
// predict.
//
// Measures the real sustained rate, sequentially and concurrently, and reports
// throughput SEPARATELY from monthly volume. They are different resources and
// conflating them is how the wrong plan gets bought.
// ---------------------------------------------------------------------------

type probeResult struct {
	concurrency int
	duration    time.Duration
	ok          int
	refused     int
	http429     int
}

func (p probeResult) okPerSec() float64 { return float64(p.ok) / p.duration.Seconds() }
func (p probeResult) cuPerSec() float64 { return p.okPerSec() * cuThroughputReceipts }
func (p probeResult) refusalRate() float64 {
	if p.ok+p.refused == 0 {
		return 0
	}
	return 100 * float64(p.refused) / float64(p.ok+p.refused)
}

// probePacedRate issues requests at a TARGET RATE and reports what got served.
//
// The first version of this hammered at fixed concurrency with no pacing and got
// 98-100% refusals at every rung — which measures what happens when you spam a
// provider, not what rate it will sustain. Sustainable throughput is the highest
// offered rate at which refusals stay near zero, so the rate is the independent
// variable and refusals are the reading.
func probePacedRate(t *testing.T, endpoint string, head uint64,
	perSec float64, window time.Duration) probeResult {
	t.Helper()

	// MaxRetries 0: a retry would hide the refusal, and the refusal IS the
	// measurement.
	src := &RPCSource{Endpoint: endpoint, MaxRetries: 0, MinInterval: 0}
	res := probeResult{concurrency: 1}

	interval := time.Duration(float64(time.Second) / perSec)
	deadline := time.Now().Add(window)
	start := time.Now()
	i := 0
	for time.Now().Before(deadline) {
		next := time.Now().Add(interval)
		_, err := src.ReceiptsByNumber(context.Background(), head-uint64(i%4000))
		if err == nil {
			res.ok++
		} else {
			res.refused++
		}
		i++
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
	res.duration = time.Since(start)
	res.http429 = src.Stats().RateLimited
	return res
}

func TestP146ECurrentPlanThroughput(t *testing.T) {
	if os.Getenv("P146E") == "" || os.Getenv("CHAIN_PROBE") == "" {
		t.Skip("set P146E=1 CHAIN_PROBE=1 — this deliberately trips the rate limit")
	}
	endpoint := os.Getenv("ETH_RPC_URL")
	if endpoint == "" {
		t.Skip("set ETH_RPC_URL")
	}
	src := &RPCSource{Endpoint: endpoint, MaxRetries: 3, MinInterval: 200 * time.Millisecond}
	head := p146Head(t, src)

	window := 20 * time.Second
	if v := os.Getenv("P146E_WINDOW"); v != "" {
		var secs int
		fmt.Sscanf(v, "%d", &secs)
		window = time.Duration(secs) * time.Second
	}

	t.Logf("MEASURED THROUGHPUT of the CURRENT plan — eth_getBlockReceipts")
	t.Logf("published expectation: 500 CU/s cap, 500 throughput CU/call => 1.0 call/s")
	t.Logf("")

	// Let the token bucket recover before starting, so the first rung is not
	// paying for whatever ran before it.
	time.Sleep(15 * time.Second)

	var clean float64
	for _, rate := range []float64{0.5, 1.0, 1.5, 2.0, 3.0} {
		r := probePacedRate(t, endpoint, head, rate, window)
		verdict := "CLEAN"
		if r.refused > 0 {
			verdict = "REFUSALS"
		}
		t.Logf("  offered %.1f/s: %3d ok, %3d refused (%.0f%%), %d HTTP 429 => served %.2f/s  %s",
			rate, r.ok, r.refused, r.refusalRate(), r.http429, r.okPerSec(), verdict)
		if r.refused == 0 && r.okPerSec() > clean {
			clean = r.okPerSec()
		}
		time.Sleep(15 * time.Second)
	}

	t.Logf("")
	if clean == 0 {
		t.Logf("NO RATE WAS CLEAN — even %.1f/s drew refusals.", 0.5)
	} else {
		t.Logf("HIGHEST CLEAN SUSTAINED RATE: %.2f eth_getBlockReceipts/sec", clean)
		t.Logf("  = %.0f effective throughput CU/s against a documented 500 CU/s cap",
			clean*cuThroughputReceipts)
	}
	best := probeResult{ok: int(clean * window.Seconds()), duration: window}
	_ = best

	// What that rate means for the catch-up the budget cares about.
	const weekBlocks, bloomHit = 50400, 0.20
	receiptFetches := float64(weekBlocks) * bloomHit
	t.Logf("")
	t.Logf("IMPLIED ONE-WEEK CATCH-UP at the best measured rate:")
	if clean > 0 {
		t.Logf("  %.0f receipt fetches / %.2f per sec = %s (receipts alone)",
			receiptFetches, clean,
			(time.Duration(receiptFetches/clean) * time.Second).Round(time.Minute))
	}
	t.Logf("  against the 4-hour Outage budget term")
	t.Log("")
	t.Log("THROUGHPUT AND MONTHLY VOLUME ARE SEPARATE RESOURCES. This measures " +
		"throughput only. Monthly CU is reported separately and is not a " +
		"constraint at our volume.")
}
