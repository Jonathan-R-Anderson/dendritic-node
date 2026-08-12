package channel

// Measuring the chain terms of the challenge budget — roadmap P12.
//
// validation.go refuses to produce a deployable challengePeriod until every
// term that makes a claim about the world has evidence. This is how two of
// those claims get measured, and — as importantly — it is where the ones that
// CANNOT be measured this way are written down.
//
//	reorg depth   measurable here, read-only, by watching the head
//	rpc failure   measurable here, read-only, by watching the endpoints
//
//	inclusion     NOT measurable here. Needs transactions actually sent on the
//	repricing     target chain from a funded account, because the thing being
//	              measured is what the network does with a real transaction.
//	              A read-only probe can observe fee markets and block times,
//	              which is context, not evidence.
//
//	detection     measurable, but by running the watchtower at the channel
//	              count this deployment will hold — not by asking the chain.
//	outage        an operational commitment, not a property of any network.
//
// Guessing at the four unmeasurable ones from the two measurable ones would be
// exactly the move the gate exists to stop.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ReorgObservation is what watching the head found.
type ReorgObservation struct {
	// MaxDepth is the deepest reorganisation seen: how many blocks had to be
	// discarded. Zero means none were observed, which is NOT the same as none
	// being possible — see Evidence.
	MaxDepth int
	// Blocks and Reorgs are the sample size and the number of events.
	Blocks, Reorgs int
	// MaxDepthTime is the wall-clock equivalent of MaxDepth at the observed
	// block interval, which is the form the budget wants.
	MaxDepthTime time.Duration
	// BlockInterval is the mean spacing observed.
	BlockInterval time.Duration
}

// ObserveReorgs watches the chain head and reports the deepest reorganisation.
//
// Read-only, so it needs no funds and no deployed contract — it can be pointed
// at the target chain long before anything is deployed to it, which is the
// point: this measurement takes real time to gather and should be started
// early.
//
// The method is to remember the hash seen at each height. When a height comes
// back with a different hash, everything from there to the previous head was
// discarded, and that distance is the depth.
func ObserveReorgs(ctx context.Context, endpoint string, poll time.Duration, want int) (ReorgObservation, error) {
	if poll <= 0 {
		poll = time.Second
	}
	client := &http.Client{Timeout: 15 * time.Second}
	seen := map[uint64]string{}
	out := ReorgObservation{}

	var highest uint64
	var firstAt, lastAt time.Time

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for out.Blocks < want {
		select {
		case <-ctx.Done():
			// A cancelled observation still reports what it saw. Losing an
			// hour's sampling because the window closed would make this
			// unusable for exactly the long runs it needs.
			return finishObservation(out, firstAt, lastAt, highest), ctx.Err()
		case <-ticker.C:
		}

		number, hash, err := headBlock(ctx, client, endpoint)
		if err != nil {
			continue // an endpoint blip is not an observation
		}
		previous, known := seen[number]
		switch {
		case !known:
			seen[number] = hash
			if number > highest {
				if firstAt.IsZero() {
					firstAt = time.Now()
				}
				lastAt = time.Now()
				out.Blocks += int(number - highest)
				if highest == 0 {
					out.Blocks = 1
				}
				highest = number
			}
		case previous != hash:
			// This height has been rewritten. Everything from here to the head
			// we had is gone.
			depth := int(highest-number) + 1
			out.Reorgs++
			if depth > out.MaxDepth {
				out.MaxDepth = depth
			}
			seen[number] = hash
		}
	}
	return finishObservation(out, firstAt, lastAt, highest), nil
}

func finishObservation(out ReorgObservation, firstAt, lastAt time.Time, highest uint64) ReorgObservation {
	if out.Blocks > 1 && !firstAt.IsZero() && lastAt.After(firstAt) {
		out.BlockInterval = lastAt.Sub(firstAt) / time.Duration(out.Blocks-1)
	}
	out.MaxDepthTime = time.Duration(out.MaxDepth) * out.BlockInterval
	return out
}

func headBlock(ctx context.Context, client *http.Client, endpoint string) (uint64, string, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", ID: 1, Method: "eth_getBlockByNumber",
		Params: []any{"latest", false},
	})
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	var parsed struct {
		Result *struct {
			Number string `json:"number"`
			Hash   string `json:"hash"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return 0, "", err
	}
	if parsed.Result == nil {
		return 0, "", fmt.Errorf("chainprobe: no block in the reply")
	}
	var number uint64
	if _, err := fmt.Sscanf(strings.TrimPrefix(parsed.Result.Number, "0x"), "%x", &number); err != nil {
		return 0, "", err
	}
	return number, parsed.Result.Hash, nil
}

// EndpointHealth is one RPC endpoint's behaviour under sampling.
type EndpointHealth struct {
	Endpoint string
	Attempts int
	Failures int
	// WorstLatency is the slowest successful reply. The budget wants a worst
	// case, so a mean would understate it by design.
	WorstLatency time.Duration
}

// FailoverObservation is what a set of endpoints did together.
type FailoverObservation struct {
	Endpoints []EndpointHealth
	// WorstFailover is the longest time taken to get an answer from SOMEBODY,
	// which is what the rpc-failure term actually budgets for.
	WorstFailover time.Duration
	// AllFailed counts rounds where no endpoint answered. Any at all means the
	// rpc-failure term cannot be validated: there is no bound on a wait that
	// nobody ends.
	AllFailed int
}

// ObserveFailover samples every endpoint in order and times how long it takes
// to get an answer from any of them.
//
// The order matters and is the deployment's own: this measures the failover
// path as configured, not an idealised one. An operator running this against a
// single endpoint will find AllFailed climbing the moment that endpoint blinks,
// which is the correct and useful result — the budget's rpc term explicitly
// assumes more than one.
func ObserveFailover(ctx context.Context, endpoints []string, rounds int, gap time.Duration) FailoverObservation {
	out := FailoverObservation{}
	health := make([]EndpointHealth, len(endpoints))
	for i, e := range endpoints {
		health[i].Endpoint = e
	}
	client := &http.Client{Timeout: 15 * time.Second}

	for round := 0; round < rounds; round++ {
		if round > 0 && gap > 0 {
			select {
			case <-ctx.Done():
				out.Endpoints = health
				return out
			case <-time.After(gap):
			}
		}
		started := time.Now()
		answered := false
		for i, endpoint := range endpoints {
			health[i].Attempts++
			at := time.Now()
			if _, _, err := headBlock(ctx, client, endpoint); err != nil {
				health[i].Failures++
				continue
			}
			if latency := time.Since(at); latency > health[i].WorstLatency {
				health[i].WorstLatency = latency
			}
			answered = true
			break // failover stops at the first endpoint that answers
		}
		if !answered {
			out.AllFailed++
			continue
		}
		if took := time.Since(started); took > out.WorstFailover {
			out.WorstFailover = took
		}
	}
	out.Endpoints = health
	return out
}

// AsEvidence turns a reorg observation into a validation record.
//
// Refuses when nothing was observed. "We watched for an hour and saw no
// reorganisation" bounds nothing — the budget term is a worst case, and the
// worst case of an empty sample is unknown, not zero. This is the single
// easiest place to accidentally validate a term with an absence of data.
func (o ReorgObservation) AsEvidence(chainID int64, takenAt int64) (Evidence, error) {
	if o.Reorgs == 0 {
		return Evidence{}, fmt.Errorf(
			"chainprobe: %d blocks with no reorganisation observed; "+
				"an absence of events does not bound the depth of one", o.Blocks)
	}
	return Evidence{
		Term: "reorg depth", Measured: o.MaxDepthTime, Samples: o.Blocks,
		ChainID: chainID, TakenAt: takenAt,
		Method: fmt.Sprintf("head-tracking over %d blocks; %d reorgs, deepest %d blocks at %s spacing",
			o.Blocks, o.Reorgs, o.MaxDepth, o.BlockInterval),
	}, nil
}

// AsEvidence turns a failover observation into a validation record.
func (o FailoverObservation) AsEvidence(chainID int64, takenAt int64) (Evidence, error) {
	if len(o.Endpoints) < 2 {
		return Evidence{}, fmt.Errorf(
			"chainprobe: %d endpoint(s); the rpc-failure term assumes failover is possible",
			len(o.Endpoints))
	}
	if o.AllFailed > 0 {
		return Evidence{}, fmt.Errorf(
			"chainprobe: %d round(s) where no endpoint answered; that is an unbounded wait, not a measured one",
			o.AllFailed)
	}
	attempts := 0
	for _, e := range o.Endpoints {
		attempts += e.Attempts
	}
	return Evidence{
		Term: "rpc failure", Measured: o.WorstFailover, Samples: attempts,
		ChainID: chainID, TakenAt: takenAt,
		Method: fmt.Sprintf("failover sampling across %d endpoints", len(o.Endpoints)),
	}, nil
}
