// Package computeworker runs a submitted program on this machine, under the
// operator's own limits.
//
// This is the piece that was missing between the site's arcade queue and a
// volunteer's hardware: the queue could accept programs and the node could
// declare it had spare cores, and nothing connected the two.
//
// WHAT ADMISSION MEANS HERE
// -------------------------
// A submitted program runs only if THREE independent things agree:
//
//  1. the operator offered this device at all (Policy.OfferCPU / OfferGPU)
//  2. the governor says the machine is free right now (load, heat, battery,
//     hours, reserved cores)
//  3. there is a slot — one job at a time per device
//
// They are checked separately and reported separately, because they mean
// different things to whoever is waiting. "You did not offer a GPU" is
// permanent until the owner changes it; "the machine is busy" clears on its
// own; "no free slot" clears in seconds. Collapsing them into one "unavailable"
// makes a permanent refusal look like a queue.
//
// WHY EACH JOB IS A FRESH CONTAINER
// ---------------------------------
// The unit of isolation is the unit of work. A reused container carries
// whatever the last program left in /tmp, in its process table and in its
// environment — so one submitter's leftovers become the next submitter's
// starting state, which is both a correctness problem and an information leak
// between strangers. Creating and destroying per job costs a few hundred
// milliseconds and removes the whole class.
//
// Until M2's microVM runner can extract results, this uses the hardened
// container profile the DCS worker already uses. That is a weaker boundary than
// a VM and the roadmap says so; it is the same boundary this node already
// accepts for container deployments, so it adds no new exposure.
package computeworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
)

// Runtime is the container surface this needs. An interface so the worker is
// testable without Docker, and so a microVM backend can replace it later
// without touching admission.
type Runtime interface {
	Create(ctx context.Context, spec dcs.ContainerSpec) (string, error)
	Start(ctx context.Context, id string) error
	Wait(ctx context.Context, id string) (int, error)
	Logs(ctx context.Context, id string) (stdout, stderr []byte, err error)
	Remove(ctx context.Context, id string, force bool) error
}

// Job is a submitted program.
type Job struct {
	ID string
	// Device is "cpu" or "gpu:<api>", matching the job classes the governor
	// policy accepts.
	Device string
	// Image is a digest-pinned catalogue image. NOT submitter-chosen — until
	// M2 ships, a volunteer runs catalogue images only, and this field is set
	// by the node from the language, never from the request.
	Image       string
	Cmd         []string
	Env         []string
	Files       map[string]string
	Timeout     time.Duration
	MemoryLimit int64
}

// Result is what came back.
type Result struct {
	JobID      string `json:"job_id"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	RanSeconds int    `json:"ran_seconds"`
	TimedOut   bool   `json:"timed_out"`
	Error      string `json:"error,omitempty"`
}

// Refusal explains why a job was not admitted. A typed error rather than a
// string so the caller can tell a permanent no from a temporary one.
type Refusal struct {
	Reason string
	// Retryable distinguishes "busy, try later" from "this machine does not do
	// that". A queue that retries a permanent refusal forever is a queue that
	// never drains and never says why.
	Retryable bool
}

func (r *Refusal) Error() string { return r.Reason }

var ErrNoSlot = &Refusal{Reason: "this node is already running a job on that device", Retryable: true}

// Worker admits and runs one job at a time per device.
type Worker struct {
	runtime  Runtime
	governor *compute.Governor
	policy   compute.Policy

	mu      sync.Mutex
	running map[string]bool // device -> busy
}

func New(runtime Runtime, governor *compute.Governor, policy compute.Policy) *Worker {
	return &Worker{
		runtime:  runtime,
		governor: governor,
		policy:   policy,
		running:  map[string]bool{},
	}
}

// Admit reports whether a job would be accepted right now, without running it.
//
// Exported separately so the bridge can answer "would you take this?" without
// side effects — a queue asking every node in turn should not have to start a
// container to find out.
func (w *Worker) Admit(device string) error {
	if !w.policy.Enabled {
		return &Refusal{Reason: "this node is not lending compute", Retryable: false}
	}
	// The operator's device switch. Permanent until they change it, so the
	// caller must not retry against this node for this device.
	if !w.policy.AcceptsClass(device) {
		return &Refusal{
			Reason:    fmt.Sprintf("this node does not offer %s work", device),
			Retryable: false,
		}
	}
	if w.governor != nil {
		grant := w.governor.Decide(w.runningCount())
		if !grant.Allowed() {
			// The governor's Reason is already written for the machine's owner,
			// so it is passed through rather than reworded — and it is
			// retryable by definition: load, heat and battery all change.
			return &Refusal{Reason: grant.Reason, Retryable: true}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running[device] {
		return ErrNoSlot
	}
	return nil
}

func (w *Worker) runningCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, busy := range w.running {
		if busy {
			n++
		}
	}
	return n
}

// Run admits and executes a job, blocking until it finishes.
func (w *Worker) Run(ctx context.Context, job Job) (Result, error) {
	if err := w.Admit(job.Device); err != nil {
		return Result{JobID: job.ID}, err
	}

	// Claim the slot. Re-checked under the lock because Admit's check and this
	// claim are not atomic together, and two submissions arriving at once would
	// otherwise both pass.
	w.mu.Lock()
	if w.running[job.Device] {
		w.mu.Unlock()
		return Result{JobID: job.ID}, ErrNoSlot
	}
	w.running[job.Device] = true
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		delete(w.running, job.Device)
		w.mu.Unlock()
	}()

	if job.Timeout <= 0 {
		job.Timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, job.Timeout)
	defer cancel()

	spec := dcs.ContainerSpec{
		Name:             "compute-" + sanitise(job.ID),
		Image:            job.Image,
		Cmd:              job.Cmd,
		Env:              job.Env,
		Labels:           map[string]string{"syndichan.compute": "1"},
		MemoryLimitBytes: job.MemoryLimit,
		ReadOnlyRootfs:   true,
		// The only writable surface, and it is memory-backed so nothing
		// survives the container. A submitted program needs somewhere to work;
		// it does not need that somewhere to persist.
		TmpfsMounts: map[string]string{"/tmp": "rw,noexec,nosuid,size=256m"},
	}

	started := time.Now()
	id, err := w.runtime.Create(runCtx, spec)
	if err != nil {
		return Result{JobID: job.ID}, fmt.Errorf("computeworker: create: %w", err)
	}
	// Removal is deferred immediately after creation, so a failure to START
	// still cleans up. Ordering this after Start would leak a container on
	// every start failure.
	defer func() {
		rmCtx, rmCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer rmCancel()
		_ = w.runtime.Remove(rmCtx, id, true)
	}()

	if err := w.runtime.Start(runCtx, id); err != nil {
		return Result{JobID: job.ID}, fmt.Errorf("computeworker: start: %w", err)
	}

	code, waitErr := w.runtime.Wait(runCtx, id)
	timedOut := errors.Is(runCtx.Err(), context.DeadlineExceeded)

	// Logs are collected on EVERY path including timeout and error, using a
	// fresh context — the run context is already dead in the timeout case, and
	// the output of a program that timed out is usually the only evidence of
	// what it was doing.
	logCtx, logCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer logCancel()
	stdout, stderr, logErr := w.runtime.Logs(logCtx, id)

	result := Result{
		JobID:      job.ID,
		ExitCode:   code,
		Stdout:     string(stdout),
		Stderr:     string(stderr),
		RanSeconds: int(time.Since(started).Seconds()),
		TimedOut:   timedOut,
	}
	switch {
	case timedOut:
		result.ExitCode = -1
		result.Error = fmt.Sprintf("the job exceeded its %s limit", job.Timeout)
	case waitErr != nil:
		result.Error = waitErr.Error()
	case logErr != nil:
		// The program ran; only its output could not be read. Reported rather
		// than failing the job, because the exit code is still a real answer.
		result.Error = "output could not be collected: " + logErr.Error()
	}
	return result, nil
}

// sanitise makes a job id safe as a container name.
func sanitise(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if len(out) > 48 {
		out = out[:48]
	}
	if out == "" {
		out = "job"
	}
	return out
}
