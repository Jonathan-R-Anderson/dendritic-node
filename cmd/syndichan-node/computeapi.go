package main

// The loopback bridge endpoints that let a site submit compute work to this
// node. Registered on the SAME listener as the DCS bridge rather than a second
// server: same loopback restriction, same lifecycle, same thing to secure. A
// second port would be a second thing to accidentally expose.
//
// WHY THE LANGUAGE PICKS THE IMAGE, NOT THE SUBMITTER
// ---------------------------------------------------
// The request names a language; this file maps that to a digest-pinned
// catalogue image. A submitter who could name the image could name any image on
// the volunteer's machine — or any public one — and the whole catalogue rule
// exists because a container is not a boundary to run arbitrary code behind
// until M2 ships. So the mapping is a fixed table here, and an unknown language
// is refused rather than passed through.
//
// TWO KINDS OF WORK ARRIVE HERE, AND THEY ARE NOT THE SAME KIND
// -------------------------------------------------------------
// `language` names an image that RUNS A SUBMITTED PROGRAM. `workload` names an
// M10 catalogue entry (internal/compute/catalogue.go) whose code was fixed at
// image-build time and which takes only DATA. The second is what makes a
// cluster deployable today: no arbitrary code is involved at any point, so
// nothing about the M2 boundary has to move for it to run.
//
// Which is why Arbitrary stays FALSE on the workload path, unconditionally.
// Widening the catalogue must not become the mechanism by which the
// arbitrary-code boundary is relaxed by drift, and the way that would happen is
// a new workload arriving with "just let it run the user's script" as an
// implementation detail.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"github.com/syndichan/maniwani/storage-client/internal/computeworker"
	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
	"github.com/syndichan/maniwani/storage-client/internal/microvm"
)

// catalogueImages maps a language to the image that runs it.
//
// Digest pinning is left to deployment (the tag is resolved at image-build
// time) but the KEY point is that this table is closed: a language not in it is
// refused, so there is no path from a request to an arbitrary image.
// Only languages an image actually exists for (see compute-images/). Listing
// one without an image would offer a language in the UI whose jobs fail at
// dispatch — a promise the node cannot keep, made at the point a submitter
// commits to it.
var catalogueImages = map[string]string{
	"python": "registry.local/compute-python:latest",
	"go":     "registry.local/compute-go:latest",
	"c":      "registry.local/compute-c:latest",
}

// jobMemoryLimitBytes caps every container this bridge starts.
//
// Containers ran UNCAPPED until now, which is a promise to the volunteer that
// nothing here can keep: a job that allocates without bound takes the machine's
// memory, and on Linux the OOM killer's choice of victim is not guaranteed to be
// the container. The desktop the whole governor exists to protect is as likely a
// target as the job that caused it.
//
// 2 GiB rather than something tighter because the embed workload loads an ONNX
// model and its runtime, and a limit that kills honest work would look exactly
// like a node that fails everything it is given. Set here as one constant so
// there is a single place to raise it when a workload genuinely needs more —
// per-workload limits belong in the catalogue table, and can go there when a
// second workload disagrees with this number.
const jobMemoryLimitBytes = 2 << 30

type computeAPI struct {
	worker *computeworker.Worker
	// micro runs ARBITRARY code. Nil when this node cannot — which is the
	// common case, and why every arbitrary request checks it rather than
	// assuming a fallback exists.
	micro *computeworker.MicroVMExecutor
	// isolation is what this node honestly offers.
	isolation computeworker.Isolation
	// policy is the operator's consent, held here because the workload gate is
	// this file's business: the worker's copy answers device questions, and a
	// workload name is not a device.
	policy compute.Policy

	mu      sync.Mutex
	results map[string]computeworker.Result
	running map[string]bool
}

type computeSubmitRequest struct {
	JobID      string            `json:"job_id"`
	Device     string            `json:"device"`
	Language   string            `json:"language"`
	Entrypoint string            `json:"entrypoint"`
	Files      map[string]string `json:"files"`
	Stdin      string            `json:"stdin"`
	TimeoutSec int               `json:"timeout_seconds"`
	// Arbitrary means the submitter sent CODE, not data for a catalogue image.
	// The whole safety question, so it is explicit rather than inferred.
	Arbitrary bool `json:"arbitrary"`
	NeedsGPU  bool `json:"needs_gpu"`

	// Workload names an M10 catalogue entry, and is the DATA-ONLY path. When
	// set it replaces Language: the node resolves the name against
	// compute.Workloads and refuses anything not in it.
	Workload string `json:"workload"`
	// Params are the knobs the workload image exposes. Values only — no
	// command, no entrypoint, no environment the image did not declare. They
	// are part of the work unit's digest, so two submissions that differ by a
	// param are two units rather than one.
	Params map[string]string `json:"params"`
	// Seed makes a workload's randomness reproducible. Present even for work
	// that draws no randomness, because a verifier re-executing a unit must be
	// able to reproduce every input to it, and a seed chosen by the runtime is
	// not one of them.
	Seed int64 `json:"seed"`
}

// handleAdmit answers "would you take this?" without running anything.
//
// Separate from submit so a scheduler can poll several nodes cheaply. Starting
// a container to discover a node is busy would cost more than the answer.
func (c *computeAPI) handleAdmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req computeSubmitRequest
	if !decode(w, r, &req) {
		return
	}
	if err := c.worker.Admit(req.Device); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"admitted":  false,
			"reason":    err.Error(),
			"retryable": retryable(err),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"admitted": true})
}

// handleSubmit accepts a job and runs it in the background.
//
// Returns immediately with a ticket rather than blocking for the whole run: a
// site request thread must not be held for a minute of compute, and the site
// already polls for DCS deploys the same way.
func (c *computeAPI) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req computeSubmitRequest
	if !decode(w, r, &req) {
		return
	}
	if req.JobID == "" {
		writeErr(w, http.StatusBadRequest, "job_id is required")
		return
	}
	// The isolation rule, checked before anything else about the job. A node
	// without a microVM must refuse arbitrary code rather than fall back to a
	// container — the fallback is precisely what the rule forbids.
	payload := computeworker.Payload{
		Arbitrary: req.Arbitrary, Files: req.Files,
		Entrypoint: req.Entrypoint, NeedsGPU: req.NeedsGPU,
	}
	// The ticket the site gets back. The job id by default, so language jobs
	// keep the behaviour compute_bridge already depends on; a catalogue workload
	// replaces it with its unit digest below.
	ticket := req.JobID
	// timeout carries the unit's deadline for workload jobs, so the container is
	// killed at the ceiling the unit declared rather than at the worker's
	// 60-second fallback — a 600-second embed run would otherwise be reaped four
	// fifths of the way through and look like a node that fails everything.
	timeout := time.Duration(req.TimeoutSec) * time.Second
	// The files this job PRODUCES, taken from the catalogue and from nowhere
	// else — a submitter who could name an output path could ask this node to
	// read one back out of the container.
	//
	// Empty for a language job, whose answer is its stdout. Set for a workload,
	// whose answer is a file: the worker only fetches paths it was given, so a
	// workload dispatched without this ran correctly, wrote its result, and had
	// it deleted with the container. The site then got a digest and no vectors.
	var outputs []string
	requireOutputs := false
	switch {
	case req.Arbitrary && req.Workload != "":
		// Incoherent, and refused rather than resolved in either direction. A
		// catalogue workload runs fixed code over submitted data; arbitrary means
		// the submitter sent code. Silently picking one would make the
		// arbitrary-code boundary depend on which branch happened to be first,
		// which is exactly how such a boundary erodes.
		writeErr(w, http.StatusBadRequest,
			"a request is either arbitrary code or a catalogue workload, not both")
		return
	case req.Arbitrary:
		// Nothing to resolve: arbitrary code names no catalogue image, and the
		// isolation check below is what decides whether it may run at all.
	case req.Workload != "":
		workload, known := compute.LookupWorkload(req.Workload)
		if !known {
			// Closed table, same rule as the language one: an unknown workload
			// is refused, never forwarded as an image name. Note the response
			// says only what was asked for — echoing a resolved image here would
			// tell a prober what this node has.
			writeErr(w, http.StatusBadRequest, "unsupported workload: "+req.Workload)
			return
		}
		// The operator's per-workload consent, checked before anything is
		// started. Not retryable: this is a config the operator wrote, and it
		// will say the same thing in an hour. A queue that retried it forever
		// would never drain and never explain why.
		if !c.policy.AcceptsWorkload(workload.Name) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"admitted":  false,
				"reason":    "this node has not opted into " + workload.Name + " work",
				"retryable": false,
			})
			return
		}
		// Arbitrary stays FALSE. A workload is data for operator-chosen code,
		// and no widening of the catalogue may turn into a relaxation of that.
		payload.CatalogueImage = workload.Image
		if name := strings.TrimSpace(workload.OutputFile); name != "" {
			// Required, not merely collected: this file is what the job was
			// submitted to produce, so a run that ends without it has not
			// succeeded however cleanly it exited. See Job.RequireOutputs.
			outputs = []string{name}
			requireOutputs = true
		}
		unit, err := compute.UnitFor(workload, req.Device, req.Params, req.Seed, req.TimeoutSec)
		if err != nil {
			// A unit that does not validate cannot be verified or paid for, so
			// it is refused here rather than run and disputed later.
			writeErr(w, http.StatusBadRequest, "cannot build a work unit: "+err.Error())
			return
		}
		// The unit's digest IS the job's identity (M4). Handing it back as the
		// ticket is what makes a redistributed unit the same fact twice rather
		// than two facts — the property the whole content-addressed format
		// exists for.
		ticket = unit.Digest()
		if timeout <= 0 {
			timeout = time.Duration(unit.DeadlineSeconds) * time.Second
		}
	default:
		image, known := catalogueImages[req.Language]
		if !known {
			// Closed table: an unknown language is refused, never forwarded as
			// an image name.
			writeErr(w, http.StatusBadRequest, "unsupported language: "+req.Language)
			return
		}
		payload.CatalogueImage = image
	}
	if err := computeworker.Admit(payload, c.isolation, false); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"admitted": false, "reason": err.Error(), "retryable": false,
		})
		return
	}
	if req.Arbitrary && c.micro == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"admitted":  false,
			"reason":    "this node has no configured guest image, so it cannot run arbitrary code",
			"retryable": false,
		})
		return
	}
	image := payload.CatalogueImage
	if err := c.worker.Admit(req.Device); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"admitted":  false,
			"reason":    err.Error(),
			"retryable": retryable(err),
		})
		return
	}

	c.mu.Lock()
	if c.running[req.JobID] {
		c.mu.Unlock()
		// Resubmission of something already in flight. Answered with the same
		// ticket rather than started twice: the site retries on a timeout it
		// cannot distinguish from a lost request, and running the job again
		// would bill the work twice.
		writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket, "accepted": true})
		return
	}
	c.running[req.JobID] = true
	c.mu.Unlock()

	job := computeworker.Job{
		ID:      req.JobID,
		Device:  req.Device,
		Image:   image,
		Files:   req.Files,
		Timeout: timeout,
		// Harmless for a data-only workload — embed's run.sh ignores it — and
		// required by the language images, which read it to find the program.
		Env:            []string{"ENTRYPOINT=" + req.Entrypoint},
		Outputs:        outputs,
		RequireOutputs: requireOutputs,
		MemoryLimit:    jobMemoryLimitBytes,
	}

	arbitrary := req.Arbitrary
	go func() {
		// Background context, not the request's: the HTTP response has already
		// been sent, so cancelling with the request would kill every job the
		// instant the site stopped waiting.
		var result computeworker.Result
		var err error
		if arbitrary {
			// Arbitrary code goes to the VM, never the container path.
			result, _, err = c.micro.Run(context.Background(), job)
		} else {
			result, err = c.worker.Run(context.Background(), job)
		}
		if err != nil && result.Error == "" {
			result.Error = err.Error()
		}
		result.JobID = job.ID
		c.mu.Lock()
		c.results[job.ID] = result
		delete(c.running, job.ID)
		c.mu.Unlock()
	}()

	writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket, "accepted": true})
}

// handleResult returns a finished job, or says it is still running.
func (c *computeAPI) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		JobID string `json:"job_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	c.mu.Lock()
	result, done := c.results[req.JobID]
	stillRunning := c.running[req.JobID]
	if done {
		// Delivered once, then forgotten. Holding every result forever would
		// grow without bound, and the site is the system of record — this node
		// only needs to hand it over.
		delete(c.results, req.JobID)
	}
	c.mu.Unlock()

	switch {
	case done:
		writeJSON(w, http.StatusOK, map[string]any{"done": true, "result": result})
	case stillRunning:
		writeJSON(w, http.StatusOK, map[string]any{"done": false, "running": true})
	default:
		// Neither running nor finished: this node has never heard of it, which
		// is different from "not yet done" and the site must not poll forever.
		writeJSON(w, http.StatusNotFound, map[string]any{
			"done": false, "error": "unknown job",
		})
	}
}

// retryable reports whether a caller should try this node again.
//
// Defaults to TRUE for anything that is not a typed refusal: an unexpected
// error is more likely a transient fault than a permanent policy, and treating
// it as permanent would take a healthy node out of the pool for good.
func retryable(err error) bool {
	var refusal *computeworker.Refusal
	if errors.As(err, &refusal) {
		return refusal.Retryable
	}
	return true
}

// newComputeAPI builds the compute bridge, or returns nil when this node lends
// nothing.
//
// Nil rather than an always-refusing handler: a node that offers no compute
// should not expose the endpoints at all. Answering "no" forever still tells a
// caller the surface exists, and it is one more thing to keep correct for a
// feature the operator declined.
func newComputeAPI(cfg config.Config, logger *log.Logger) *computeAPI {
	if !cfg.Compute.Enabled || (!cfg.Compute.OfferCPU && !cfg.Compute.OfferGPU) {
		return nil
	}
	docker, err := dcs.NewDockerClient(cfg.DCS.DockerEndpoint)
	if err != nil {
		// Compute needs a container runtime. Logged and disabled rather than
		// fatal: the rest of the node — storage, gateway, DHT — is unaffected,
		// and taking the whole node down over an optional role would punish an
		// operator for opting in.
		logger.Printf("compute: no container runtime (%v); compute endpoints disabled", err)
		return nil
	}
	policy := cfg.Compute.Policy.Normalise()
	governor := compute.NewGovernor(policy, compute.Probe(compute.Options{SkipBenchmark: true}),
		compute.LinuxSensors{})
	probe := compute.Probe(compute.Options{SkipBenchmark: true})
	api := &computeAPI{
		worker:    computeworker.New(docker, governor, policy),
		isolation: computeworker.IsolationOf(probe),
		policy:    policy,
		results:   map[string]computeworker.Result{},
		running:   map[string]bool{},
	}
	// Arbitrary code needs BOTH the capability and the artifacts. Reported
	// rather than silently absent, so an operator who set one and not the other
	// learns why their node is not taking that work.
	if ok, why := cfg.Compute.CanRunArbitrary(probe.MicroVM.Isolated()); ok {
		if runner, err := microvm.NewRunner(); err == nil {
			api.micro = &computeworker.MicroVMExecutor{
				Runner:     runner,
				KernelPath: cfg.Compute.MicroVMKernel,
				RootFSPath: cfg.Compute.MicroVMRootFS,
			}
			logger.Printf("compute: arbitrary code enabled (microVM isolation)")
		} else {
			logger.Printf("compute: firecracker unavailable (%v); arbitrary code disabled", err)
		}
	} else {
		logger.Printf("compute: catalogue images only — %s", why)
	}
	return api
}
