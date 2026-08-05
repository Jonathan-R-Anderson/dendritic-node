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

import (
	"context"
	"errors"
	"log"
	"net/http"
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

type computeAPI struct {
	worker *computeworker.Worker
	// micro runs ARBITRARY code. Nil when this node cannot — which is the
	// common case, and why every arbitrary request checks it rather than
	// assuming a fallback exists.
	micro *computeworker.MicroVMExecutor
	// isolation is what this node honestly offers.
	isolation computeworker.Isolation

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
	if !req.Arbitrary {
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
		writeJSON(w, http.StatusOK, map[string]any{"ticket": req.JobID, "accepted": true})
		return
	}
	c.running[req.JobID] = true
	c.mu.Unlock()

	timeout := time.Duration(req.TimeoutSec) * time.Second
	job := computeworker.Job{
		ID:      req.JobID,
		Device:  req.Device,
		Image:   image,
		Files:   req.Files,
		Timeout: timeout,
		Env:     []string{"ENTRYPOINT=" + req.Entrypoint},
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

	writeJSON(w, http.StatusOK, map[string]any{"ticket": req.JobID, "accepted": true})
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
