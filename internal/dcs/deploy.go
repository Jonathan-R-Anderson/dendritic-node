package dcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DeployRequest is the payload of a Launch envelope: what the deployer wants
// run, and under what constraints. It is signed inside the envelope by the
// owner, so the worker's audit log records exactly who asked for what.
type DeployRequest struct {
	DeploymentID string   `json:"deployment_id"`
	Image        string   `json:"image"` // digest-pinned reference
	Cmd          []string `json:"cmd,omitempty"`
	Env          []string `json:"env,omitempty"`
	Lab          bool     `json:"lab"`          // deliberately-vulnerable workload
	RuntimeSecs  int      `json:"runtime_secs"` // requested; ceiling-clamped for lab

	MemoryLimitBytes int64 `json:"memory_limit_bytes,omitempty"`
	NanoCPUs         int64 `json:"nano_cpus,omitempty"`
	// PrimaryPort is where a portless inbound I2P stream is routed -- the
	// container's main service. Defaults to DefaultLabPort when unset.
	PrimaryPort int `json:"primary_port,omitempty"`

	// These say what the deployer wants the container REACHABLE as. For a lab
	// workload every one of them is refused (see AdmitLab), so a researcher who
	// ticks the wrong box is told, not silently given a public box.
	RequestPublish bool `json:"request_publish,omitempty"`
	RequestEgress  bool `json:"request_egress,omitempty"`
	RequestGateway bool `json:"request_gateway,omitempty"`
}

// DeployReply is what the owner gets back. For a lab deployment the Destination
// is the whole point: it is the private I2P address of the container, disclosed
// to the owner alone, which the owner then uses to reach the box (port scan,
// exploit, whatever the research is).
type DeployReply struct {
	DeploymentID string `json:"deployment_id"`
	ContainerID  string `json:"container_id"`
	Destination  string `json:"destination"` // <b32>.i2p — reach the container here
	Private      bool   `json:"private"`     // true: never published anywhere else
	ExpiresAt    int64  `json:"expires_at"`  // agent destroys it at this time
	Note         string `json:"note,omitempty"`
}

// Runtime is the container backend the agent drives. *DockerClient satisfies
// it; the interface exists so the agent is testable without a docker daemon.
type Runtime interface {
	Create(ctx context.Context, spec ContainerSpec) (string, error)
	Start(ctx context.Context, id string) error
	Remove(ctx context.Context, id string, force bool) error
}

// Allocator gives a container its own I2P destination. *AddressAllocator
// satisfies it.
type Allocator interface {
	Allocate(ctx context.Context, containerID string, private bool) (*ContainerAddress, error)
	Release(containerID string, purge bool) error
}

// NetworkAttacher bridges a started container's I2P destination to its network
// namespace, so the returned address actually reaches the container. It is
// injected so the agent stays testable without root, docker or a SAM bridge;
// the production wiring is BuildContainerNetwork (network_attach.go).
//
// primaryPort is the container's main service port -- where a portless inbound
// stream is routed. The attacher returns a handle the agent keeps for teardown.
type NetworkAttacher interface {
	Attach(ctx context.Context, containerID string, primaryPort int) (NetworkHandle, error)
}

// NetworkHandle detaches a container's network on stop/destroy.
type NetworkHandle interface {
	Detach()
}

// AuditSink records what strangers did with the worker's hardware. The agent
// never proceeds without logging the decision first, so a crash mid-launch
// still leaves a record of what was attempted.
type AuditSink interface {
	Record(entry AuditEntry)
}

type AuditEntry struct {
	At           time.Time
	Requester    string // owner node ID
	DeploymentID string
	Method       string
	Decision     string // "admitted" | "refused"
	Reason       string
	ContainerID  string
	Destination  string // recorded locally; this is the operator's own log
}

// AgentConfig is the worker operator's policy. These are the consent knobs no
// deployer can override.
type AgentConfig struct {
	AcceptsLab     bool
	LabMaxRuntime  time.Duration
	OwnerAllowlist []string // empty = any owner
	NodeID         string   // this worker's identity, == envelope ToNode
}

func (c AgentConfig) ownerAllowed(owner string) bool {
	if len(c.OwnerAllowlist) == 0 {
		return true
	}
	for _, allowed := range c.OwnerAllowlist {
		if allowed == owner {
			return true
		}
	}
	return false
}

// Agent is the worker side. It admits a deploy request, creates the container
// with a hardened profile, gives it a private I2P destination, attaches that
// destination to the container's network namespace, and returns the address to
// the owner alone.
type Agent struct {
	cfg     AgentConfig
	runtime Runtime
	alloc   Allocator
	audit   AuditSink
	network NetworkAttacher // optional; nil means "address allocated but not bridged"
	now     func() time.Time

	mu       sync.Mutex
	attached map[string]NetworkHandle // containerID → its network, for teardown
}

func NewAgent(cfg AgentConfig, runtime Runtime, alloc Allocator, audit AuditSink) *Agent {
	return &Agent{
		cfg: cfg, runtime: runtime, alloc: alloc, audit: audit,
		now: time.Now, attached: map[string]NetworkHandle{},
	}
}

// SetNetworkAttacher wires the container-netns bridge. Without it the agent
// still allocates and returns a destination, but the container is not reachable
// at it -- useful for tests and for a dry run, honest about the difference.
func (a *Agent) SetNetworkAttacher(n NetworkAttacher) { a.network = n }

// DefaultLabPort is where a portless inbound stream is routed when the deploy
// request does not name a primary port. 80 is the common case for a web-facing
// vulnerable box; a request can override it via DeployRequest.PrimaryPort.
const DefaultLabPort = 80

var (
	ErrOwnerNotAllowed = errors.New("dcs: this worker does not accept deployments from that owner")
	ErrBadRequest      = errors.New("dcs: malformed deploy request")
)

// HandleLaunch processes a verified Launch envelope. The envelope MUST already
// have passed Envelope.Verify -- HandleLaunch trusts env.FromNode as the
// authenticated owner and does not re-check the signature.
func (a *Agent) HandleLaunch(ctx context.Context, env Envelope) (DeployReply, error) {
	owner := env.FromNode
	var req DeployRequest
	if err := env.Bind(&req); err != nil {
		a.refuse(owner, "", "bind", err.Error())
		return DeployReply{}, ErrBadRequest
	}
	if req.Image == "" || req.DeploymentID == "" {
		a.refuse(owner, req.DeploymentID, "validate", "missing image or deployment id")
		return DeployReply{}, ErrBadRequest
	}
	if !a.cfg.ownerAllowed(owner) {
		a.refuse(owner, req.DeploymentID, "authorize", "owner not on allowlist")
		return DeployReply{}, ErrOwnerNotAllowed
	}

	dep := Deployment{
		ID: req.DeploymentID, Owner: owner, Image: req.Image, Lab: req.Lab,
		RequestedRuntime: time.Duration(req.RuntimeSecs) * time.Second,
		RequestPublish:   req.RequestPublish,
		RequestEgress:    req.RequestEgress,
		RequestGateway:   req.RequestGateway,
	}

	// Lab workloads go through the containment gate; everything it refuses is
	// refused here, with the reason, before any container exists.
	var containment LabContainment
	if req.Lab {
		c, err := AdmitLab(dep, a.cfg.AcceptsLab, a.cfg.LabMaxRuntime)
		if err != nil {
			a.refuse(owner, req.DeploymentID, "admit_lab", err.Error())
			return DeployReply{}, err
		}
		containment = c
	}

	// A lab container's destination is private and never leaves the agent
	// except to this owner; a normal one may later be advertised.
	private := req.Lab

	containerID, err := a.runtime.Create(ctx, ContainerSpec{
		Name:  "dcs-" + req.DeploymentID,
		Image: req.Image, Cmd: req.Cmd, Env: req.Env,
		MemoryLimitBytes: req.MemoryLimitBytes, NanoCPUs: req.NanoCPUs,
		Lab: req.Lab,
	})
	if err != nil {
		a.refuse(owner, req.DeploymentID, "create", err.Error())
		return DeployReply{}, fmt.Errorf("create container: %w", err)
	}

	// Address BEFORE start: the container must not run for even an instant
	// without its network identity in place.
	address, err := a.alloc.Allocate(ctx, containerID, private)
	if err != nil {
		_ = a.runtime.Remove(ctx, containerID, true)
		a.refuse(owner, req.DeploymentID, "allocate_address", err.Error())
		return DeployReply{}, fmt.Errorf("allocate destination: %w", err)
	}

	if err := a.runtime.Start(ctx, containerID); err != nil {
		_ = a.alloc.Release(containerID, true)
		_ = a.runtime.Remove(ctx, containerID, true)
		a.refuse(owner, req.DeploymentID, "start", err.Error())
		return DeployReply{}, fmt.Errorf("start container: %w", err)
	}

	// Attach the container's destination to its network namespace so the
	// address we are about to hand back actually reaches the container. If no
	// attacher is wired (a dry run, or a non-Linux host), the address is still
	// returned but the note says it is not yet reachable, rather than implying
	// a connection that will not work.
	reachable := false
	if a.network != nil {
		primary := req.PrimaryPort
		if primary <= 0 {
			primary = DefaultLabPort
		}
		handle, attachErr := a.network.Attach(ctx, containerID, primary)
		if attachErr != nil {
			_ = a.alloc.Release(containerID, true)
			_ = a.runtime.Remove(ctx, containerID, true)
			a.refuse(owner, req.DeploymentID, "attach_network", attachErr.Error())
			return DeployReply{}, fmt.Errorf("attach network: %w", attachErr)
		}
		a.mu.Lock()
		a.attached[containerID] = handle
		a.mu.Unlock()
		reachable = true
	}

	// Disclose the destination to the owner -- the single, audited revelation.
	destination, err := address.Disclose(owner, "launch result", a.now())
	if err != nil {
		return DeployReply{}, err
	}

	reply := DeployReply{
		DeploymentID: req.DeploymentID,
		ContainerID:  containerID,
		Destination:  destination,
		Private:      private,
	}
	if req.Lab {
		reply.ExpiresAt = containment.ExpiresAt(a.now()).Unix()
		reply.Note = "lab workload: no egress, no gateway, destroyed at expiry"
	}
	if !reachable {
		reply.Note = strings.TrimSpace(reply.Note + " (address allocated but not yet bridged on this host)")
	}

	a.audit.Record(AuditEntry{
		At: a.now(), Requester: owner, DeploymentID: req.DeploymentID,
		Method: MethodLaunch, Decision: "admitted",
		ContainerID: containerID, Destination: destination,
	})
	return reply, nil
}

func (a *Agent) refuse(owner, deployment, phase, reason string) {
	a.audit.Record(AuditEntry{
		At: a.now(), Requester: owner, DeploymentID: deployment,
		Method: MethodLaunch, Decision: "refused",
		Reason: phase + ": " + reason,
	})
}

// ---------------------------------------------------------------------------
// Manager (deployer side)
// ---------------------------------------------------------------------------

// Transport sends a signed envelope to a worker and returns its reply envelope.
// A libp2p-stream implementation opens /syndichan/dcs/1.0.0 to the worker's
// destination; the interface keeps the deploy flow testable without I2P.
type Transport interface {
	RoundTrip(ctx context.Context, worker WorkerRecord, env Envelope) ([]byte, error)
}

// Manager runs on the deployer's node. DeployToRandom is the function behind
// "deploy to a random peer and give me its address".
type Manager struct {
	signer    EnvelopeSigner
	transport Transport
	now       func() time.Time
	rand      func() uint64
}

func NewManager(signer EnvelopeSigner, transport Transport) *Manager {
	return &Manager{signer: signer, transport: transport, now: time.Now, rand: RandUint64}
}

// DeployToRandom picks a random worker from the supplied records (already read
// from the DHT by the caller), sends it a signed Launch, and returns the
// container's I2P destination.
//
// The records are passed in rather than fetched here so the DHT dependency
// stays at the edges and this core is pure. For a lab deployment the returned
// DeployReply.Destination is the private address the caller wanted -- the thing
// to point a port scanner at.
func (m *Manager) DeployToRandom(ctx context.Context, records []WorkerRecord, req DeployRequest) (DeployReply, WorkerRecord, error) {
	capabilities := []string{"worker"}
	if req.Lab {
		// A lab workload must land on a worker whose operator opted into lab
		// hosting; a plain worker never sees it.
		capabilities = []string{"worker", "lab"}
	}
	worker, err := PickRandom(records, Requirement{
		Capabilities: capabilities,
		MinRAMBytes:  req.MemoryLimitBytes,
	}, m.now(), m.rand)
	if err != nil {
		return DeployReply{}, WorkerRecord{}, err
	}

	env, err := NewEnvelope(m.signer, worker.NodeID, MethodLaunch, req, m.now())
	if err != nil {
		return DeployReply{}, worker, err
	}
	raw, err := m.transport.RoundTrip(ctx, worker, env)
	if err != nil {
		return DeployReply{}, worker, fmt.Errorf("launch on %s: %w", worker.NodeID, err)
	}
	var reply DeployReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return DeployReply{}, worker, fmt.Errorf("decode reply: %w", err)
	}
	if reply.Destination == "" {
		return DeployReply{}, worker, errors.New("dcs: worker returned no destination")
	}
	return reply, worker, nil
}
