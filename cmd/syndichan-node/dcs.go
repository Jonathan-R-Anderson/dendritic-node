package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
	syndii2p "github.com/syndichan/maniwani/storage-client/internal/i2p"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// This file wires the Distributed Container Service into the node binary. It is
// the seam the README's "run a container worker" instructions describe: with
// dcs.enabled and role.worker set, a storage node also becomes a DCS worker.
//
// DCS reuses the storage node wholesale -- its libp2p host for RPC over I2P, its
// DHT for worker records, its I2P bridge for per-container destinations, and its
// shard store for build contexts. It is not a second network; it is one more
// protocol on the node already running.

// startDCSWorker assembles and starts the worker. It returns without error when
// DCS is disabled or the role is not worker, so main can call it unconditionally.
// A failure to reach Docker is logged, not fatal: a node that cannot run
// containers is still a perfectly good storage node.
func startDCSWorker(ctx context.Context, cfg config.Config, node *p2p.Node, storage *store.Store, logger *log.Logger) {
	if !cfg.DCS.Enabled || !cfg.DCS.Role.Worker {
		return
	}
	if node == nil || storage == nil {
		// DCS needs the full storage node (host + DHT + I2P + store). A
		// gateway-only or probe-only process has none of these.
		logger.Printf("dcs: worker role requires full storage mode; not started")
		return
	}

	docker, err := dcs.NewDockerClient(cfg.DCS.DockerEndpoint)
	if err != nil {
		logger.Printf("dcs: worker disabled: %v", err)
		return
	}
	if err := docker.Ping(ctx); err != nil {
		logger.Printf("dcs: Docker is not reachable at %s (%v); worker not started. "+
			"The node continues as a storage node.", cfg.DCS.DockerEndpoint, err)
		return
	}

	// Per-container I2P destinations come from fresh SAM sessions on the same
	// bridge the node already uses.
	sam := cfg.I2PSAM
	allocator := dcs.NewAddressAllocator(&samOpener{sam: sam}, filepath.Join(cfg.DataDir, "dcs"))

	admission := dcs.NewAdmissionController(dcs.AdmissionConfig{
		MaxSlots:    cfg.DCS.Limits.MaxContainers,
		InstanceTTL: instanceTTL(cfg),
	})

	agentCfg := dcs.AgentConfig{
		AcceptsLab:     cfg.DCS.Role.Lab,
		LabMaxRuntime:  time.Duration(cfg.DCS.Limits.LabMaxRuntimeSeconds) * time.Second,
		OwnerAllowlist: cfg.DCS.Policy.OwnerAllowlist,
		TrustedBrokers: cfg.DCS.Policy.TrustedBrokers,
		NodeID:         node.ID(),
	}
	agent := dcs.NewAgent(agentCfg, docker, allocator, &logAudit{logger: logger})
	agent.SetAdmission(admission, instanceTTL(cfg))
	// Build-context deploys: fetch the Dockerfile+files from the shard store and
	// build locally, registry-free.
	agent.SetBuilder(docker, NewStoreBlobStore(storage))
	// Open per-object content-key grants the coordinator sealed to this node, so
	// an encrypted build context can be decrypted before it is run.
	agent.SetContentOpener(node.OpenSealedContentKey)
	agent.SetNetworkAttacher(dcs.NewNetworkAttacher(
		&containerSessions{alloc: allocator},
		docker, dcs.NewNamespaceDialer,
		func(format string, args ...any) { logger.Printf(format, args...) },
	))
	// Compose challenges (vulhub-style): run `docker compose up` for a project
	// whose files came off the DHT, pulling the images from the registry. Needs
	// the Compose CLI on the host; without it, compose deploys are refused with a
	// clear message rather than mis-run.
	composeRunner, cerr := newDockerComposeRunner(
		filepath.Join(cfg.DataDir, "dcs", "compose"), cfg.DCS.DockerEndpoint,
		func(format string, args ...any) { logger.Printf(format, args...) },
	)
	if cerr != nil {
		logger.Printf("dcs: docker compose not available; compose challenges will be refused: %v", cerr)
	} else {
		agent.SetComposeRunner(composeRunner)
		logger.Printf("dcs: docker compose runner ready")
	}

	// Register the DCS record validator and the RPC handler on the node's host.
	if err := node.ConfigureDCSRecords(dcs.WorkerDHTValidator{}); err != nil {
		logger.Printf("dcs: could not register worker record validator: %v", err)
		return
	}
	server := dcs.NewStreamServer(node.Host(), agent, node.ID())
	server.Start()

	// Auto-spin-down reaper: destroys instances past their TTL.
	reaper := dcs.NewReaper(admission, agent.Destroy,
		func(format string, args ...any) { logger.Printf(format, args...) })
	go reaper.Run(ctx)

	// Tell the heartbeat this node is now a container host, so the operator's map
	// draws its yellow role and the site sees it as DCS-capable.
	node.SetDCSWorker(true)

	// Publish the capability record, and republish on the advertise interval so
	// the record never expires while the worker is alive.
	go advertiseWorker(ctx, cfg, node, admission, logger)

	logger.Printf("dcs: container worker started (slots=%d, lab=%t, ttl=%s)",
		cfg.DCS.Limits.MaxContainers, cfg.DCS.Role.Lab, instanceTTL(cfg))
}

// nodeI2PDestination returns this node's own base32 I2P destination, taken from
// its /garlic32/<b32>/p2p/<id> address. That base32 host is exactly what a
// deployer passes to i2p.Multiaddr to dial the worker.
func nodeI2PDestination(node *p2p.Node) string {
	for _, addr := range node.Addresses() {
		parts := strings.Split(addr, "/")
		for i, part := range parts {
			if part == "garlic32" && i+1 < len(parts) && parts[i+1] != "" {
				return parts[i+1]
			}
		}
	}
	return ""
}

func instanceTTL(cfg config.Config) time.Duration {
	if cfg.DCS.Limits.MaxRuntimeSeconds > 0 {
		return time.Duration(cfg.DCS.Limits.MaxRuntimeSeconds) * time.Second
	}
	return dcs.DefaultInstanceTTL
}

// advertiseWorker publishes and periodically refreshes this node's worker record.
func advertiseWorker(ctx context.Context, cfg config.Config, node *p2p.Node, admission *dcs.AdmissionController, logger *log.Logger) {
	interval := time.Duration(cfg.DCS.AdvertiseIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ttl := int64(cfg.DCS.RecordTTLSeconds)
	if ttl <= 0 {
		ttl = 900
	}
	var sequence uint64
	publish := func() {
		sequence++
		caps := []string{"worker"}
		if cfg.DCS.Role.GPU {
			caps = append(caps, "gpu")
		}
		if cfg.DCS.Role.Volumes {
			caps = append(caps, "volumes")
		}
		if cfg.DCS.Role.Lab {
			caps = append(caps, "lab")
		}
		// The record MUST carry the node's own I2P destination -- it is the only
		// address a deployer can dial the worker at. Without it the bridge finds
		// the worker but has nothing to connect to ("invalid I2P base32
		// destination"). It comes from the node's /garlic32/<b32> address, which
		// exists once the I2P session is up (well before this runs).
		destination := nodeI2PDestination(node)
		if destination == "" {
			logger.Printf("dcs: worker not advertised yet -- I2P destination not ready")
			return
		}
		now := time.Now()
		rec := dcs.WorkerRecord{
			RecordType: "dcs_worker", ProtocolVer: 1, AgentVersion: "1.0.0",
			Destination: destination, ContentPubKey: node.ContentPublicKey(),
			Arch: config.PlatformLabel(), Capabilities: caps,
			CPUCores: cfg.DCS.Limits.MaxContainers, RAMBytes: cfg.DCS.Limits.RAMBytes,
			Slots: cfg.DCS.Limits.MaxContainers, Region: cfg.DCS.Region,
			Sequence: sequence, IssuedAt: now.Unix(), ExpiresAt: now.Unix() + ttl,
		}
		signed, err := dcs.SignWorkerRecord(node, rec)
		if err != nil {
			logger.Printf("dcs: sign worker record: %v", err)
			return
		}
		pubCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := node.PublishDCSWorker(pubCtx, signed); err != nil {
			logger.Printf("dcs: publish worker record: %v", err)
		}
	}
	publish()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publish()
		}
	}
}

// ---- the deploy client (-dcs-deploy) ----

type dcsDeployOptions struct {
	image       string
	buildDir    string
	lab         bool
	runtimeSecs int
	primaryPort int
}

// runDCSDeploy is the client side end to end: open a node, discover workers,
// deploy to a random one, poll while queued, and print the container's private
// I2P address. It is what the README's "deploy a container" instructions call.
func runDCSDeploy(cfg config.Config, opts dcsDeployOptions, logger *log.Logger) {
	if opts.image == "" && opts.buildDir == "" {
		logger.Fatal("dcs-deploy: pass -dcs-image or -dcs-build-context")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A deploy needs the full node substrate: I2P, DHT, the shard store (for a
	// build context). Open it the same way the storage path does.
	storage, err := store.Open(
		filepath.Join(cfg.DataDir, "storage"),
		cfg.DataShards, cfg.ParityShards, cfg.ChunkBytes, cfg.CapacityBytes,
	)
	if err != nil {
		logger.Fatalf("dcs-deploy: open store: %v", err)
	}
	defer storage.Close()

	logger.Printf("dcs-deploy: connecting to I2P and the DHT (this can take a minute)…")
	node, err := p2p.Open(ctx, cfg.DataDir, cfg.I2PSAM, cfg.I2PHTTPProxy, storage, logger)
	if err != nil {
		logger.Fatalf("dcs-deploy: open node: %v", err)
	}
	defer node.Close()
	if err := node.ConfigureDCSRecords(dcs.WorkerDHTValidator{}); err != nil {
		logger.Fatalf("dcs-deploy: %v", err)
	}

	req := dcs.DeployRequest{
		DeploymentID: "cli-" + short(node.ID()) + "-" + shortTime(),
		Image:        opts.image, Lab: opts.lab,
		RuntimeSecs: opts.runtimeSecs, PrimaryPort: opts.primaryPort,
	}

	// A build context: pack the directory, store it on the DHT as shards, and
	// reference it by digest so the worker builds it.
	if opts.buildDir != "" {
		files, err := loadBuildDir(opts.buildDir)
		if err != nil {
			logger.Fatalf("dcs-deploy: build context: %v", err)
		}
		digest, err := dcs.StoreBuildContext(ctx, NewStoreBlobStore(storage), files)
		if err != nil {
			logger.Fatalf("dcs-deploy: store build context: %v", err)
		}
		req.BuildContextDigest = digest
		logger.Printf("dcs-deploy: build context stored on the DHT (%s)", digest)
	}

	logger.Printf("dcs-deploy: discovering workers…")
	workers, err := node.FindDCSWorkers(ctx, 32)
	if err != nil || len(workers) == 0 {
		logger.Fatalf("dcs-deploy: no container workers found on the network")
	}
	logger.Printf("dcs-deploy: %d worker(s) available", len(workers))

	manager := dcs.NewManager(node, dcs.NewStreamTransport(node.Host()))

	// Deploy, polling through any queue. The manager picks a random worker; a
	// queued reply carries a countdown that we surface each poll.
	deadline := time.Now().Add(30 * time.Minute)
	var reply dcs.DeployReply
	var worker dcs.WorkerRecord
	for {
		reply, worker, err = manager.DeployToRandom(ctx, workers, req, nil)
		if err != nil {
			logger.Fatalf("dcs-deploy: %v", err)
		}
		if !reply.Queued {
			break
		}
		fmt.Printf("Queued on %s — position %d, about %s until a slot frees.\n",
			short(worker.NodeID), reply.Position, humaneDuration(reply.ETASeconds))
		if time.Now().After(deadline) {
			logger.Fatal("dcs-deploy: still queued after 30m; giving up")
		}
		req.Ticket = reply.Ticket
		// Refresh the worker view and wait before retrying.
		time.Sleep(15 * time.Second)
		if refreshed, rerr := node.FindDCSWorkers(ctx, 32); rerr == nil && len(refreshed) > 0 {
			workers = refreshed
		}
	}

	fmt.Println()
	fmt.Println("Container deployed.")
	fmt.Printf("  worker:       %s\n", worker.NodeID)
	fmt.Printf("  container:    %s\n", reply.ContainerID)
	fmt.Printf("  I2P address:  %s\n", reply.Destination)
	if reply.Private {
		fmt.Println("  visibility:   PRIVATE — only you were told this address")
	}
	if reply.ExpiresAt > 0 {
		fmt.Printf("  auto-expires: %s\n", time.Unix(reply.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	if reply.Note != "" {
		fmt.Printf("  note:         %s\n", reply.Note)
	}
	fmt.Println()
	fmt.Println("Reach it through your I2P proxy at the address above. It spins down on its own.")
}

func loadBuildDir(dir string) ([]dcs.BuildFile, error) {
	var files []dcs.BuildFile
	root := filepath.Clean(dir)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, _ := d.Info()
		mode := int64(0o644)
		if info != nil {
			mode = int64(info.Mode().Perm())
		}
		files = append(files, dcs.BuildFile{Path: filepath.ToSlash(rel), Mode: mode, Data: data})
		return nil
	})
	return files, err
}

func humaneDuration(seconds int64) string {
	if seconds <= 0 {
		return "moments"
	}
	d := time.Duration(seconds) * time.Second
	return d.Round(time.Second).String()
}

func shortTime() string {
	// A short, monotone-ish suffix for a deployment id. time.Now is fine here:
	// this is a CLI invocation, not one of the deterministic build paths.
	return short(dcs.BlobDigest([]byte(time.Now().UTC().Format(time.RFC3339Nano))))
}

// ---- adapters between the node's primitives and the dcs interfaces ----

// samOpener opens a fresh I2P destination for a container's stable address.
type samOpener struct{ sam string }

func (o *samOpener) Open(ctx context.Context, keyPath string) (dcs.Session, error) {
	return syndii2p.Open(ctx, o.sam, keyPath)
}

// containerSessions supplies the accepting session a container's inbound proxy
// runs on. It REUSES the session the address allocator already opened for the
// container rather than opening a second one: a container has a single I2P
// destination, and I2P rejects a second session on the same destination
// (DUPLICATED_DEST). Reusing it also guarantees the proxy accepts on the very
// destination the deployer was handed -- otherwise every port reads closed.
type containerSessions struct {
	alloc *dcs.AddressAllocator
}

// sharedAccepter hands the proxy the allocator-owned session but neutralises
// Close: the allocator's Release owns the session's lifecycle (it must outlive a
// proxy restart), so the proxy tearing down must not close the address's session.
type sharedAccepter struct{ dcs.SessionAccepter }

func (sharedAccepter) Close() error { return nil }

func (c *containerSessions) OpenForContainer(_ context.Context, containerID string) (dcs.SessionAccepter, error) {
	sess, ok := c.alloc.AcceptSession(containerID)
	if !ok {
		return nil, fmt.Errorf("dcs: no allocated i2p session for container %s", containerID)
	}
	return sharedAccepter{sess}, nil
}

// storeBlobStore stores build-context blobs in the shard store, content-addressed.
type storeBlobStore struct{ store *store.Store }

// NewStoreBlobStore adapts the shard store to dcs.BlobStore. Build contexts land
// in a dedicated bucket keyed by their digest, so the store's chunking,
// Reed-Solomon coding and DHT provider announcements carry them like any object.
//
// The bucket is (idempotently) created here: putObject refuses to write to a
// bucket that does not exist, so on a fresh or wiped store a PutBlob would fail
// with "file does not exist" until something created it.
func NewStoreBlobStore(s *store.Store) dcs.BlobStore {
	_ = s.CreateBucket(buildContextBucket)
	return &storeBlobStore{store: s}
}

const buildContextBucket = "dcs-buildctx"

func (b *storeBlobStore) PutBlob(ctx context.Context, data []byte) (string, error) {
	digest := dcs.BlobDigest(data)
	_, err := b.store.PutObject(buildContextBucket, digest, "application/x-tar", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	return digest, nil
}

func (b *storeBlobStore) GetBlob(_ context.Context, digest string) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := b.store.GetObject(buildContextBucket, digest, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// logAudit writes the worker's audit trail to the node log. It is the operator's
// record of what strangers did with their hardware.
type logAudit struct{ logger *log.Logger }

func (a *logAudit) Record(e dcs.AuditEntry) {
	a.logger.Printf("dcs audit: %s %s owner=%s deployment=%s container=%s %s",
		e.Method, e.Decision, short(e.Requester), e.DeploymentID, e.ContainerID, e.Reason)
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
