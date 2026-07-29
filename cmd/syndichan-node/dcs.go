package main

import (
	"bytes"
	"context"
	"log"
	"path/filepath"
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
		NodeID:         node.ID(),
	}
	agent := dcs.NewAgent(agentCfg, docker, allocator, &logAudit{logger: logger})
	agent.SetAdmission(admission, instanceTTL(cfg))
	// Build-context deploys: fetch the Dockerfile+files from the shard store and
	// build locally, registry-free.
	agent.SetBuilder(docker, NewStoreBlobStore(storage))
	agent.SetNetworkAttacher(dcs.NewNetworkAttacher(
		&containerSessions{sam: sam, dataDir: filepath.Join(cfg.DataDir, "dcs")},
		docker, dcs.NewNamespaceDialer,
		func(format string, args ...any) { logger.Printf(format, args...) },
	))

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

	// Publish the capability record, and republish on the advertise interval so
	// the record never expires while the worker is alive.
	go advertiseWorker(ctx, cfg, node, admission, logger)

	logger.Printf("dcs: container worker started (slots=%d, lab=%t, ttl=%s)",
		cfg.DCS.Limits.MaxContainers, cfg.DCS.Role.Lab, instanceTTL(cfg))
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
		now := time.Now()
		rec := dcs.WorkerRecord{
			RecordType: "dcs_worker", ProtocolVer: 1, AgentVersion: "1.0.0",
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

// ---- adapters between the node's primitives and the dcs interfaces ----

// samOpener opens a fresh I2P destination for a container's stable address.
type samOpener struct{ sam string }

func (o *samOpener) Open(ctx context.Context, keyPath string) (dcs.Session, error) {
	return syndii2p.Open(ctx, o.sam, keyPath)
}

// containerSessions opens the accepting session a container's inbound proxy runs on.
type containerSessions struct {
	sam     string
	dataDir string
}

func (c *containerSessions) OpenForContainer(ctx context.Context, containerID string) (dcs.SessionAccepter, error) {
	keyPath := filepath.Join(c.dataDir, "containers", containerID, "i2p.destination")
	return syndii2p.Open(ctx, c.sam, keyPath)
}

// storeBlobStore stores build-context blobs in the shard store, content-addressed.
type storeBlobStore struct{ store *store.Store }

// NewStoreBlobStore adapts the shard store to dcs.BlobStore. Build contexts land
// in a dedicated bucket keyed by their digest, so the store's chunking,
// Reed-Solomon coding and DHT provider announcements carry them like any object.
func NewStoreBlobStore(s *store.Store) dcs.BlobStore { return &storeBlobStore{store: s} }

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
