package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/dcs"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// This file is the BRIDGE: a small, loopback-only HTTP API that a website runs
// against so its users can deploy containers to the network without every user
// running a node. The site's backend (services/attack_range.py's NodeBridgeClient)
// is the only caller.
//
// Why a bridge and not one-node-per-user: the site has thousands of users and one
// I2P node. The node deploys on each user's behalf, sub-accounting them by an
// opaque "on_behalf_of" tag so the worker's one-container-per-user rule keys on
// the real user, not on the shared bridge identity. The worker trusts this node
// to name its sub-owners honestly because the operator put the bridge node's ID
// in the worker's TrustedBrokers list -- exactly the same trust boundary as a
// company deploying for its employees through one service account.
//
// It binds loopback (or a cluster-internal address the operator chooses) and is
// NOT authenticated at the HTTP layer: the deployment model is that only the
// co-located site process can reach it. Do not expose cfg.DCS.APIListen publicly.

// bridgeAPI holds the long-lived node substrate the HTTP handlers deploy through.
type bridgeAPI struct {
	node    *p2p.Node
	store   *store.Store
	manager *dcs.Manager
	blobs   dcs.BlobStore
	logger  *log.Logger
}

// startDCSBridge opens (reuses) the node and serves the loopback deploy API. It
// runs only when cfg.DCS.APIListen is set. Unlike the worker, the bridge does
// not need Docker -- it never runs a container itself; it asks workers to.
func startDCSBridge(ctx context.Context, cfg config.Config, node *p2p.Node, storage *store.Store, logger *log.Logger) {
	if cfg.DCS.APIListen == "" {
		return
	}
	if node == nil || storage == nil {
		logger.Printf("dcs-bridge: API requires full storage mode (host + DHT + store); not started")
		return
	}
	if err := node.ConfigureDCSRecords(dcs.WorkerDHTValidator{}); err != nil {
		// Harmless if the worker path already registered it; only the first wins.
		logger.Printf("dcs-bridge: worker record validator: %v", err)
	}

	api := &bridgeAPI{
		node:    node,
		store:   storage,
		manager: dcs.NewManager(node, dcs.NewStreamTransport(node.Host())),
		blobs:   NewStoreBlobStore(storage),
		logger:  logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", api.handleHealth)
	mux.HandleFunc("/dcs/blob", api.handleBlob)     // PUT: publish a build context
	mux.HandleFunc("/dcs/deploy", api.handleDeploy) // POST: deploy for a user
	mux.HandleFunc("/dcs/status", api.handleStatus) // POST: poll a queued deploy
	mux.HandleFunc("/dcs/destroy", api.handleDestroy)

	srv := &http.Server{
		Addr:              cfg.DCS.APIListen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.DCS.APIListen)
	if err != nil {
		logger.Printf("dcs-bridge: cannot listen on %s: %v", cfg.DCS.APIListen, err)
		return
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	go func() {
		logger.Printf("dcs-bridge: deploy API listening on %s (loopback/cluster-internal only)", cfg.DCS.APIListen)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Printf("dcs-bridge: serve: %v", err)
		}
	}()
}

func (api *bridgeAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"node": api.node.ID(),
	})
}

// handleBlob stores a pre-packed build context (a gzip tar produced by the site's
// lab_registry.pack_build_context) in the shard store and returns its digest. The
// blob is opaque, content-addressed bytes; storing it announces this node as a
// DHT provider so any worker can fetch it later by digest.
func (api *bridgeAPI) handleBlob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use PUT")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, dcs.MaxBuildContextBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	if int64(len(body)) > dcs.MaxBuildContextBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "build context too large")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	digest, err := api.blobs.PutBlob(ctx, body)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "store blob: "+err.Error())
		return
	}
	api.logger.Printf("dcs-bridge: published build context %s (%d bytes)", digest, len(body))
	writeJSON(w, http.StatusOK, map[string]any{"digest": digest, "size": len(body)})
}

// deployBody is the site's deploy request. Exactly one of image / build_context_digest
// is set. on_behalf_of is the site user id the worker sub-accounts by.
type deployBody struct {
	DeploymentID       string `json:"deployment_id"`
	Image              string `json:"image,omitempty"`
	BuildContextDigest string `json:"build_context_digest,omitempty"`
	Lab                bool   `json:"lab,omitempty"`
	PrimaryPort        int    `json:"primary_port,omitempty"`
	RuntimeSecs        int    `json:"runtime_secs,omitempty"`
	OnBehalfOf         string `json:"on_behalf_of"`
	Ticket             string `json:"ticket,omitempty"` // set when re-polling a queued deploy
	// When re-polling a queued deploy, the site names the worker its ticket is
	// held on so promotion returns to that exact worker (a reservation lives on
	// one worker, not the whole network). A first deploy leaves these empty and
	// the bridge picks a random worker.
	WorkerNode        string `json:"worker_node,omitempty"`
	WorkerDestination string `json:"worker_destination,omitempty"`
}

// deployResult is DeployReply plus which worker handled it, so the site can
// persist the (worker, container) pair and later poll or destroy it.
type deployResult struct {
	dcs.DeployReply
	WorkerNode        string `json:"worker_node"`
	WorkerDestination string `json:"worker_destination"`
}

func (api *bridgeAPI) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var body deployBody
	if !decode(w, r, &body) {
		return
	}
	if body.Image == "" && body.BuildContextDigest == "" {
		writeErr(w, http.StatusBadRequest, "pass image or build_context_digest")
		return
	}
	if body.OnBehalfOf == "" {
		writeErr(w, http.StatusBadRequest, "on_behalf_of is required (the site user id)")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	req := dcs.DeployRequest{
		DeploymentID:       body.DeploymentID,
		Image:              body.Image,
		BuildContextDigest: body.BuildContextDigest,
		Lab:                body.Lab,
		PrimaryPort:        body.PrimaryPort,
		RuntimeSecs:        body.RuntimeSecs,
		OnBehalfOf:         body.OnBehalfOf,
		Ticket:             body.Ticket,
	}
	if req.DeploymentID == "" {
		req.DeploymentID = "bridge-" + short(api.node.ID()) + "-" + shortTime()
	}

	// Re-poll of a queued deploy: go back to the exact worker holding the ticket.
	if body.WorkerNode != "" && body.Ticket != "" {
		worker := dcs.WorkerRecord{NodeID: body.WorkerNode, Destination: body.WorkerDestination}
		reply, err := api.manager.DeployTo(ctx, worker, req)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "deploy: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, deployResult{
			DeployReply:       reply,
			WorkerNode:        worker.NodeID,
			WorkerDestination: worker.Destination,
		})
		return
	}

	// First deploy: pick a random eligible worker.
	workers, err := api.node.FindDCSWorkers(ctx, 32)
	if err != nil || len(workers) == 0 {
		writeErr(w, http.StatusServiceUnavailable, "no container workers on the network")
		return
	}
	reply, worker, err := api.manager.DeployToRandom(ctx, workers, req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "deploy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, deployResult{
		DeployReply:       reply,
		WorkerNode:        worker.NodeID,
		WorkerDestination: worker.Destination,
	})
}

// workerRef targets a specific worker for status/destroy. The site persisted
// these from the deploy reply.
type workerRef struct {
	WorkerNode        string `json:"worker_node"`
	WorkerDestination string `json:"worker_destination"`
	Ticket            string `json:"ticket,omitempty"`
	ContainerID       string `json:"container_id,omitempty"`
}

func (ref workerRef) record() dcs.WorkerRecord {
	return dcs.WorkerRecord{NodeID: ref.WorkerNode, Destination: ref.WorkerDestination}
}

func (api *bridgeAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	var ref workerRef
	if !decode(w, r, &ref) {
		return
	}
	if ref.WorkerNode == "" || ref.Ticket == "" {
		writeErr(w, http.StatusBadRequest, "worker_node and ticket are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	reply, err := api.manager.Status(ctx, ref.record(), ref.Ticket)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "status: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reply)
}

func (api *bridgeAPI) handleDestroy(w http.ResponseWriter, r *http.Request) {
	var ref workerRef
	if !decode(w, r, &ref) {
		return
	}
	if ref.WorkerNode == "" || ref.ContainerID == "" {
		writeErr(w, http.StatusBadRequest, "worker_node and container_id are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := api.manager.Destroy(ctx, ref.record(), ref.ContainerID); err != nil {
		writeErr(w, http.StatusBadGateway, "destroy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- helpers ----

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "use POST")
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
