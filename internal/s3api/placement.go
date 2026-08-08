package s3api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// THE LEDGER OVER HTTP
// ====================
// The placement ledger knows which peer holds which shard, and nothing could
// read it. Not the S3 gateway, not the DCS bridge, not the loopback dashboard --
// so the site's admin purge page printed "?" for holder counts and derived shard
// counts by arithmetic on the object's size.
//
// WHY HERE AND NOT THE DASHBOARD
// ------------------------------
// The loopback dashboard is unreachable from the site three times over: the
// Service publishes only port 9000, the NetworkPolicy admits only port 9000, and
// config.go refuses a publicly-routable ui_listen. The S3 gateway is the only
// site->node channel that exists, it already has TLS and SigV4, and the site
// already builds a client for it. Exposing the ledger as an S3 QUERY
// SUBRESOURCE -- the same extension pattern the gateway already uses for
// ?policy, ?delete, ?uploads, ?uploadId -- costs no new port, no new
// credential, no NetworkPolicy edit and no second client on the site.
//
// AUTH, EXPLICITLY
// ----------------
// ServeHTTP skips SigV4 for GET/HEAD of an object in a public-read bucket, and
// it never looks at the query string. A ?placement subresource would therefore
// have been UNAUTHENTICATED on arcade, static and releases. These routes are
// listed in placementQuery() and the bypass is refused for them by name: this
// surface exposes what the node stores and can destroy it, so it is always
// signed.

// Recaller is the half of recall that needs the p2p node (streams to peers), so
// it is injected rather than reached for: the gateway is constructed with a
// *store.Store and nothing else.
type Recaller interface {
	RecallForKey(ctx context.Context, bucket, key string, shardFilter map[string]bool, reason string) (*store.RecallRecord, error)
}

// SetRecaller wires the node in, in the shape of the existing SetMeter hook.
func (s *Server) SetRecaller(r Recaller) { s.recaller = r }

// placementQuery reports whether a request is addressing the ledger surface.
// Used both to route and, crucially, to refuse the public-read auth bypass.
func placementQuery(query map[string][]string) bool {
	if _, ok := query["placement"]; ok {
		return true
	}
	_, ok := query["recall"]
	return ok
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// ledgerSummary answers GET /?placement -- the whole-node headline the admin
// page shows above the listing.
func (s *Server) ledgerSummary(w http.ResponseWriter, requestID string) {
	summary, err := s.store.PlacementStatus()
	if err != nil {
		s3Error(w, "InternalError", "Could not read the placement ledger.", 500, requestID)
		return
	}
	recalls, err := s.store.AllRecalls()
	if err != nil {
		s3Error(w, "InternalError", "Could not read the recall ledger.", 500, requestID)
		return
	}
	outstanding, holders := 0, 0
	for _, record := range recalls {
		if !record.Resolved() {
			outstanding++
		}
		holders += record.Outstanding()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"objects":               summary.Objects,
		"under_replicated":      summary.UnderReplicated,
		"fully_dispersed":       summary.FullyDispersed,
		"local_only":            summary.LocalOnly,
		"recalls":               len(recalls),
		"recalls_outstanding":   outstanding,
		"recall_holders_left":   holders,
		"recall_verb_available": true,
	})
}

// listPlacements answers GET /<bucket>?placement.
func (s *Server) listPlacements(w http.ResponseWriter, r *http.Request, bucket, requestID string) {
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	listing, err := s.store.ListPlacements(
		bucket, query.Get("prefix"), query.Get("marker"), limit, false)
	if err != nil {
		s3Error(w, "InternalError", "Could not read the placement ledger.", 500, requestID)
		return
	}
	if listing.Objects == nil {
		listing.Objects = []store.PlacementView{}
	}
	writeJSON(w, http.StatusOK, listing)
}

// objectPlacement answers GET /<bucket>/<key>?placement -- the per-shard view,
// which is the axis a per-shard delete needs.
func (s *Server) objectPlacement(w http.ResponseWriter, bucket, key, requestID string) {
	objectID, err := s.store.ObjectIDForKey(bucket, key)
	if err != nil {
		s3Error(w, "NoSuchKey", "No placement ledger row for this key.", http.StatusNotFound, requestID)
		return
	}
	view, err := s.store.PlacementFor(objectID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s3Error(w, "NoSuchKey", "No placement ledger row for this key.", http.StatusNotFound, requestID)
			return
		}
		s3Error(w, "InternalError", "Could not read the placement ledger.", 500, requestID)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// recallStatus answers GET /<bucket>/<key>?recall -- the tombstone without
// touching anything.
func (s *Server) recallStatus(w http.ResponseWriter, bucket, key, requestID string) {
	objectID, err := s.store.ObjectIDForKey(bucket, key)
	if err != nil {
		s3Error(w, "NoSuchKey", "No ledger row for this key.", http.StatusNotFound, requestID)
		return
	}
	record, err := s.store.LoadRecall(objectID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"object_id": objectID, "outstanding": 0, "shards": []any{},
			"note": "no recall is outstanding for this object",
		})
		return
	}
	writeJSON(w, http.StatusOK, recallReport(*record))
}

// recallObject answers POST /<bucket>/<key>?recall -- ask every recorded holder
// to drop the shards, and report per holder.
//
// Deliberately NOT modelled on deleteObject, which discards the store error and
// answers 204 unconditionally. There is no single success here: some holders
// delete, some refuse with a reason, some never answer, and each of those is a
// true and different outcome the operator has to see.
func (s *Server) recallObject(w http.ResponseWriter, r *http.Request, bucket, key, requestID string) {
	if s.recaller == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "recall_unavailable",
			"detail": "This node has no peer-to-peer transport attached, so it " +
				"cannot reach the holders. Shards already placed are untouched.",
		})
		return
	}
	filter := map[string]bool{}
	for _, shardID := range r.URL.Query()["shard"] {
		if len(shardID) == 64 {
			filter[shardID] = true
		}
	}
	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "operator recall"
	}
	if len(reason) > 200 {
		reason = reason[:200]
	}
	// Bounded independently of the caller's client timeout: a recall over I2P is
	// slow, and abandoning it midway would leave the tombstone right, the report
	// missing, and the operator guessing.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	record, err := s.recaller.RecallForKey(ctx, bucket, key, filter, reason)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s3Error(w, "NoSuchKey", "No ledger row for this key.", http.StatusNotFound, requestID)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"error": "recall_failed", "detail": err.Error(),
		})
		return
	}
	if record == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"outstanding": 0, "shards": []any{},
			"note": "the ledger recorded no confirmed remote holder for this object",
		})
		return
	}
	writeJSON(w, http.StatusOK, recallReport(*record))
}

// recallReport flattens a tombstone into the per-holder rows the admin page
// prints as layers.
func recallReport(record store.RecallRecord) map[string]any {
	counts := record.Counts()
	shards := make([]map[string]any, 0, len(record.Shards))
	for _, shard := range record.Shards {
		holders := make([]map[string]any, 0, len(shard.Holders))
		for _, holder := range shard.Holders {
			holders = append(holders, map[string]any{
				"peer_id": holder.PeerID, "state": holder.State,
				"detail": holder.Detail, "attempts": holder.Attempts,
			})
		}
		shards = append(shards, map[string]any{
			"shard_id": shard.ShardID, "chunk_index": shard.ChunkIndex,
			"shard_index": shard.ShardIndex, "size": shard.Size,
			"holders": holders,
		})
	}
	return map[string]any{
		"object_id": record.ObjectID, "bucket": record.Bucket, "key": record.Key,
		"reason": record.Reason, "attempts": record.Attempts,
		"outstanding": record.Outstanding(), "resolved": record.Resolved(),
		"counts": counts, "shards": shards,
	}
}
