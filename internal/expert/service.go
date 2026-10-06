// Package expert exposes this node's local praxis experts to the dendritic network.
//
// A remote praxis node reaches our experts by dialing  <our-addr>.key.axon/expert/<uid>/forward
// (and /train) through the AXON loopback proxy -- see deps/praxis-shim/dendritic_expert.py. This
// package is the listener behind that address: it reverse-proxies /expert/<uid>/forward|train to a
// local praxis expert backend (the praxis Node sidecar, default 127.0.0.1:7777, which serves that
// exact protocol: POST /expert/<uid>/forward {"ids":[...]} -> {"logits":[...]}).
//
// The node serves this handler in two places (see cmd/dendritic-node):
//   - on its AXON hidden service (reachable by peers as <addr>.key.axon/expert/...), and
//   - on a loopback listener for same-host praxis + local testing.
//
// It carries no model itself -- it is the network-facing door to whatever praxis instance runs beside
// the node. Facilitators who run a praxis node this way earn CREDIT via the ServiceAgentInference
// proof-of-facilitation design (see the anonymOS AI_SOFTWARE_FACTORY_ROADMAP).
package expert

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// DefaultBackend is the praxis Node sidecar's expert API on the same host.
const DefaultBackend = "http://127.0.0.1:7777"

// Handler reverse-proxies /expert/* to the praxis expert backend, and answers /expert/health.
// backend is a base URL like "http://127.0.0.1:7777"; empty uses DefaultBackend.
func Handler(backend string) http.Handler {
	if backend == "" {
		backend = DefaultBackend
	}
	target, err := url.Parse(backend)
	mux := http.NewServeMux()

	mux.HandleFunc("/expert/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": err == nil, "backend": backend})
	})

	if err == nil {
		rp := httputil.NewSingleHostReverseProxy(target)
		rp.FlushInterval = 100 * time.Millisecond
		base := rp.Director
		rp.Director = func(req *http.Request) {
			base(req)
			req.Host = target.Host
		}
		rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, e error) {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": "praxis expert backend unreachable at " + backend + ": " + e.Error()})
		}
		// Only /expert/<uid>/forward and /expert/<uid>/train are forwarded; everything else is 404.
		mux.HandleFunc("/expert/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/forward") || strings.HasSuffix(r.URL.Path, "/train") {
				rp.ServeHTTP(w, r)
				return
			}
			http.Error(w, "only /expert/<uid>/forward and /expert/<uid>/train are served", http.StatusNotFound)
		})
	}
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
