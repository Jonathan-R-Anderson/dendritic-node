package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestPeersDirectory(t *testing.T) {
	h := New(nil)
	h.Peers = func() []string { return []string{"aaaa.key.axon", "bbbb.key.axon"} }

	rec := httptest.NewRecorder()
	// origin-form request to the proxy itself (not an absolute-form AXON request)
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/axon/peers", nil))
	if rec.Code != 200 {
		t.Fatalf("peers: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Peers []string `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("peers: bad json: %v", err)
	}
	if len(out.Peers) != 2 || out.Peers[0] != "aaaa.key.axon" {
		t.Fatalf("peers: unexpected %v", out.Peers)
	}
}

func TestPeersDirectoryEmptyWhenUnset(t *testing.T) {
	h := New(nil) // no Peers provider
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/axon/peers", nil))
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var out struct {
		Peers []string `json:"peers"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Peers == nil || len(out.Peers) != 0 {
		t.Fatalf("want empty non-nil peers, got %v", out.Peers)
	}
}
