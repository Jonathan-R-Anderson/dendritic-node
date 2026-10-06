package expert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerProxiesForwardToBackend(t *testing.T) {
	// a fake praxis expert backend that answers /expert/<uid>/forward
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/expert/abc/forward" || r.Method != http.MethodPost {
			t.Errorf("backend got unexpected %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "\"ids\"") {
			t.Errorf("backend did not receive the ids payload: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"logits":[0.1,0.2,0.3]}`))
	}))
	defer backend.Close()

	h := Handler(backend.URL)

	// /expert/health
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/expert/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health: want 200, got %d", rec.Code)
	}
	var health map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &health)
	if health["ok"] != true {
		t.Fatalf("health: want ok=true, got %v", health)
	}

	// /expert/<uid>/forward is proxied to the backend
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/expert/abc/forward", strings.NewReader(`{"ids":[1,2,3]}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("forward: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "logits") {
		t.Fatalf("forward: backend logits not returned: %s", rec.Body.String())
	}
}

func TestHandlerRejectsNonForwardTrain(t *testing.T) {
	h := Handler("http://127.0.0.1:1") // backend unused for this path
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/expert/abc/bogus", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("bogus expert path: want 404, got %d", rec.Code)
	}
}

func TestHandlerBadBackendReturns502(t *testing.T) {
	h := Handler("http://127.0.0.1:1") // nothing listening
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/expert/abc/forward", strings.NewReader(`{"ids":[1]}`)))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("unreachable backend: want 502, got %d", rec.Code)
	}
}
