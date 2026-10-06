package exitproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowedHostRefusesPrivateByDefault(t *testing.T) {
	deny := New(false)
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.0.1", "0.0.0.0"} {
		if err := deny.allowedHost(ip); err == nil {
			t.Fatalf("exit should refuse private/loopback %s by default", ip)
		}
	}
	allow := New(true)
	if err := allow.allowedHost("127.0.0.1"); err != nil {
		t.Fatalf("exit with allowPrivate should permit 127.0.0.1: %v", err)
	}
}

// With allowPrivate (so the loopback test server is reachable), an absolute-form
// request is forwarded to the clearnet origin and its response returned.
func TestExitForwardsAbsoluteForm(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Path", r.URL.Path)
		io.WriteString(w, "clearnet-body")
	}))
	defer backend.Close()

	h := New(true) // allow loopback for the test
	req := httptest.NewRequest(http.MethodGet, backend.URL+"/hello", nil)
	req.RequestURI = ""
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "clearnet-body" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if rec.Header().Get("X-Seen-Path") != "/hello" {
		t.Fatalf("origin did not see the path: %q", rec.Header().Get("X-Seen-Path"))
	}
}

func TestExitRefusesNonProxyForm(t *testing.T) {
	h := New(true)
	rec := httptest.NewRecorder()
	// origin-form (no absolute URL) is not a proxy request
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/just/a/path", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-proxy form, got %d", rec.Code)
	}
}
