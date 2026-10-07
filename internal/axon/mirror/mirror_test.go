package mirror

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// overlayLikeClient returns an http.Client whose transport ignores the dialed
// host and connects to target instead -- exactly what the real overlay client
// does when it routes a .axon host to the hidden service that answers for it.
func overlayLikeClient(targetHost string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, targetHost)
		},
	}}
}

func TestMirrorRequiresKeyDirAndClient(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := New(Config{Origin: "x.key.axon", Dir: t.TempDir()}, overlayLikeClient("x")); err == nil {
		t.Fatal("missing publisher key accepted")
	}
	if _, err := New(Config{Origin: "x.key.axon", PublisherKey: pub}, overlayLikeClient("x")); err == nil {
		t.Fatal("missing cache dir accepted")
	}
	if _, err := New(Config{Origin: "x.key.axon", PublisherKey: pub, Dir: t.TempDir()}, nil); err == nil {
		t.Fatal("nil client accepted")
	}
}

// The mirror serves the origin's content through the injected (overlay-style)
// transport, with the origin addressed as a .axon service -- the production
// path, minus the real overlay.
func TestMirrorServesOriginOverInjectedTransport(t *testing.T) {
	const body = "hello from the mirrored hidden service"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Rabbiit-Gateway-Fetch") == "" {
			t.Error("origin did not see the gateway-fetch marker")
		}
		_, _ = io.WriteString(w, body)
	}))
	defer origin.Close()
	originHost := mustHost(t, origin.URL)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	m, err := New(Config{
		Origin:       "abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdea.key.axon",
		PublisherKey: pub, Dir: t.TempDir(), NodeID: "node-under-test",
	}, overlayLikeClient(originHost))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://mirror/index.html", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("body = %q, want origin content %q", got, body)
	}
}

// A POST is refused: a mirror serves public reads only, so a write can never be
// silently swallowed by a volunteer.
func TestMirrorRefusesWrites(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	m, err := New(Config{Origin: "x.key.axon", PublisherKey: pub, Dir: t.TempDir()},
		overlayLikeClient("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://mirror/x", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

// Wiring: the snapshot cache is enabled (key + dir), so the mirror can hold a
// copy, and offload is carried from config.
func TestMirrorWiresSnapshotAndOffload(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	m, err := New(Config{Origin: "x.key.axon", PublisherKey: pub, Dir: t.TempDir(), Offload: true},
		overlayLikeClient("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Snapshot().Enabled() {
		t.Fatal("snapshot cache not enabled despite key+dir")
	}
	if !m.proxy.Offload {
		t.Fatal("offload not carried from config")
	}
	if m.proxy.Health == nil {
		t.Fatal("origin health not wired")
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
