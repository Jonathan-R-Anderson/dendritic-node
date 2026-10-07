package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
)

// When the origin is unreachable, the proxy retries the request against a
// discovered mirror and serves the mirror's answer, tagged X-Rabbiit-Served-Via.
func TestMirrorFallbackServesWhenOriginDown(t *testing.T) {
	originKey := make([]byte, 32)
	originKey[0] = 1
	mirrorKey := make([]byte, 32)
	mirrorKey[0] = 2
	origin := identity.FullAddress(originKey)
	mirror := identity.FullAddress(mirrorKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "MIRROR SERVED")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	srvHost := u.Host

	var originTried, mirrorTried bool
	h := New(func(_ context.Context, _, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		switch host {
		case origin:
			originTried = true
			return nil, errors.New("origin down")
		case mirror:
			mirrorTried = true
			return net.Dial("tcp", srvHost)
		default:
			return nil, errors.New("unexpected dial: " + addr)
		}
	})
	h.Mirrors = func(o string) []string {
		if o == origin {
			return []string{mirror}
		}
		return nil
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+origin+"/page", nil))

	if !originTried || !mirrorTried {
		t.Fatalf("expected origin then mirror to be dialed: origin=%v mirror=%v", originTried, mirrorTried)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "MIRROR SERVED" {
		t.Fatalf("body = %q, want mirror content", rec.Body.String())
	}
	if rec.Header().Get("X-Rabbiit-Served-Via") != "mirror" {
		t.Fatal("response not tagged as served via mirror")
	}
}

// With no mirrors known, an unreachable origin is a plain 502 — the fallback
// changes nothing when there is nothing to fall back to.
func TestNoMirrorsStillFailsCleanly(t *testing.T) {
	originKey := make([]byte, 32)
	originKey[0] = 3
	origin := identity.FullAddress(originKey)

	h := New(func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("origin down")
	})
	h.Mirrors = func(string) []string { return nil }

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+origin+"/page", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if rec.Header().Get("X-Rabbiit-Served-Via") == "mirror" {
		t.Fatal("tagged as mirror-served with no mirror")
	}
}
