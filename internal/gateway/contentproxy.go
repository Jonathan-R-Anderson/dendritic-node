package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ContentProxy serves site content under the GATEWAY's own hostname.
//
// WHY THIS EXISTS
// ---------------
// The SNI frontend forwards syndichan.org straight to the origin without
// decrypting it. That is safe, and it is also unmeasurable: the reader's TLS
// session ends at the origin, so every response says it came from the origin no
// matter whose machine carried it. A volunteer cannot be credited for honest
// service and cannot be caught at dishonest service, because nothing a reader
// can see distinguishes one gateway from another — or from none.
//
// This handler is the opposite trade. It terminates TLS under
// gw-<hash>.syndichan.org, fetches the object from the origin, and serves it
// under its OWN name and its OWN certificate. That means it *can* alter the
// bytes — which is the point. The origin signs content (X-Syndichan-Signature),
// so a reader can check what they were handed, and an alteration is now a thing
// that can be detected and attributed rather than a thing nobody can express.
//
// The volunteer never holds syndichan.org's private key. It holds a certificate
// for a name that is visibly its own, which is what lets a reader tell which
// party is answering.
//
// WHAT IT REFUSES TO CARRY, AND WHY THAT IS MOST OF THE DESIGN
// ------------------------------------------------------------
// An untrusted machine handling arbitrary site traffic would be a credential
// harvester with extra steps. Every rule below exists to keep the gateway
// confined to public, anonymous, verifiable reads:
//
//   - GET and HEAD only. A gateway must never carry a login, a post, or a
//     payment. Writes are not idempotent, not signed, and not re-checkable, so a
//     forged one could never be detected after the fact.
//   - Cookies are stripped in BOTH directions. Not forwarded, so a reader's
//     session is never exposed to a volunteer; not returned, so a gateway cannot
//     plant a session of its own choosing in a reader's browser. This alone
//     turns the proxy into an anonymous view, which is the only view worth
//     serving from a machine nobody vouches for.
//   - Authorization and similar credential headers are dropped for the same
//     reason.
//   - A deny list for paths that must never be anonymous anyway. Redundant
//     given no cookies travel — admin would simply redirect to a login — but
//     defence that costs nothing should not be omitted because another layer
//     currently happens to hold.
//   - Redirects are returned, never followed. Following one would let a
//     response choose the gateway's next destination.
type ContentProxy struct {
	// Origin is the scheme://host the gateway fetches from.
	Origin *url.URL
	// ServerName is the TLS name to validate the origin against. The origin is
	// reached by address, so the certificate check is what makes this a
	// connection to syndichan.org rather than to whoever holds that address.
	ServerName string
	// NodeID is this gateway's peer ID, announced on every response it serves.
	NodeID     string
	MaxBytes   int64
	client     *http.Client
	deniedPath []string
}

// Paths a gateway has no business carrying even anonymously.
var defaultDeniedPrefixes = []string{
	"/admin", "/api/v1/bot", "/api/v1/admin", "/login", "/logout",
	"/register", "/profile", "/settings", "/stripe", "/webhook",
	"/slip", "/mod", "/report",
}

// Request headers that must never reach a volunteer's machine.
var strippedRequestHeaders = []string{
	"Cookie", "Authorization", "Proxy-Authorization", "X-Csrf-Token",
	"X-Api-Key", "X-Bot-Token",
}

// Response headers a gateway must not be able to set on the origin's behalf.
var strippedResponseHeaders = []string{
	"Set-Cookie", "Set-Cookie2", "Strict-Transport-Security",
}

func NewContentProxy(origin *url.URL, serverName, nodeID string, originAddress string) *ContentProxy {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if originAddress != "" {
		// Pin the origin to a literal address while still validating its
		// certificate by name. DNS for syndichan.org points at gateways as well
		// as at the origin, so resolving it here could send a gateway's fetch to
		// another gateway — a loop, and a way for one volunteer's answer to be
		// laundered through another's identity.
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, originAddress)
		}
	} else {
		transport.DialContext = dialer.DialContext
	}
	return &ContentProxy{
		Origin: origin, ServerName: serverName, NodeID: nodeID,
		MaxBytes:   8 << 20,
		deniedPath: defaultDeniedPrefixes,
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *ContentProxy) denied(path string) bool {
	lowered := strings.ToLower(path)
	for _, prefix := range p.deniedPath {
		if lowered == prefix || strings.HasPrefix(lowered, prefix+"/") {
			return true
		}
	}
	return false
}

func (p *ContentProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// 405 rather than a silent proxy: a reader whose post vanished into a
		// volunteer's machine would have no way to tell that is what happened.
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "this gateway serves public reads only", http.StatusMethodNotAllowed)
		return
	}
	if p.denied(r.URL.Path) {
		http.Error(w, "not served by a gateway", http.StatusForbidden)
		return
	}

	target := *p.Origin
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	outbound, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for name, values := range r.Header {
		if headerIn(name, strippedRequestHeaders) {
			continue
		}
		for _, value := range values {
			outbound.Header.Add(name, value)
		}
	}
	outbound.Host = p.ServerName
	// The origin must be able to tell a gateway fetch from a reader, both for
	// its own logs and so it never treats one as a visitor.
	outbound.Header.Set("X-Syndichan-Gateway-Fetch", p.NodeID)
	outbound.Header.Del("Accept-Encoding") // let Go negotiate; body must be verifiable

	response, err := p.client.Do(outbound)
	if err != nil {
		http.Error(w, "origin unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	for name, values := range response.Header {
		if headerIn(name, strippedResponseHeaders) {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	// Announce which gateway answered. The origin sets this to "origin"; a
	// gateway overwrites it with its own identity, which is what makes an audit
	// receipt attributable to a specific key. Set, not added: two values would
	// let a gateway claim to be both itself and the origin.
	w.Header().Set("X-Syndichan-Gateway", p.NodeID)
	w.Header().Set("X-Gateway-Version", "1")

	// Readable cross-origin, so a reader on syndichan.org can fetch the same
	// object here and compare it against the origin's signature. Without this
	// the browser hides the response and a gateway becomes un-auditable by the
	// only party positioned to audit it.
	//
	// Safe precisely because of the rules above: no cookie was forwarded, so
	// this is the anonymous public view and nothing here is authorised by the
	// reader's identity. Credentials are NOT allowed, which is what keeps that
	// true — with them, "*" would let any site read a logged-in view.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "false")
	w.Header().Set("Access-Control-Expose-Headers",
		"X-Syndichan-Version, X-Syndichan-Hash, X-Syndichan-Signature, "+
			"X-Syndichan-Key, X-Syndichan-Gateway, X-Gateway-Version")

	w.WriteHeader(response.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, io.LimitReader(response.Body, p.MaxBytes))
}

func headerIn(name string, list []string) bool {
	canonical := http.CanonicalHeaderKey(name)
	for _, candidate := range list {
		if http.CanonicalHeaderKey(candidate) == canonical {
			return true
		}
	}
	return false
}
