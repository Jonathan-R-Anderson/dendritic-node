// Package exitproxy is an opt-in clearnet EXIT (outproxy) for the overlay: it is
// mounted on a node's AXON hidden service and forwards a client's request out to
// the ordinary internet, the one thing the loopback proxy (internal/axon/proxy)
// deliberately refuses. An operator who runs one carries other people's traffic
// under their own IP -- the role Tor exits exist to take the heat for -- so it is
// off unless explicitly enabled, and by default it refuses private/loopback/
// link-local destinations so it cannot be turned into a probe of its operator's
// own network (basic SSRF protection).
//
// A client reaches it by chaining to it over AXON: internal/axon/proxy, when it is
// given a clearnet host and an ExitVia address, opens a stream to this service and
// speaks ordinary forward-proxy to it (absolute-form GET, or CONNECT host:port).
package exitproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Handler forwards overlay requests to the clearnet. allowPrivate lifts the
// default refusal of private/loopback/link-local destinations.
type Handler struct {
	allowPrivate bool
	transport    *http.Transport
	dialTimeout  time.Duration
}

// New returns an exit handler. allowPrivate=false (the recommended default) makes
// the exit refuse destinations on private/loopback/link-local ranges.
func New(allowPrivate bool) *Handler {
	h := &Handler{allowPrivate: allowPrivate, dialTimeout: 30 * time.Second}
	h.transport = &http.Transport{
		DialContext:         (&net.Dialer{Timeout: h.dialTimeout}).DialContext,
		MaxIdleConnsPerHost: 8,
		// The exit terminates the client's hop and makes its OWN clearnet request;
		// it does not tunnel the client's TLS, so https origins are fetched here.
	}
	return h
}

var errBlockedDest = errors.New("exit: destination not allowed (private/loopback refused)")

// allowedHost resolves host and refuses it when any address is private/loopback/
// link-local/unspecified, unless allowPrivate is set.
func (h *Handler) allowedHost(host string) error {
	if h.allowPrivate {
		return nil
	}
	host = strings.TrimSuffix(host, ".")
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("exit: cannot resolve %q: %w", host, err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return errBlockedDest
		}
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.connect(w, r)
		return
	}
	// Absolute-form forward-proxy request (http:// only; https arrives as CONNECT).
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		http.Error(w, "exit: send absolute-form http:// requests, or CONNECT for TLS", http.StatusBadRequest)
		return
	}
	host := r.URL.Hostname()
	if err := h.allowedHost(host); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopByHop(out.Header)
	resp, err := h.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "exit: upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopByHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// connect dials the clearnet host for a CONNECT (HTTPS and any tunnelled TCP) and
// splices the two sides, so the client's TLS is end-to-end to the real origin and
// the exit sees only ciphertext.
func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	hn := host
	if h2, _, err := net.SplitHostPort(host); err == nil {
		hn = h2
	}
	if err := h.allowedHost(hn); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	upstream, err := net.DialTimeout("tcp", host, h.dialTimeout)
	if err != nil {
		http.Error(w, "exit: dial: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "exit: no hijack", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() { io.Copy(upstream, client); upstream.Close() }()
	io.Copy(client, upstream)
	client.Close()
}

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func removeHopByHop(hdr http.Header) {
	for _, k := range hopByHop {
		hdr.Del(k)
	}
}
