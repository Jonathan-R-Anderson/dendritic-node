// Package proxy is a loopback HTTP proxy onto the AXON overlay: how a person
// on this machine reaches a <56 base32>.key.axon address with an ordinary
// browser, curl or port scanner -- the job the I2P router's HTTP proxy did for
// .i2p addresses.
//
// Configured aliases resolve to AXON identities; optional clearnet routes use an
// explicit AXON exit. Alias failures never silently use public DNS.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/names"
)

// Dialer opens a stream to "<addr>.key.axon:port". *runtime.Runtime's
// DialContext satisfies it.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Handler serves both proxy forms: CONNECT host:port (HTTPS, and any TCP
// protocol a client tunnels) and absolute-form plain HTTP requests.
type Handler struct {
	Dial Dialer
	// DialTimeout bounds reaching a service. Zero means two minutes, which
	// covers a cold rendezvous.
	DialTimeout time.Duration

	// Peers, if set, backs the local GET /v1/axon/peers directory: the
	// <addr>.key.axon peers a local client (e.g. praxis's dendritic_expert)
	// can reach for services like /expert. Nil means an empty directory.
	Peers func() []string

	// Resolve, if set, turns a human `.axon` name (e.g. ai.epin.axon) into its
	// canonical <56 base32>.key.axon address via the on-chain registry, so a
	// request for a named host dials the self-certifying address it points at.
	// Nil means only self-certifying addresses are reachable (the old behaviour).
	Resolve         func(ctx context.Context, host string) (string, error)
	ResolveAll      func(context.Context, string) ([]string, error)
	NameMatches     func(string) bool
	MissingFallback bool

	// ExitVia, if set (a <56 base32>.key.axon[:port]), routes clearnet requests
	// through that exit node by CONNECT-tunnelling to it over AXON. Empty keeps
	// clearnet refused (ErrNotAxon) — there is no exit.
	ExitVia string

	transport *http.Transport
}

// New returns a proxy over dial.
func New(dial Dialer) *Handler {
	h := &Handler{Dial: dial}
	h.transport = &http.Transport{
		DialContext:         func(ctx context.Context, network, addr string) (net.Conn, error) { return h.dial(ctx, addr) },
		Proxy:               nil,
		MaxIdleConnsPerHost: 4,
	}
	return h
}

// ErrNotAxon is the refusal for any host that is not an AXON address.
var ErrNotAxon = errors.New("only <56 base32>.key.axon addresses are reachable through this proxy")

func (h *Handler) dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "80"
	}
	canonicalHost := strings.TrimSuffix(strings.ToLower(host), ".")
	timeout := h.DialTimeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if pub, err := identity.ParseAddress(canonicalHost); err == nil && strings.HasSuffix(canonicalHost, ".key.axon") {
		return h.Dial(ctx, "tcp", net.JoinHostPort(identity.FullAddress(pub), port))
	}
	policyHost := strings.TrimRight(strings.ToLower(host), ".")
	isAxon := policyHost == "axon" || strings.HasSuffix(policyHost, ".axon")
	matched := isAxon || (h.NameMatches != nil && h.NameMatches(host))
	if matched {
		var destinations []string
		var resolveErr error
		if h.ResolveAll != nil {
			destinations, resolveErr = h.ResolveAll(ctx, host)
		} else if h.Resolve != nil {
			var dest string
			dest, resolveErr = h.Resolve(ctx, host)
			destinations = []string{dest}
		} else {
			return nil, ErrNotAxon
		}
		if resolveErr != nil {
			if !(errors.Is(resolveErr, names.ErrNotRegistered) && !isAxon && h.MissingFallback) {
				return nil, resolveErr
			}
		} else {
			if len(destinations) == 0 {
				return nil, names.ErrNoDestination
			}
			// At most four connection attempts, primary first. Never replay application traffic.
			limit := len(destinations)
			if limit > 4 {
				limit = 4
			}
			var dialErr error
			for _, dest := range destinations[:limit] {
				pub, err := identity.ParseAddress(dest)
				if err != nil {
					return nil, err
				}
				attempt, stop := context.WithTimeout(ctx, timeout/time.Duration(limit))
				conn, err := h.Dial(attempt, "tcp", net.JoinHostPort(identity.FullAddress(pub), port))
				stop()
				if err == nil {
					return conn, nil
				}
				dialErr = err
			}
			return nil, dialErr
		}
	}
	// A clearnet host is routed THROUGH the configured exit (if any), by CONNECT-
	// tunnelling to it over AXON; with no exit, clearnet stays refused.
	if h.ExitVia == "" {
		return nil, ErrNotAxon
	}
	return h.exitTunnel(ctx, net.JoinHostPort(host, port))
}

// exitTunnel opens a stream to the configured exit over AXON and asks it to
// CONNECT to the clearnet target, returning the spliced tunnel. Both the HTTP and
// the CONNECT client paths funnel through here, so an origin-form request simply
// flows down the tunnel the exit opened to the real host.
func (h *Handler) exitTunnel(ctx context.Context, target string) (net.Conn, error) {
	via := h.ExitVia
	if _, _, err := net.SplitHostPort(via); err != nil {
		via = net.JoinHostPort(via, "80")
	}
	conn, err := h.Dial(ctx, "tcp", via)
	if err != nil {
		return nil, fmt.Errorf("axon/proxy: exit %q unreachable: %w", h.ExitVia, err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("axon/proxy: exit handshake: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("axon/proxy: exit refused %s: %s", target, resp.Status)
	}
	return &bufConn{Conn: conn, r: br}, nil
}

// bufConn preserves any bytes the CONNECT handshake buffered ahead of the tunnel.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.connect(w, r)
		return
	}
	// Local management endpoint (origin-form request to the proxy itself, not an AXON address): the
	// peer directory praxis's dendritic_expert.discover_peers() reads to find expert-serving nodes.
	if !r.URL.IsAbs() && r.URL.Path == "/v1/axon/peers" {
		var peers []string
		if h.Peers != nil {
			peers = h.Peers()
		}
		if peers == nil {
			peers = []string{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"peers": peers})
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		http.Error(w, "this is a proxy: send absolute-form http:// requests, or CONNECT", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopByHop(out.Header)
	resp, err := h.transport.RoundTrip(out)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrNotAxon) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer resp.Body.Close()
	removeHopByHop(resp.Header)
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *Handler) connect(w http.ResponseWriter, r *http.Request) {
	upstream, err := h.dial(r.Context(), r.Host)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrNotAxon) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "CONNECT is not supported on this connection", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() {
		if buffered.Reader.Buffered() > 0 {
			io.CopyN(upstream, buffered, int64(buffered.Reader.Buffered()))
		}
		io.Copy(upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
	client.Close()
	upstream.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func removeHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}
