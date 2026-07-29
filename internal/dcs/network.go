package dcs

import (
	"context"
	"net"
	"sync"
)

// This file ties the container's I2P destination (a SAM session) to the
// container's network namespace (the ContainerProxy). It is the seam between
// "the container has an address" and "the address reaches the container".

// SessionAccepter is the subset of internal/i2p.Session the proxy needs: accept
// inbound streams on the container's destination, and close. The i2p Session
// satisfies it. Kept as an interface so this package does not hard-depend on
// the SAM client for the parts that are pure plumbing.
type SessionAccepter interface {
	Accept() (net.Conn, error)
	Close() error
}

// sessionListener adapts a SAM session to I2PListener.
//
// PORT CAVEAT, stated honestly: the current SAM client's STREAM ACCEPT does not
// surface the caller's TO_PORT, so every inbound stream reports TargetPort 0
// and is routed to the proxy's DefaultPort -- the container's single primary
// service. Multi-port scanning over ONE destination needs SAMv3.2
// FROM_PORT/TO_PORT parsing in internal/i2p, which is a follow-up there; until
// then, a lab that must expose several ports for scanning should map each to
// its own destination, or the SAM client should be extended. The proxy already
// carries TargetPort end to end, so that extension needs no change here.
type sessionListener struct {
	session SessionAccepter
}

// NewSessionListener wraps a SAM session as an I2PListener.
func NewSessionListener(session SessionAccepter) I2PListener {
	return &sessionListener{session: session}
}

func (l *sessionListener) Accept() (InboundStream, error) {
	conn, err := l.session.Accept()
	if err != nil {
		return InboundStream{}, err
	}
	return InboundStream{Conn: conn, TargetPort: 0}, nil
}

func (l *sessionListener) Close() error { return l.session.Close() }

// ContainerNetwork is the per-container network attachment the agent owns for
// the life of a container. Attach starts the inbound proxy; Detach stops it and
// leaves the container with no network path.
type ContainerNetwork struct {
	mu     sync.Mutex
	proxy  *ContainerProxy
	cancel context.CancelFunc
}

// AttachInbound bridges a container's destination to its loopback ports.
//
//	listener    — accepts on the container's I2P destination (NewSessionListener)
//	dialer      — enters the container's netns (NewNamespaceDialer, Linux)
//	primaryPort — where a portless inbound stream is routed (the container's
//	              main service); 0 means "refuse portless streams"
//
// It returns immediately; the accept loop runs until Detach or the container
// stops. Errors from the loop are terminal only for the loop, never for the
// agent -- a container losing its inbound path is a liveness problem for that
// one container, logged, not a crash.
func (n *ContainerNetwork) AttachInbound(containerID string, listener I2PListener, dialer NamespaceDialer, primaryPort int, logf func(string, ...any)) {
	n.mu.Lock()
	defer n.mu.Unlock()

	proxy := NewContainerProxy(containerID, listener, dialer, logf)
	proxy.DefaultPort = primaryPort
	ctx, cancel := context.WithCancel(context.Background())
	n.proxy = proxy
	n.cancel = cancel

	go func() {
		if err := proxy.Serve(ctx); err != nil && logf != nil {
			logf("dcs: container %s inbound proxy stopped: %v", containerID, err)
		}
	}()
}

// Detach tears the network down. After this the container is reachable by
// nothing, which is the correct end state for a stopped or destroyed container
// -- especially a lab one.
func (n *ContainerNetwork) Detach() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cancel != nil {
		n.cancel()
		n.cancel = nil
	}
	if n.proxy != nil {
		_ = n.proxy.Close()
		n.proxy = nil
	}
}
