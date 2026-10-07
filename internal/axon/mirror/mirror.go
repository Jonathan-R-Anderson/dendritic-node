// Package mirror makes a node an availability mirror for an AXON hidden
// service: it keeps a signed, verified local snapshot of a .axon site and
// serves it when the origin is offline, so the site stays reachable even while
// its origin is down. It is the hidden-service form of the clearnet reverse
// gateway -- the same snapshot/health/content-proxy machinery
// (internal/gateway), pointed at an <56 base32>.key.axon origin reached over the
// overlay instead of a clearnet address.
//
// Acquisition is a cooperative pull, not a crawl: the origin service publishes a
// publisher-signed /.well-known/rabbiit/snapshot.json plus its objects over its
// own AXON HTTP listener, and the mirror fetches and verifies them through the
// overlay. A mirror runs as its own hidden service, so a client that knows a
// mirror's address reaches the content through the mirror when the origin is
// gone; many nodes mirroring one site is what makes the site hard to take down.
package mirror

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/gateway"
)

// Config describes one hidden-service site this node mirrors.
type Config struct {
	// Origin is the service to mirror, "<56 base32>.key.axon". It is reached
	// over the overlay as plain HTTP (the circuit is already encrypted).
	Origin string
	// PublisherKey pins the ed25519 key the origin's snapshots are signed with.
	// Required: an unsigned or wrong-key snapshot is refused, so a malicious
	// relay cannot feed the mirror forged content.
	PublisherKey ed25519.PublicKey
	// Dir is where the local copy lives between restarts.
	Dir string
	// Poll is how often to look for a newer snapshot (default 10m).
	Poll time.Duration
	// MaxObjectBytes caps one cached object (default 8 MiB).
	MaxObjectBytes int64
	// Offload serves publisher-approved routes from the snapshot even while the
	// origin is up, taking read load off it. Off by default (origin-first).
	Offload bool
	// NodeID is this node's peer id, announced on served responses.
	NodeID string
}

// Mirror is a running availability mirror for one origin.
type Mirror struct {
	Origin string
	proxy  *gateway.ContentProxy
	snap   *gateway.SnapshotCache
}

// New builds a mirror whose origin is reached through client -- in production a
// client whose transport dials .axon hosts over the runtime, so the origin can
// be a hidden service. client must not be nil.
func New(cfg Config, client *http.Client) (*Mirror, error) {
	origin := normalizeOrigin(cfg.Origin)
	if origin == "" {
		return nil, fmt.Errorf("axon/mirror: origin is required")
	}
	if len(cfg.PublisherKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("axon/mirror: a publisher key is required to pin the snapshot signature")
	}
	if cfg.Dir == "" {
		return nil, fmt.Errorf("axon/mirror: a cache directory is required")
	}
	if client == nil {
		return nil, fmt.Errorf("axon/mirror: an overlay HTTP client is required")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("axon/mirror: bad origin %q: %w", origin, err)
	}

	snap := gateway.NewSnapshotCache(origin, cfg.Dir, cfg.PublisherKey)
	if cfg.Poll > 0 {
		snap.Poll = cfg.Poll
	}
	if cfg.MaxObjectBytes > 0 {
		snap.MaxObjectBytes = cfg.MaxObjectBytes
	}
	snap.UseClient(client)

	// originAddress "" means no clearnet address pinning: over the overlay the
	// address IS the identity, so there is no DNS to pin and no gateway loop to
	// avoid. The injected client does the overlay dialing.
	proxy := gateway.NewContentProxy(u, "", cfg.NodeID, "")
	proxy.UseClient(client)
	proxy.Snapshot = snap
	proxy.Health = gateway.NewOriginHealth()
	proxy.Offload = cfg.Offload

	return &Mirror{Origin: origin, proxy: proxy, snap: snap}, nil
}

// Run keeps the local snapshot up to date until ctx ends. It blocks, so callers
// run it in a goroutine.
func (m *Mirror) Run(ctx context.Context) { m.snap.Run(ctx) }

// Handler serves the mirror: the origin while it is healthy, the verified
// snapshot while it is down. Mount it on the node's own .axon service (and/or a
// loopback port).
func (m *Mirror) Handler() http.Handler { return m.proxy }

// Snapshot exposes the underlying cache, for status and tests.
func (m *Mirror) Snapshot() *gateway.SnapshotCache { return m.snap }

// normalizeOrigin defaults an .axon origin to plain HTTP (the overlay already
// encrypts) and trims a trailing slash.
func normalizeOrigin(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	return strings.TrimRight(s, "/")
}
