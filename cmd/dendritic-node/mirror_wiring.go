package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/mirror"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime"
	"github.com/rabbiit/maniwani/storage-client/internal/config"
)

// startMirrors brings up an availability mirror for each configured .axon site.
// Each keeps a signed local snapshot of its origin and serves it -- over the
// node's own .axon mirror service, and optionally a loopback port -- so the
// site stays reachable when its origin is offline. Failures are logged and
// skipped; a bad mirror entry never stops the node.
func startMirrors(ctx context.Context, overlay *runtime.Runtime, cfg config.Config, logger *log.Logger) {
	if len(cfg.Axon.Mirrors) == 0 {
		return
	}
	client := policyHTTPClient(overlay) // dials .axon origins over the overlay
	for _, mc := range cfg.Axon.Mirrors {
		origin := strings.TrimSpace(mc.Origin)
		if origin == "" {
			continue
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(mc.PublisherKey))
		if err != nil || len(key) != ed25519.PublicKeySize {
			logger.Printf("mirror %s: publisher_key is not a base64 ed25519 public key; skipping", origin)
			continue
		}
		dir := mc.CacheDir
		if dir == "" {
			dir = filepath.Join(cfg.DataDir, "mirror", sanitizeOrigin(origin))
		}
		m, err := mirror.New(mirror.Config{
			Origin:         origin,
			PublisherKey:   ed25519.PublicKey(key),
			Dir:            dir,
			Poll:           time.Duration(mc.PollSeconds) * time.Second,
			MaxObjectBytes: mc.MaxObjectBytes,
			Offload:        mc.Offload,
			NodeID:         overlay.NodeID().String(),
		}, client)
		if err != nil {
			logger.Printf("mirror %s: %v; skipping", origin, err)
			continue
		}
		go m.Run(ctx)

		// Serve the mirror as this node's own .axon service, so a client that
		// knows this address reaches the site through us when the origin is down.
		if svc, err := overlay.Listen(mirrorSeed(cfg.DataDir, origin)); err == nil {
			handler := m.Handler()
			go func() { _ = http.Serve(svc.Listener(), handler) }()
			logger.Printf("mirroring %s -> reachable at %s (serves the cached copy when the origin is down)",
				origin, svc.Addr())
		} else {
			logger.Printf("mirror %s: could not start mirror service: %v", origin, err)
		}

		if mc.Listen != "" {
			addr, handler := mc.Listen, m.Handler()
			go func() {
				if err := http.ListenAndServe(addr, handler); err != nil {
					logger.Printf("mirror %s loopback %s: %v", origin, addr, err)
				}
			}()
			logger.Printf("mirror %s also served on http://%s", origin, mc.Listen)
		}
	}
}

// mirrorSeed derives a stable per-origin AXON service seed, so this node's
// mirror of a given site keeps the same .axon address across restarts.
func mirrorSeed(dataDir, origin string) [32]byte {
	return sha256.Sum256([]byte(dataDir + "\x00axon-mirror-v1\x00" + strings.ToLower(strings.TrimSpace(origin))))
}

// sanitizeOrigin makes an origin safe as a directory name.
func sanitizeOrigin(origin string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(origin) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
