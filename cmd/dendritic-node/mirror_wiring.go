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
	"github.com/rabbiit/maniwani/storage-client/internal/mirrordisc"
	"github.com/rabbiit/maniwani/storage-client/internal/p2p"
)

// startedMirror is a mirror this node is serving, to be announced for
// decentralized discovery once the DHT-bearing node is open.
type startedMirror struct {
	Origin string
	Addr   string // this node's .axon address for the mirror
}

// startMirrors brings up an availability mirror for each configured .axon site.
// Each keeps a signed local snapshot of its origin and serves it -- over the
// node's own .axon mirror service, and optionally a loopback port -- so the
// site stays reachable when its origin is offline. It returns the mirrors it
// started so they can be announced in the DHT. Failures are logged and skipped;
// a bad mirror entry never stops the node.
func startMirrors(ctx context.Context, overlay *runtime.Runtime, cfg config.Config, logger *log.Logger) []startedMirror {
	if len(cfg.Axon.Mirrors) == 0 {
		return nil
	}
	var started []startedMirror
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
			started = append(started, startedMirror{Origin: origin, Addr: svc.Addr()})
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
	return started
}

// announceMirrors registers the mirror-discovery validator and, for each mirror
// this node serves, publishes a signed announcement to the DHT and refreshes it
// before it expires -- so other nodes find our mirror of an origin with no
// central directory. Called once the DHT-bearing node is open.
func announceMirrors(ctx context.Context, node *p2p.Node, started []startedMirror, logger *log.Logger) {
	if node == nil {
		return
	}
	// Register on every node (publisher or not) so FindMirrors can validate reads.
	if err := node.ConfigureMirrorRecords(mirrordisc.DHTValidator{}); err != nil {
		logger.Printf("mirror discovery: validator not registered: %v", err)
		return
	}
	if len(started) == 0 {
		return
	}
	go func() {
		seq := uint64(time.Now().Unix())
		publish := func() {
			for _, sm := range started {
				seq++
				rec, err := mirrordisc.Sign(node, mirrordisc.MirrorRecord{
					Origin: sm.Origin, MirrorAddr: sm.Addr,
					IssuedAt:  time.Now().Unix(),
					ExpiresAt: time.Now().Add(mirrordisc.RecordTTL).Unix(),
					Sequence:  seq,
				})
				if err != nil {
					logger.Printf("mirror discovery: sign %s: %v", sm.Origin, err)
					continue
				}
				if err := node.PublishMirror(ctx, rec); err != nil {
					logger.Printf("mirror discovery: announce %s: %v", sm.Origin, err)
					continue
				}
				logger.Printf("mirror discovery: announced our mirror of %s (%s)", sm.Origin, sm.Addr)
			}
		}
		publish()
		t := time.NewTicker(mirrordisc.RecordTTL / 2)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				publish()
			}
		}
	}()
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
