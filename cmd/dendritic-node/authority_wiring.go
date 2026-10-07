package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	axondht "github.com/rabbiit/maniwani/storage-client/internal/axon/dht"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime"
	"github.com/rabbiit/maniwani/storage-client/internal/config"
	"github.com/rabbiit/maniwani/storage-client/internal/p2p"
	"github.com/rabbiit/maniwani/storage-client/internal/policyauthority"
)

// startAuthority runs the policy authority on this node when enabled: it grades
// the watched services from the reports that propagate over the DHT, folds in
// DAO suspensions (none wired yet), and serves the signed service-policy
// document over HTTP and over this node's own .axon service. Its public key is
// logged so an operator can pin it as other nodes' service_policy.policy_key.
func startAuthority(ctx context.Context, overlay *runtime.Runtime, node *p2p.Node, cfg config.Config, logger *log.Logger) {
	ac := cfg.Axon.Authority
	if !ac.Enabled || node == nil {
		return
	}
	priv, err := loadOrCreateAuthorityKey(filepath.Join(cfg.DataDir, "authority.key"))
	if err != nil {
		logger.Printf("policy authority: cannot load signing key: %v", err)
		return
	}
	a := &policyauthority.Authority{
		Watchlist: policyauthority.StaticWatchlist(ac.Watchlist),
		Reports:   reportFetcher{node: node, limit: 64},
		Key:       priv,
		DocTTL:    time.Duration(ac.DocTTLSeconds) * time.Second,
		Logger:    log.New(logger.Writer(), logger.Prefix()+"authority: ", logger.Flags()),
	}
	go a.Run(ctx, time.Duration(ac.RebuildSeconds)*time.Second)

	if ac.Listen != "" {
		srv := &http.Server{Addr: ac.Listen, Handler: a, ReadHeaderTimeout: 30 * time.Second}
		go func() { <-ctx.Done(); srv.Close() }()
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("policy authority HTTP: %v", err)
			}
		}()
		logger.Printf("policy authority: signed document on http://%s", ac.Listen)
	}
	if svc, err := overlay.Listen(authoritySeed(cfg.DataDir)); err == nil {
		go func() { _ = http.Serve(svc.Listener(), a) }()
		logger.Printf("policy authority: signed document also served over AXON at http://%s/", svc.Addr())
	} else {
		logger.Printf("policy authority: AXON service unavailable: %v", err)
	}
	logger.Printf("policy authority: PUBLIC KEY (pin as axon.service_policy.policy_key): %s",
		base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
}

// reportFetcher adapts the node's FindReports to the authority's ReportFetcher.
type reportFetcher struct {
	node  *p2p.Node
	limit int
}

func (r reportFetcher) Reports(ctx context.Context, subject []byte) ([]*axondht.ContentReport, error) {
	return r.node.FindReports(ctx, subject, r.limit)
}

// loadOrCreateAuthorityKey reads the authority's ed25519 signing key, creating
// and persisting one (owner-only) on first run so its public key is stable.
func loadOrCreateAuthorityKey(path string) (ed25519.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw), nil
		}
		return nil, errors.New("authority key file is malformed")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func authoritySeed(dataDir string) [32]byte {
	return sha256.Sum256([]byte(dataDir + "\x00axon-authority-v1"))
}
