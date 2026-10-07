package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/runtime"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/servicepolicy"
	"github.com/rabbiit/maniwani/storage-client/internal/config"
)

// buildServicePolicy turns the operator's config into a routing policy, or nil
// when nothing is configured (nil Gate admits every service at zero cost). It
// returns an error only for a malformed policy key, which is worth refusing to
// start over rather than silently accepting unsigned policy.
func buildServicePolicy(cfg config.AxonConfig, logger *log.Logger) (*servicepolicy.Policy, error) {
	sp := cfg.ServicePolicy
	configured := sp.Enforce || sp.MinGrade != "" || sp.DenyUnknown ||
		len(sp.Allow) > 0 || len(sp.Deny) > 0 || sp.PolicyURL != ""
	if !configured {
		return nil, nil
	}
	if sp.PolicyURL != "" && sp.PolicyKey == "" {
		return nil, fmt.Errorf("axon.service_policy.policy_url is set but policy_key is empty; " +
			"a policy document must be signed by a pinned key")
	}
	p := servicepolicy.New(servicepolicy.Options{
		Enforce:     sp.Enforce,
		MinGrade:    sp.MinGrade,
		DenyUnknown: sp.DenyUnknown,
		Allow:       sp.Allow,
		Deny:        sp.Deny,
		Logger:      log.New(logger.Writer(), logger.Prefix()+"servicepolicy: ", logger.Flags()),
	})
	mode := "log-only"
	if sp.Enforce {
		mode = "ENFORCING"
	}
	logger.Printf("service routing policy active (%s): min_grade=%q allow=%d deny=%d doc=%v",
		mode, sp.MinGrade, len(sp.Allow), len(sp.Deny), sp.PolicyURL != "")
	return p, nil
}

// startPolicyLoader begins fetching the signed grade+suspension document when a
// policy_url is configured. The document may be served over clearnet or over
// the overlay (an .axon URL), so the client dials .axon hosts through the
// runtime and everything else directly.
func startPolicyLoader(ctx context.Context, rt *runtime.Runtime, cfg config.AxonConfig,
	p *servicepolicy.Policy, logger *log.Logger) error {
	sp := cfg.ServicePolicy
	if p == nil || sp.PolicyURL == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sp.PolicyKey))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("axon.service_policy.policy_key is not a base64 ed25519 public key")
	}
	poll := time.Duration(sp.PollSeconds) * time.Second
	loader := &servicepolicy.Loader{
		URL:    sp.PolicyURL,
		Key:    ed25519.PublicKey(raw),
		Client: policyHTTPClient(rt),
		Poll:   poll,
		Policy: p,
		Logger: log.New(logger.Writer(), logger.Prefix()+"servicepolicy: ", logger.Flags()),
	}
	go loader.Run(ctx)
	logger.Printf("service policy document: fetching from %s", sp.PolicyURL)
	return nil
}

// policyHTTPClient reaches both clearnet URLs and .axon URLs: .axon hosts are
// dialed through the overlay runtime (plain HTTP over the encrypted circuit),
// everything else through an ordinary dialer.
func policyHTTPClient(rt *runtime.Runtime) *http.Client {
	base := &net.Dialer{Timeout: 15 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			if strings.HasSuffix(strings.ToLower(host), ".axon") {
				return rt.DialContext(ctx, network, addr)
			}
			return base.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}
