// Package heartbeat sends the node's signed presence beacon to the Syndichan
// frontend.
//
// It is deliberately the one connection that does not go through I2P: the
// frontend has to see a real source address to count unique nodes and to place
// them on the operator's map. That is the same address the web server already
// logs when the operator visits the site.
//
// Every role that has a persistent node identity sends it -- a storage node, a
// dedicated gateway, or a probe. A gateway that stores nothing reports zero
// capacity, which is how the frontend tells "gateway" apart from "storage"
// rather than a separate message type.
package heartbeat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/gateway"
)

const (
	// UserAgent identifies the client to the frontend, which rejects anything
	// else on the heartbeat endpoint.
	UserAgent = "Syndichan-Storage-Client/1.0"
	// Interval matches the five-minute presence window the frontend documents.
	Interval = 5 * time.Minute
	// Endpoint is the production presence endpoint.
	Endpoint = "https://syndichan.org/api/v1/storage/nodes/heartbeat"

	maxResponseBytes = 64 << 10
)

// Signer is the persistent node identity. Both a full p2p node and a
// standalone gateway identity satisfy it.
type Signer interface {
	ID() string
	Sign([]byte) ([]byte, error)
}

type logf interface{ Printf(string, ...any) }

// State is what the node currently is, sampled fresh on every send so a
// gateway that gains or loses verification is reflected within one interval.
type State struct {
	CapacityBytes   int64
	GatewayEnabled  bool
	GatewayVerified bool
	Registration    *gateway.Registration
	// DCSWorker is true when this node accepts container deployments (dcs.enabled
	// + role.worker). It is what makes the node draw its yellow role on the
	// operator's map and marks it as a container host on the network.
	DCSWorker bool
	// I2PDestination is the node's own base32 garlic destination. Reported so the
	// coordinator can hand this node out to others as a LIVE bootstrap peer,
	// instead of the network relying on a single hardcoded one.
	I2PDestination string
}

type request struct {
	Version             int                   `json:"version"`
	NodeID              string                `json:"node_id"`
	Timestamp           int64                 `json:"timestamp"`
	Nonce               string                `json:"nonce"`
	CapacityBytes       int64                 `json:"capacity_bytes"`
	Platform            string                `json:"platform"`
	GatewayEnabled      bool                  `json:"gateway_enabled"`
	GatewayVerified     bool                  `json:"gateway_verified"`
	GatewayRegistration *gateway.Registration `json:"gateway_registration,omitempty"`
	DCSWorker           bool                  `json:"dcs_worker"`
	I2PDestination      string                `json:"i2p_destination,omitempty"`
}

// Client posts the signed beacon. Endpoint and HTTP are injected so tests can
// point at a local server and so the caller controls the transport -- in
// particular that it has no proxy configured.
type Client struct {
	Signer   Signer
	Endpoint string
	HTTP     *http.Client
	Logger   logf
	// Snapshot reports the current state at send time.
	Snapshot func() State
	// OnPeers, if set, receives the bootstrap peer multiaddrs the coordinator
	// returns in the heartbeat response. This is the live bootstrap service: the
	// node reports its own destination and is handed a few reachable peers back,
	// so it can keep heartbeating until it joins the DHT and stay joined after.
	OnPeers func([]string)
}

// DirectHTTPClient is the transport a heartbeat must use: no proxy, so neither
// I2P nor HTTP(S)_PROXY environment variables can redirect the one request
// whose whole purpose is to originate from the node's real address.
func DirectHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// Run sends immediately, then every Interval until ctx is cancelled. Sending
// at once means a freshly started gateway appears on the operator's map
// without waiting out a full interval.
func (c *Client) Run(ctx context.Context) {
	c.Send(ctx)
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Send(ctx)
		}
	}
}

// Send posts one beacon. Failures are logged and swallowed: presence
// reporting is never allowed to take down a running node.
func (c *Client) Send(ctx context.Context) {
	if c.Signer == nil {
		return
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return
	}
	state := State{}
	if c.Snapshot != nil {
		state = c.Snapshot()
	}
	payload := request{
		Version: 1, NodeID: c.Signer.ID(), Timestamp: time.Now().UTC().Unix(),
		Nonce:          base64.RawURLEncoding.EncodeToString(nonceBytes),
		CapacityBytes:  state.CapacityBytes,
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		GatewayEnabled: state.GatewayEnabled,
		// A registration is attached only when the node genuinely holds one;
		// the frontend re-validates it before showing a gateway role.
		GatewayVerified:     state.GatewayVerified,
		GatewayRegistration: state.Registration,
		DCSWorker:           state.DCSWorker,
		I2PDestination:      state.I2PDestination,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	signature, err := c.Signer.Sign(body)
	if err != nil {
		c.logf("heartbeat signing failed: %v", err)
		return
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = Endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Syndichan-Node", payload.NodeID)
	req.Header.Set("X-Syndichan-Signature", base64.RawStdEncoding.EncodeToString(signature))
	client := c.HTTP
	if client == nil {
		client = DirectHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		c.logf("heartbeat unavailable: %v", err)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		c.logf("heartbeat returned HTTP %d", resp.StatusCode)
		return
	}
	// The response carries the bootstrap peers the coordinator picked for us.
	// It is fine for this list to be short or empty -- the coordinator returns
	// whatever live peers it can find, and we simply try again next interval.
	if c.OnPeers != nil {
		var reply struct {
			BootstrapPeers []string `json:"bootstrap_peers"`
		}
		if err := json.Unmarshal(respBody, &reply); err == nil && len(reply.BootstrapPeers) > 0 {
			c.OnPeers(reply.BootstrapPeers)
		}
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
	}
}
