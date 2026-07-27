package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The coordinator is the main site, not a separate host: syndichan.org already
// terminates TLS, runs the backend that serves this document and issues leases,
// and is the same origin the presence heartbeat posts to. A dedicated
// node.syndichan.org would mean a second cert, a second edge, and a second
// place for the storage routes to be missing -- for no gain.
const BootstrapURL = "https://syndichan.org/.well-known/syndichan/storage-node.json"

type Config struct {
	DataDir  string `json:"data_dir"`
	S3Listen string `json:"s3_listen"`
	// CacheOnly: serve our own content but host nothing for other peers.
	CacheOnly     bool          `json:"cache_only"`
	UIListen      string        `json:"ui_listen"`
	P2PListen     []string      `json:"p2p_listen"`
	I2PSAM        string        `json:"i2p_sam"`
	I2PHTTPProxy  string        `json:"i2p_http_proxy"`
	AccessKey     string        `json:"access_key"`
	SecretKey     string        `json:"secret_key"`
	CapacityBytes int64         `json:"capacity_bytes"`
	DataShards    int           `json:"data_shards"`
	ParityShards  int           `json:"parity_shards"`
	ChunkBytes    int           `json:"chunk_bytes"`
	TLSCert       string        `json:"tls_cert,omitempty"`
	TLSKey        string        `json:"tls_key,omitempty"`
	Gateway       GatewayConfig `json:"gateway"`
	DNS           DNSConfig     `json:"dns"`
}

type GatewayConfig struct {
	Enabled        bool                `json:"enabled"`
	ProbeEnabled   bool                `json:"probe_enabled"`
	ListenAddress  string              `json:"listen_address"`
	ListenPort     int                 `json:"listen_port"`
	PublicHostname string              `json:"public_hostname"`
	AdvertiseIPv4  bool                `json:"advertise_ipv4"`
	AdvertiseIPv6  bool                `json:"advertise_ipv6"`
	ReverseProxy   bool                `json:"reverse_proxy"`
	TLS            GatewayTLSConfig    `json:"tls"`
	Verification   VerificationConfig  `json:"external_verification"`
	Health         GatewayHealthConfig `json:"health"`
	Eligibility    EligibilityConfig   `json:"eligibility"`
	// TrustedProbes maps node IDs to base64-encoded public keys. An empty map
	// admits no probes; a candidate can never authorize itself.
	TrustedProbes   map[string]string `json:"trusted_probes,omitempty"`
	ProbeURLs       []string          `json:"probe_urls,omitempty"`
	PublicAddresses []string          `json:"public_addresses,omitempty"`
	ProbeNetwork    string            `json:"probe_network,omitempty"`
}

type GatewayTLSConfig struct {
	Mode            string `json:"mode"`
	CertificatePath string `json:"certificate_path,omitempty"`
	PrivateKeyPath  string `json:"private_key_path,omitempty"`
}

type VerificationConfig struct {
	Enabled                     bool `json:"enabled"`
	MinimumSuccessfulProbes     int  `json:"minimum_successful_probes"`
	MinimumDistinctNetworks     int  `json:"minimum_distinct_networks"`
	VerificationTimeoutSeconds  int  `json:"verification_timeout_seconds"`
	RegistrationValiditySeconds int  `json:"registration_validity_seconds"`
	ProbeResultValiditySeconds  int  `json:"probe_result_validity_seconds"`
	ReverifyIntervalSeconds     int  `json:"reverify_interval_seconds"`
}

type GatewayHealthConfig struct {
	FailureThreshold     int `json:"failure_threshold"`
	RecoveryThreshold    int `json:"recovery_threshold"`
	CheckIntervalSeconds int `json:"check_interval_seconds"`
	DrainSeconds         int `json:"drain_seconds"`
}

type EligibilityConfig struct {
	MinimumUploadMbps    int   `json:"minimum_upload_mbps"`
	MinimumFreeMemoryMB  int64 `json:"minimum_free_memory_mb"`
	MinimumFreeDiskMB    int64 `json:"minimum_free_disk_mb"`
	MaximumCPUPercent    int   `json:"maximum_cpu_percent"`
	RequirePublicAddress bool  `json:"require_public_address"`
	RejectCGNAT          bool  `json:"reject_cgnat"`
}

type DNSConfig struct {
	Enabled                       bool     `json:"enabled"`
	Hostname                      string   `json:"hostname"`
	TTLSeconds                    int      `json:"ttl_seconds"`
	Provider                      string   `json:"provider"`
	ProviderEndpoint              string   `json:"provider_endpoint,omitempty"`
	CredentialsSource             string   `json:"credentials_source"`
	ReconciliationIntervalSeconds int      `json:"reconciliation_interval_seconds"`
	DryRun                        bool     `json:"dry_run"`
	Freeze                        bool     `json:"freeze"`
	MaxRecords                    int      `json:"max_records"`
	MaxMutations                  int      `json:"max_mutations"`
	GatewayNodeIDs                []string `json:"gateway_node_ids,omitempty"`
}

func DefaultDataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "Syndichan", "storage-node"), nil
}

func Default() (Config, error) {
	dir, err := DefaultDataDir()
	if err != nil {
		return Config{}, err
	}
	return Config{
		DataDir:  dir,
		S3Listen: "127.0.0.1:9000",
		UIListen: "127.0.0.1:9090",
		// P2PListen is retained only so old configuration files still parse. The
		// production node never uses these clearnet addresses.
		P2PListen:     nil,
		I2PSAM:        "127.0.0.1:7656",
		I2PHTTPProxy:  "http://127.0.0.1:4444",
		CapacityBytes: 20 << 30,
		DataShards:    6,
		ParityShards:  3,
		ChunkBytes:    1 << 20,
		Gateway: GatewayConfig{
			ListenAddress: "0.0.0.0", ListenPort: 443,
			AdvertiseIPv4: true, AdvertiseIPv6: true,
			TLS: GatewayTLSConfig{Mode: "existing"},
			Verification: VerificationConfig{
				Enabled: true, MinimumSuccessfulProbes: 3,
				MinimumDistinctNetworks: 2, VerificationTimeoutSeconds: 15,
				RegistrationValiditySeconds: 300, ProbeResultValiditySeconds: 120,
				ReverifyIntervalSeconds: 60,
			},
			Health: GatewayHealthConfig{
				FailureThreshold: 3, RecoveryThreshold: 2,
				CheckIntervalSeconds: 30, DrainSeconds: 60,
			},
			Eligibility: EligibilityConfig{
				MinimumUploadMbps: 10, MinimumFreeMemoryMB: 512,
				MinimumFreeDiskMB: 1024, MaximumCPUPercent: 90,
				RequirePublicAddress: true, RejectCGNAT: true,
			},
		},
		DNS: DNSConfig{
			TTLSeconds: 60, CredentialsSource: "environment",
			ReconciliationIntervalSeconds: 30, DryRun: true,
			MaxRecords: 100, MaxMutations: 10,
		},
	}, nil
}

func LoadOrCreate(path string) (Config, bool, error) {
	cfg, err := Default()
	if err != nil {
		return Config{}, false, err
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return Config{}, false, fmt.Errorf("parse config: %w", err)
		}
		return cfg, false, cfg.Validate()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Config{}, false, err
	}
	cfg.DataDir = filepath.Dir(path)
	cfg.AccessKey = "SYN" + randomToken(12)
	cfg.SecretKey = randomToken(32)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return Config{}, false, err
	}
	raw, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Config{}, false, err
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
		return Config{}, false, err
	}
	return cfg, true, cfg.Validate()
}

func (c Config) Validate() error {
	if c.AccessKey == "" || len(c.SecretKey) < 32 {
		return errors.New("S3 credentials are missing or too short")
	}
	if c.DataShards < 2 || c.ParityShards < 1 || c.DataShards+c.ParityShards > 64 {
		return errors.New("erasure coding must use 2-63 data shards and at least one parity shard")
	}
	if c.ChunkBytes < 64<<10 || c.ChunkBytes > 16<<20 {
		return errors.New("chunk_bytes must be between 64 KiB and 16 MiB")
	}
	if c.CapacityBytes < 64<<20 {
		return errors.New("capacity_bytes must be at least 64 MiB")
	}
	if c.CapacityBytes > 8<<50 {
		return errors.New("capacity_bytes must not exceed 8 PiB")
	}
	if err := c.validateGateway(); err != nil {
		return err
	}
	uiHost, _, err := net.SplitHostPort(c.UIListen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.UIListen, err)
	}
	if !isLoopback(uiHost) {
		return errors.New("the management dashboard must remain bound to loopback")
	}
	s3Host, _, err := net.SplitHostPort(c.S3Listen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.S3Listen, err)
	}
	if !isLoopback(s3Host) && (c.TLSCert == "" || c.TLSKey == "") {
		return fmt.Errorf("%s is non-loopback; TLS certificate and key are required", c.S3Listen)
	}
	samHost, _, err := net.SplitHostPort(c.I2PSAM)
	if err != nil {
		return fmt.Errorf("invalid I2P SAM address %q: %w", c.I2PSAM, err)
	}
	if !isLoopback(samHost) {
		return errors.New("the I2P SAM bridge must be on loopback")
	}
	proxy, err := url.Parse(c.I2PHTTPProxy)
	if err != nil || proxy.Scheme != "http" || proxy.User != nil || proxy.Path != "" ||
		proxy.RawQuery != "" || proxy.Fragment != "" {
		return errors.New("i2p_http_proxy must be an unauthenticated loopback HTTP proxy URL")
	}
	proxyHost, _, err := net.SplitHostPort(proxy.Host)
	if err != nil || !isLoopback(proxyHost) {
		return errors.New("i2p_http_proxy must point to a loopback address")
	}
	return nil
}

func (c Config) validateGateway() error {
	g := c.Gateway
	if g.ListenPort < 1 || g.ListenPort > 65535 {
		return errors.New("gateway listen_port must be between 1 and 65535")
	}
	if g.Enabled || g.ProbeEnabled {
		if g.PublicHostname == "" || strings.ContainsAny(g.PublicHostname, "/:@") {
			return errors.New("gateway public_hostname is required and must be a hostname")
		}
		if g.TLS.Mode != "existing" && g.TLS.Mode != "reverse_proxy" {
			return errors.New("gateway tls mode must be existing or reverse_proxy")
		}
		if g.TLS.Mode == "existing" &&
			(g.TLS.CertificatePath == "" || g.TLS.PrivateKeyPath == "") {
			return errors.New("gateway existing TLS mode requires certificate and private key paths")
		}
	}
	if g.ProbeEnabled && strings.TrimSpace(g.ProbeNetwork) == "" {
		return errors.New("probe_network is required when probe mode is enabled")
	}
	if g.Enabled && g.Verification.Enabled {
		if len(g.PublicAddresses) == 0 {
			return errors.New("gateway public_addresses are required for external verification")
		}
		if len(g.ProbeURLs) < g.Verification.MinimumSuccessfulProbes {
			return errors.New("gateway needs at least as many probe_urls as its quorum")
		}
	}
	v := g.Verification
	if v.MinimumSuccessfulProbes < 1 || v.MinimumDistinctNetworks < 1 ||
		v.MinimumDistinctNetworks > v.MinimumSuccessfulProbes {
		return errors.New("invalid gateway verification quorum")
	}
	if v.VerificationTimeoutSeconds < 1 || v.ProbeResultValiditySeconds < 1 ||
		v.RegistrationValiditySeconds < 1 || v.ReverifyIntervalSeconds < 1 {
		return errors.New("gateway verification durations must be positive")
	}
	if c.DNS.Enabled {
		if c.DNS.Hostname == "" {
			return errors.New("dns hostname is required")
		}
		if g.PublicHostname != "" && c.DNS.Hostname != g.PublicHostname {
			return errors.New("dns hostname must match gateway public_hostname when both are configured")
		}
		if c.DNS.TTLSeconds < 30 || c.DNS.MaxRecords < 1 || c.DNS.MaxMutations < 1 {
			return errors.New("invalid dns safety limits")
		}
		if c.DNS.Provider == "" {
			return errors.New("dns provider is required when dns is enabled")
		}
		if c.DNS.Provider != "https-api" || c.DNS.ProviderEndpoint == "" {
			return errors.New("dns provider must be https-api with provider_endpoint")
		}
	}
	return nil
}

func isLoopback(host string) bool {
	host = strings.Trim(host, "[]")
	return host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func randomToken(bytes int) string {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

// Save writes the config back atomically at mode 0600. Used when a flag such
// as -data-dir changes a persisted value, so the setting survives restarts
// instead of having to be repeated on every launch.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	// Write-then-rename so an interrupted save cannot leave a truncated config
	// that would lose the S3 credentials and master key references.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ConfigPath(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	dir, err := DefaultDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func PlatformLabel() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}
