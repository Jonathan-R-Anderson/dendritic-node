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

// Peer discovery starts at the dedicated data-node edge. That edge exposes only
// this well-known document over publicly trusted TLS; coordinator leases and
// the direct five-minute presence heartbeat remain separate concerns.
const BootstrapURL = "https://node.syndichan.org/.well-known/syndichan/storage-node.json"

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
	// RegistrationAPI is a public, credential-free HTTPS endpoint. The node
	// authenticates requests with its existing Ed25519 identity; authoritative
	// DNS credentials exist only on that server.
	RegistrationAPI string                `json:"registration_api"`
	Frontend        GatewayFrontendConfig `json:"frontend"`
}

type GatewayFrontendConfig struct {
	Enabled                 bool     `json:"enabled"`
	OriginAddress           string   `json:"origin_address"`
	OriginServerName        string   `json:"origin_server_name"`
	SNIAllowlist            []string `json:"sni_allowlist"`
	MaxConnections          int      `json:"max_connections"`
	MaxBytesPerSecond       int64    `json:"max_bytes_per_second"`
	HandshakeTimeoutSeconds int      `json:"handshake_timeout_seconds"`
	DialTimeoutSeconds      int      `json:"dial_timeout_seconds"`
	IdleTimeoutSeconds      int      `json:"idle_timeout_seconds"`
	DrainSeconds            int      `json:"drain_seconds"`
	ProxyProtocol           bool     `json:"proxy_protocol"`
	// AllowPrivateOrigin is an explicit development escape hatch. Production
	// configurations must never silently turn a volunteer into a route to its
	// loopback or private network.
	AllowPrivateOrigin bool `json:"allow_private_origin,omitempty"`
}

type GatewayTLSConfig struct {
	Mode               string `json:"mode"`
	CertificatePath    string `json:"certificate_path,omitempty"`
	PrivateKeyPath     string `json:"private_key_path,omitempty"`
	ACMEEmail          string `json:"acme_email,omitempty"`
	ACMEHTTPAddress    string `json:"acme_http_address,omitempty"`
	ACMECacheDirectory string `json:"acme_cache_directory,omitempty"`
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
			RegistrationAPI: "https://syndichan.org/api/v1/gateways",
			TLS: GatewayTLSConfig{
				Mode: "existing", ACMEHTTPAddress: "0.0.0.0:80",
			},
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
			Frontend: GatewayFrontendConfig{
				Enabled: false, OriginAddress: "",
				OriginServerName: "syndichan.org",
				SNIAllowlist:     []string{"syndichan.org"},
				MaxConnections:   1024, MaxBytesPerSecond: 16 << 20,
				HandshakeTimeoutSeconds: 10,
				DialTimeoutSeconds:      10, IdleTimeoutSeconds: 300,
				DrainSeconds: 60, ProxyProtocol: true,
			},
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
		if strings.ContainsAny(g.PublicHostname, "/:@") {
			return errors.New("gateway public_hostname is required and must be a hostname")
		}
		if g.PublicHostname == "" && (!g.Enabled || g.TLS.Mode != "acme") {
			return errors.New("gateway public_hostname is required unless ACME uses controller reservation")
		}
		if g.TLS.Mode != "existing" && g.TLS.Mode != "acme" &&
			g.TLS.Mode != "reverse_proxy" {
			return errors.New("gateway tls mode must be existing, acme, or reverse_proxy")
		}
		if g.TLS.Mode == "existing" &&
			(g.TLS.CertificatePath == "" || g.TLS.PrivateKeyPath == "") {
			return errors.New("gateway existing TLS mode requires certificate and private key paths")
		}
		if g.TLS.Mode == "acme" {
			if g.PublicHostname != "" && !validLiteralHostname(g.PublicHostname) {
				return errors.New("gateway ACME mode requires a literal public hostname")
			}
			if _, _, err := net.SplitHostPort(g.TLS.ACMEHTTPAddress); err != nil {
				return errors.New("gateway ACME HTTP address must be host:port")
			}
		}
		if g.Frontend.Enabled && g.TLS.Mode == "reverse_proxy" {
			return errors.New("gateway frontend requires existing or ACME TLS for its local identity endpoint")
		}
	}
	if g.Enabled {
		registry, err := url.Parse(g.RegistrationAPI)
		if err != nil || registry.Scheme != "https" || registry.Host == "" ||
			registry.User != nil || registry.RawQuery != "" || registry.Fragment != "" {
			return errors.New("gateway registration_api must be a credential-free HTTPS URL")
		}
		if registry.Path == "" || registry.Path == "/" {
			return errors.New("gateway registration_api must include its API path")
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
	if err := validateGatewayFrontend(g.Frontend); err != nil {
		return err
	}
	return nil
}

func validateGatewayFrontend(frontend GatewayFrontendConfig) error {
	if !frontend.Enabled {
		return nil
	}
	host, port, err := net.SplitHostPort(frontend.OriginAddress)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return errors.New("gateway frontend origin_address must be host:port")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return errors.New("gateway frontend origin_address has an invalid port")
	}
	originHost := strings.Trim(strings.ToLower(host), "[]")
	if !frontend.AllowPrivateOrigin && isPrivateOrLocalHost(originHost) {
		return errors.New("gateway frontend origin is loopback/private; set allow_private_origin only for development")
	}
	if !validLiteralHostname(frontend.OriginServerName) {
		return errors.New("gateway frontend origin_server_name must be a literal hostname")
	}
	if len(frontend.SNIAllowlist) == 0 {
		return errors.New("gateway frontend sni_allowlist must not be empty")
	}
	for _, hostname := range frontend.SNIAllowlist {
		if !validLiteralHostname(hostname) {
			return fmt.Errorf("gateway frontend SNI entry %q must be a literal hostname", hostname)
		}
	}
	if frontend.MaxConnections < 1 {
		return errors.New("gateway frontend max_connections must be positive")
	}
	if frontend.MaxBytesPerSecond < 1 {
		return errors.New("gateway frontend max_bytes_per_second must be positive")
	}
	if frontend.HandshakeTimeoutSeconds < 1 || frontend.DialTimeoutSeconds < 1 ||
		frontend.IdleTimeoutSeconds < 1 || frontend.DrainSeconds < 0 {
		return errors.New("gateway frontend timeouts must be positive and drain_seconds non-negative")
	}
	return nil
}

func validLiteralHostname(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "* /:@[]") ||
		net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func isPrivateOrLocalHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && (address.IsLoopback() || address.IsPrivate() ||
		address.IsLinkLocalUnicast() || address.IsUnspecified())
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
