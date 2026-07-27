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
	CacheOnly     bool     `json:"cache_only"`
	UIListen      string   `json:"ui_listen"`
	P2PListen     []string `json:"p2p_listen"`
	I2PSAM        string   `json:"i2p_sam"`
	I2PHTTPProxy  string   `json:"i2p_http_proxy"`
	AccessKey     string   `json:"access_key"`
	SecretKey     string   `json:"secret_key"`
	CapacityBytes int64    `json:"capacity_bytes"`
	DataShards    int      `json:"data_shards"`
	ParityShards  int      `json:"parity_shards"`
	ChunkBytes    int      `json:"chunk_bytes"`
	TLSCert       string   `json:"tls_cert,omitempty"`
	TLSKey        string   `json:"tls_key,omitempty"`
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
