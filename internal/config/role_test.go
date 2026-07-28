package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gatewayCandidateConfig is a complete, valid storage node that also runs the
// gateway role. Individual tests then remove pieces of it to prove which
// pieces each runtime role actually depends on.
func gatewayCandidateConfig(t *testing.T) Config {
	t.Helper()
	cfg := validTestConfig(t)
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicHostname = "gw-node.example.com"
	cfg.Gateway.TLS.Mode = "existing"
	cfg.Gateway.TLS.CertificatePath = "cert.pem"
	cfg.Gateway.TLS.PrivateKeyPath = "key.pem"
	cfg.Gateway.PublicAddresses = []string{"198.51.100.10"}
	cfg.Gateway.ProbeURLs = []string{
		"https://probe-a.example", "https://probe-b.example", "https://probe-c.example",
	}
	return cfg
}

func probeCandidateConfig(t *testing.T) Config {
	t.Helper()
	cfg := gatewayCandidateConfig(t)
	cfg.Gateway.Enabled = false
	cfg.Gateway.ProbeEnabled = true
	cfg.Gateway.ProbeNetwork = "AS64500"
	return cfg
}

// storageRemovals are the settings a dedicated gateway or probe host genuinely
// does not have. None of them may block startup for a storage-free role.
var storageRemovals = []struct {
	name   string
	mutate func(*Config)
}{
	{"missing S3 credentials", func(c *Config) { c.AccessKey, c.SecretKey = "", "" }},
	{"short S3 secret", func(c *Config) { c.SecretKey = "too-short" }},
	{"missing dashboard configuration", func(c *Config) { c.UIListen = "" }},
	{"public dashboard address", func(c *Config) { c.UIListen = "0.0.0.0:9090" }},
	{"missing S3 listen address", func(c *Config) { c.S3Listen = "" }},
	{"missing storage capacity", func(c *Config) { c.CapacityBytes = 0 }},
	{"missing erasure layout", func(c *Config) { c.DataShards, c.ParityShards = 0, 0 }},
	{"missing chunk size", func(c *Config) { c.ChunkBytes = 0 }},
	{"missing I2P SAM bridge", func(c *Config) { c.I2PSAM = "" }},
	{"missing I2P HTTP proxy", func(c *Config) { c.I2PHTTPProxy = "" }},
	{"no storage configuration at all", func(c *Config) {
		c.AccessKey, c.SecretKey = "", ""
		c.UIListen, c.S3Listen = "", ""
		c.I2PSAM, c.I2PHTTPProxy = "", ""
		c.CapacityBytes, c.DataShards, c.ParityShards, c.ChunkBytes = 0, 0, 0, 0
	}},
}

func TestGatewayOnlyIgnoresStorageConfiguration(t *testing.T) {
	for _, test := range storageRemovals {
		t.Run(test.name, func(t *testing.T) {
			cfg := gatewayCandidateConfig(t)
			test.mutate(&cfg)
			if err := cfg.ValidateForRole(RoleGatewayOnly); err != nil {
				t.Fatalf("gateway-only rejected for a storage setting it never uses: %v", err)
			}
		})
	}
}

func TestProbeOnlyIgnoresStorageConfiguration(t *testing.T) {
	for _, test := range storageRemovals {
		t.Run(test.name, func(t *testing.T) {
			cfg := probeCandidateConfig(t)
			test.mutate(&cfg)
			if err := cfg.ValidateForRole(RoleProbeOnly); err != nil {
				t.Fatalf("probe-only rejected for a storage setting it never uses: %v", err)
			}
		})
	}
}

// The other direction: a storage node must still be held to every one of them.
func TestStorageRoleStillValidatesStorageConfiguration(t *testing.T) {
	for _, test := range storageRemovals {
		t.Run(test.name, func(t *testing.T) {
			cfg := gatewayCandidateConfig(t)
			test.mutate(&cfg)
			if err := cfg.ValidateForRole(RoleStorage); err == nil {
				t.Fatal("storage role accepted an unusable storage configuration")
			}
		})
	}
	cfg := gatewayCandidateConfig(t)
	cfg.AccessKey, cfg.SecretKey = "", ""
	err := cfg.ValidateForRole(RoleStorage)
	if err == nil || !strings.Contains(err.Error(), "S3 credentials") {
		t.Fatalf("storage role lost its S3 credential check: %v", err)
	}
}

func TestGatewayOnlyStillRequiresGatewayConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no gateway or probe role", func(c *Config) {
			c.Gateway.Enabled, c.Gateway.ProbeEnabled = false, false
		}},
		{"missing TLS mode", func(c *Config) { c.Gateway.TLS.Mode = "" }},
		{"missing TLS certificate", func(c *Config) { c.Gateway.TLS.CertificatePath = "" }},
		{"missing TLS private key", func(c *Config) { c.Gateway.TLS.PrivateKeyPath = "" }},
		{"missing public hostname", func(c *Config) { c.Gateway.PublicHostname = "" }},
		{"missing registration API", func(c *Config) { c.Gateway.RegistrationAPI = "" }},
		{"credential-bearing registration API", func(c *Config) {
			c.Gateway.RegistrationAPI = "https://user:token@syndichan.org/api/v1/gateways"
		}},
		{"missing public addresses", func(c *Config) { c.Gateway.PublicAddresses = nil }},
		{"probe quorum larger than probe list", func(c *Config) { c.Gateway.ProbeURLs = nil }},
		{"invalid listen port", func(c *Config) { c.Gateway.ListenPort = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := gatewayCandidateConfig(t)
			test.mutate(&cfg)
			err := cfg.ValidateForRole(RoleGatewayOnly)
			if err == nil {
				t.Fatal("gateway-only accepted an incomplete gateway configuration")
			}
			// The failure must be about the gateway, never about storage.
			if strings.Contains(err.Error(), "S3") {
				t.Fatalf("gateway-only failed on storage configuration: %v", err)
			}
		})
	}
}

func TestProbeOnlyRequiresProbeRole(t *testing.T) {
	cfg := probeCandidateConfig(t)
	cfg.Gateway.ProbeEnabled = false
	if err := cfg.ValidateForRole(RoleProbeOnly); err == nil {
		t.Fatal("probe-only accepted a config with no probe role")
	}
	cfg = probeCandidateConfig(t)
	cfg.Gateway.Enabled = true
	if err := cfg.ValidateForRole(RoleProbeOnly); err == nil {
		t.Fatal("probe-only accepted a config that also enables the gateway role")
	}
	cfg = probeCandidateConfig(t)
	cfg.Gateway.ProbeNetwork = ""
	if err := cfg.ValidateForRole(RoleProbeOnly); err == nil {
		t.Fatal("probe-only accepted a probe with no network trust domain")
	}
}

// -gateway-status and friends must work on a dedicated gateway's own config,
// which has no storage settings at all.
func TestManagementRoleIgnoresStorageConfiguration(t *testing.T) {
	for _, test := range storageRemovals {
		t.Run(test.name, func(t *testing.T) {
			cfg := gatewayCandidateConfig(t)
			test.mutate(&cfg)
			if err := cfg.ValidateForRole(RoleManagement); err != nil {
				t.Fatalf("config management rejected a storage-free config: %v", err)
			}
		})
	}
	// It also accepts a config with no gateway role at all, which is what
	// -gateway-disable leaves behind.
	cfg := gatewayCandidateConfig(t)
	cfg.Gateway.Enabled, cfg.Gateway.ProbeEnabled = false, false
	if err := cfg.ValidateForRole(RoleManagement); err != nil {
		t.Fatalf("config management rejected a node with no gateway role: %v", err)
	}
	// But -gateway-enable must still refuse to save a broken gateway section.
	cfg = gatewayCandidateConfig(t)
	cfg.Gateway.TLS.CertificatePath = ""
	if err := cfg.ValidateForRole(RoleManagement); err == nil {
		t.Fatal("config management saved an unusable gateway section")
	}
}

func TestUnknownRoleIsRejected(t *testing.T) {
	if err := gatewayCandidateConfig(t).ValidateForRole(Role("bogus")); err == nil {
		t.Fatal("an unknown runtime role was accepted")
	}
}

// The reported bug, end to end: a hand-written gateway.json holds no S3
// credentials, and -gateway-only must start from it.
func TestLoadOrCreateGatewayOnlyAcceptsConfigWithoutStorageSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.json")
	raw := []byte(`{
	  "gateway": {
	    "enabled": true,
	    "listen_port": 443,
	    "public_hostname": "gw-node.example.com",
	    "registration_api": "https://syndichan.org/api/v1/gateways",
	    "tls": {"mode": "existing", "certificate_path": "cert.pem", "private_key_path": "key.pem"},
	    "public_addresses": ["198.51.100.10"],
	    "probe_urls": [
	      "https://probe-a.example", "https://probe-b.example", "https://probe-c.example"
	    ]
	  }
	}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, created, err := LoadOrCreate(path, RoleGatewayOnly)
	if err != nil {
		t.Fatalf("gateway-only refused a storage-free gateway config: %v", err)
	}
	if created {
		t.Fatal("existing config reported as newly created")
	}
	if cfg.AccessKey != "" || cfg.SecretKey != "" {
		t.Fatal("loading a gateway config invented S3 credentials")
	}
	// Same file, storage role: the S3 check must still fire.
	if _, _, err := LoadOrCreate(path, RoleStorage); err == nil {
		t.Fatal("storage role accepted a config with no S3 credentials")
	}
}

// A config created by the gateway-only path must round-trip through Save
// without the storage validation rejecting it.
func TestSaveRoundTripsAStorageFreeGatewayConfig(t *testing.T) {
	cfg := gatewayCandidateConfig(t)
	cfg.AccessKey, cfg.SecretKey = "", ""
	cfg.I2PSAM, cfg.I2PHTTPProxy, cfg.UIListen, cfg.S3Listen = "", "", "", ""
	path := filepath.Join(t.TempDir(), "gateway.json")
	if err := Save(path, cfg, RoleGatewayOnly); err != nil {
		t.Fatalf("saving a gateway-only config failed: %v", err)
	}
	if _, _, err := LoadOrCreate(path, RoleGatewayOnly); err != nil {
		t.Fatalf("reloading a gateway-only config failed: %v", err)
	}
	if err := Save(path, cfg, RoleStorage); err == nil {
		t.Fatal("storage role saved a config it could not start from")
	}
}

// The documented copy-paste path: gateway.example.json must carry no storage
// settings and must be startable as a dedicated gateway once its host-specific
// fields are filled in.
func TestShippedGatewayExampleNeedsNoStorageConfiguration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "gateway.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var probe struct {
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.AccessKey != "" || probe.SecretKey != "" {
		t.Fatal("the gateway example ships S3 credentials a gateway never uses")
	}
	cfg, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.AccessKey, cfg.SecretKey = "", ""
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicAddresses = []string{"198.51.100.10"}
	cfg.Gateway.ProbeURLs = []string{
		"https://probe-a.example", "https://probe-b.example", "https://probe-c.example",
	}
	if err := cfg.ValidateForRole(RoleGatewayOnly); err != nil {
		t.Fatalf("the documented gateway example cannot start as a gateway: %v", err)
	}
}
