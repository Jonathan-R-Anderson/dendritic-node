package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func validTestConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	cfg.AccessKey = "SYNTEST"
	cfg.SecretKey = "a-secret-key-that-is-at-least-32-bytes"
	return cfg
}

func TestDashboardMustRemainLoopback(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.UIListen = "0.0.0.0:9090"
	cfg.TLSCert = "cert.pem"
	cfg.TLSKey = "key.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("public dashboard binding was accepted")
	}
}

func TestPublicS3RequiresTLS(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.S3Listen = "0.0.0.0:9000"
	if err := cfg.Validate(); err == nil {
		t.Fatal("cleartext public S3 binding was accepted")
	}
	cfg.TLSCert = "cert.pem"
	cfg.TLSKey = "key.pem"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("TLS public S3 binding was rejected: %v", err)
	}
}

func TestI2PControlEndpointsMustRemainLoopback(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.I2PSAM = "192.0.2.10:7656"
	if err := cfg.Validate(); err == nil {
		t.Fatal("remote cleartext SAM bridge was accepted")
	}
	cfg = validTestConfig(t)
	cfg.I2PHTTPProxy = "http://192.0.2.10:4444"
	if err := cfg.Validate(); err == nil {
		t.Fatal("remote I2P HTTP proxy was accepted")
	}
}

func TestGatewayDefaultDisabledAndRegistryIsPublicConfiguration(t *testing.T) {
	cfg := validTestConfig(t)
	if cfg.Gateway.Enabled {
		t.Fatal("public gateway is enabled by default")
	}
	if cfg.Gateway.RegistrationAPI != "https://syndichan.org/api/v1/gateways" {
		t.Fatal("unexpected registration API default")
	}
}

func TestGatewayRequiresExternalQuorumConfiguration(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicHostname = "gateway.example.com"
	cfg.Gateway.TLS.CertificatePath = "cert.pem"
	cfg.Gateway.TLS.PrivateKeyPath = "key.pem"
	if err := cfg.Validate(); err == nil {
		t.Fatal("gateway without addresses/probes was accepted")
	}
	cfg.Gateway.PublicAddresses = []string{"8.8.8.8"}
	cfg.Gateway.ProbeURLs = []string{
		"https://probe-a.example", "https://probe-b.example", "https://probe-c.example",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fully configured candidate rejected: %v", err)
	}
}

func TestGatewayRejectsCredentialBearingRegistrationAPI(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.Gateway.Enabled = true
	cfg.Gateway.PublicHostname = "gw-001.syndichan.org"
	cfg.Gateway.TLS.CertificatePath = "cert.pem"
	cfg.Gateway.TLS.PrivateKeyPath = "key.pem"
	cfg.Gateway.PublicAddresses = []string{"8.8.8.8"}
	cfg.Gateway.ProbeURLs = []string{
		"https://probe-a.example", "https://probe-b.example", "https://probe-c.example",
	}
	cfg.Gateway.RegistrationAPI = "https://user:token@syndichan.org/api/v1/gateways"
	if err := cfg.Validate(); err == nil {
		t.Fatal("credential-bearing registration API was accepted")
	}
}

func TestGatewayFrontendDefaultsDisabled(t *testing.T) {
	cfg := validTestConfig(t)
	if cfg.Gateway.Frontend.Enabled {
		t.Fatal("gateway frontend is enabled by default")
	}
	if !cfg.Gateway.Frontend.ProxyProtocol {
		t.Fatal("secure frontend default must preserve client addresses")
	}
}

func TestGatewayFrontendValidation(t *testing.T) {
	valid := func() Config {
		cfg := validTestConfig(t)
		cfg.Gateway.Frontend.Enabled = true
		cfg.Gateway.Frontend.OriginAddress = "origin.syndichan.org:9443"
		cfg.Gateway.Frontend.OriginServerName = "syndichan.org"
		cfg.Gateway.Frontend.SNIAllowlist = []string{"syndichan.org", "gw-node.syndichan.org"}
		return cfg
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid frontend rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing port", func(c *Config) { c.Gateway.Frontend.OriginAddress = "origin.example" }},
		{"empty allowlist", func(c *Config) { c.Gateway.Frontend.SNIAllowlist = nil }},
		{"wildcard allowlist", func(c *Config) { c.Gateway.Frontend.SNIAllowlist = []string{"*.example"} }},
		{"suffix pattern", func(c *Config) { c.Gateway.Frontend.SNIAllowlist = []string{".example"} }},
		{"IP allowlist", func(c *Config) { c.Gateway.Frontend.SNIAllowlist = []string{"203.0.113.1"} }},
		{"private origin", func(c *Config) { c.Gateway.Frontend.OriginAddress = "10.0.0.2:443" }},
		{"loopback origin", func(c *Config) { c.Gateway.Frontend.OriginAddress = "localhost:443" }},
		{"zero connections", func(c *Config) { c.Gateway.Frontend.MaxConnections = 0 }},
		{"zero handshake timeout", func(c *Config) { c.Gateway.Frontend.HandshakeTimeoutSeconds = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid frontend configuration was accepted")
			}
		})
	}
	cfg := valid()
	cfg.Gateway.Frontend.OriginAddress = "127.0.0.1:9443"
	cfg.Gateway.Frontend.AllowPrivateOrigin = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit private-origin escape hatch rejected: %v", err)
	}
}

func TestGatewayFrontendSaveLoadRoundTrip(t *testing.T) {
	cfg := validTestConfig(t)
	cfg.Gateway.Frontend.Enabled = true
	cfg.Gateway.Frontend.OriginAddress = "origin.syndichan.org:9443"
	cfg.Gateway.Frontend.OriginServerName = "syndichan.org"
	cfg.Gateway.Frontend.SNIAllowlist = []string{"syndichan.org"}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, created, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing config reported as newly created")
	}
	if !reflect.DeepEqual(loaded.Gateway.Frontend, cfg.Gateway.Frontend) {
		t.Fatalf("frontend block changed during round trip:\n got %#v\nwant %#v",
			loaded.Gateway.Frontend, cfg.Gateway.Frontend)
	}
}
