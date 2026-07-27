package config

import "testing"

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
