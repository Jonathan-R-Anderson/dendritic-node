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
