package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type registrySigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func (s registrySigner) ID() string { return "test-node" }
func (s registrySigner) Sign(value []byte) ([]byte, error) {
	return ed25519.Sign(s.private, value), nil
}
func (s registrySigner) PublicKey() ([]byte, error) { return s.public, nil }
func (s registrySigner) DHTReady() bool             { return true }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestRegistryRequestHasSignatureAndNoReusableSecret(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := registrySigner{public: public, private: private}
	client, err := NewRegistryClient("https://syndichan.org/api/v1/gateways", "gw-001.syndichan.org", signer)
	if err != nil {
		t.Fatal(err)
	}
	client.Now = func() time.Time { return time.Unix(1700000000, 0) }
	client.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		signature, err := base64.RawStdEncoding.DecodeString(request.Header.Get("X-Syndichan-Signature"))
		if err != nil || !ed25519.Verify(public, body, signature) {
			t.Fatal("request signature was invalid")
		}
		if request.Header.Get("Authorization") != "" ||
			strings.Contains(strings.ToLower(string(body)), "token") {
			t.Fatal("request exposed a reusable credential")
		}
		if request.Header.Get("User-Agent") != RegistryUserAgent {
			t.Fatal("unexpected user agent")
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	registration := Registration{NodeID: signer.ID(), HealthState: StateHealthy}
	if err := client.PublishGatewayRegistration(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryEndpointRejectsEmbeddedCredentials(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	_, err := NewRegistryClient(
		"https://user:secret@syndichan.org/api/v1/gateways", "gw-001.syndichan.org",
		registrySigner{private: private},
	)
	if err == nil {
		t.Fatal("credential-bearing endpoint was accepted")
	}
}
