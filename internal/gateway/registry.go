package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const RegistryUserAgent = "Syndichan-Storage-Client/1.0"

// RegistryClient sends signed, short-lived statements to the central gateway
// controller. It deliberately has no credential field: the node identity is
// the client credential, while Name.com credentials remain server-side.
type RegistryClient struct {
	Endpoint       string
	PublicHostname string
	Signer         Signer
	Client         *http.Client
	Now            func() time.Time
}

type registryRequest struct {
	Version        int          `json:"version"`
	NodeID         string       `json:"node_id"`
	PublicKey      string       `json:"public_key"`
	PublicHostname string       `json:"public_hostname"`
	Port           int          `json:"port"`
	Timestamp      int64        `json:"timestamp"`
	Nonce          string       `json:"nonce"`
	Registration   Registration `json:"registration"`
}

func NewRegistryClient(endpoint, hostname string, signer Signer) (*RegistryClient, error) {
	parsed, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("registration endpoint must be a credential-free HTTPS URL")
	}
	if signer == nil || hostname == "" {
		return nil, errors.New("registration signer and public hostname are required")
	}
	return &RegistryClient{
		Endpoint: strings.TrimRight(endpoint, "/"), PublicHostname: hostname,
		Signer: signer, Now: time.Now,
		Client: &http.Client{
			Timeout: 25 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("registration redirects are forbidden")
			},
		},
	}, nil
}

func (c *RegistryClient) PublishGatewayRegistration(ctx context.Context, registration Registration) error {
	publicKey, err := c.Signer.PublicKey()
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("create nonce: %w", err)
	}
	now := c.Now().UTC()
	body, err := json.Marshal(registryRequest{
		Version: ProtocolVersion, NodeID: c.Signer.ID(),
		PublicKey:      base64.RawStdEncoding.EncodeToString(publicKey),
		PublicHostname: c.PublicHostname, Port: 443, Timestamp: now.Unix(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Registration: registration,
	})
	if err != nil {
		return err
	}
	signature, err := c.Signer.Sign(body)
	if err != nil {
		return fmt.Errorf("sign registration request: %w", err)
	}
	action := "register"
	if registration.HealthState == StateDraining ||
		registration.HealthState == StateUnhealthy ||
		registration.HealthState == StateRemoved {
		action = "unregister"
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.Endpoint+"/"+action, bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", RegistryUserAgent)
	request.Header.Set("X-Syndichan-Node", c.Signer.ID())
	request.Header.Set("X-Syndichan-Signature", base64.RawStdEncoding.EncodeToString(signature))
	response, err := c.Client.Do(request)
	if err != nil {
		return fmt.Errorf("gateway registry: %w", err)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("gateway registry returned HTTP %d", response.StatusCode)
	}
	return nil
}

// MultiPublisher performs the authoritative server registration first. A
// failed server-side verification therefore cannot accidentally become a
// successful local/DHT registration.
type MultiPublisher struct {
	Publishers []RegistrationPublisher
}

func (m MultiPublisher) PublishGatewayRegistration(ctx context.Context, registration Registration) error {
	for _, publisher := range m.Publishers {
		if publisher == nil {
			continue
		}
		if err := publisher.PublishGatewayRegistration(ctx, registration); err != nil {
			return err
		}
	}
	return nil
}
