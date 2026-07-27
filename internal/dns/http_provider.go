package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPProvider talks to the project-owned authoritative DNS API. The token is
// supplied by the DNS-controller process environment and is never serialized.
// The API must enforce the same single-hostname and A/AAAA restrictions.
type HTTPProvider struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

func (p *HTTPProvider) ListRecords(ctx context.Context, hostname string) ([]Record, error) {
	var result struct {
		Records []Record `json:"records"`
	}
	err := p.do(ctx, http.MethodGet, "?hostname="+url.QueryEscape(hostname), nil, &result)
	return result.Records, err
}

func (p *HTTPProvider) CreateRecord(ctx context.Context, record Record) error {
	return p.do(ctx, http.MethodPost, "", record, nil)
}

func (p *HTTPProvider) UpdateRecord(ctx context.Context, record Record) error {
	return p.do(ctx, http.MethodPut, "/"+url.PathEscape(record.ID), record, nil)
}

func (p *HTTPProvider) DeleteRecord(ctx context.Context, record Record) error {
	return p.do(ctx, http.MethodDelete, "/"+url.PathEscape(record.ID), nil, nil)
}

func (p *HTTPProvider) do(ctx context.Context, method, suffix string, body, target any) error {
	endpoint := strings.TrimSuffix(p.Endpoint, "/")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil {
		return errors.New("DNS provider endpoint must be an HTTPS URL without credentials")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+suffix, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	client := p.Client
	if client == nil {
		client = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("DNS provider redirects are forbidden")
			},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("DNS provider returned HTTP %d", resp.StatusCode)
	}
	if target != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(target)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}
