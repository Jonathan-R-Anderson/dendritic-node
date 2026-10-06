package authoritative

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestAtomicPublisherAndSerial(t *testing.T) {
	z := testZone()
	z.File = filepath.Join(t.TempDir(), "zone")
	// Unit tests substitute only the external checker; real BIND validation has an integration test.
	checker := filepath.Join(t.TempDir(), "check")
	os.WriteFile(checker, []byte("#!/bin/sh\nexit 0\n"), 0700)
	p := Publisher{Check: []string{checker}}
	ctx := context.Background()
	s := Snapshot{}
	if changed, err := p.Publish(ctx, z, s); err != nil || !changed {
		t.Fatal(changed, err)
	}
	initial, _ := os.ReadFile(z.File)
	if changed, err := p.Publish(ctx, z, s); err != nil || changed {
		t.Fatal(changed, err)
	}
	s.Records = []dns.RR{rr(t, "www.example.com. 30 IN A 192.0.2.1")}
	if changed, err := p.Publish(ctx, z, s); err != nil || !changed {
		t.Fatal(changed, err)
	}
	updated, _ := os.ReadFile(z.File)
	records, err := parseZone(string(updated))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if soa, ok := r.(*dns.SOA); ok && soa.Serial != 2 {
			t.Fatal("serial", soa.Serial)
		}
	}
	os.WriteFile(checker, []byte("#!/bin/sh\nexit 1\n"), 0700)
	s.Records = nil
	if _, err = p.Publish(ctx, z, s); err == nil {
		t.Fatal("checker failure ignored")
	}
	still, _ := os.ReadFile(z.File)
	if string(still) != string(updated) {
		t.Fatal("invalid candidate published")
	}
	os.WriteFile(checker, []byte("#!/bin/sh\nexit 0\n"), 0700)
	p.Reload = []string{"/bin/false"}
	if _, err = p.Publish(ctx, z, s); err == nil {
		t.Fatal("reload failure ignored")
	}
	still, _ = os.ReadFile(z.File)
	if string(still) != string(updated) || string(initial) == string(updated) {
		t.Fatal("failed rollback")
	}
}
