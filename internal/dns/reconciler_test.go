package dns

import (
	"context"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/gateway"
)

func TestDesiredRecordsAndDiffPreserveUnmanaged(t *testing.T) {
	now := time.Now().Unix()
	reconciler := Reconciler{
		Hostname: "gateway.example.com", TTL: 60,
		MaxRecords: 10, MaxMutations: 10, DryRun: true,
	}
	registrations := []gateway.Registration{{
		RecordType: "verified_gateway", NodeID: "node",
		HealthState: gateway.StateHealthy, ExpiresAt: now + 300,
		Addresses: []gateway.Address{
			{Family: "ipv4", Address: "8.8.8.8", Port: 443},
			{Family: "ipv6", Address: "2606:4700:4700::1111", Port: 443},
			{Family: "ipv4", Address: "127.0.0.1", Port: 443},
		},
	}}
	desired, err := reconciler.Desired(registrations, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(desired) != 2 || desired[0].Type != "A" || desired[1].Type != "AAAA" {
		t.Fatalf("unexpected desired records: %#v", desired)
	}
	existing := []Record{
		{ID: "old", Name: reconciler.Hostname, Type: "A", Value: "1.1.1.1", TTL: 60, Managed: true},
		{ID: "mx", Name: reconciler.Hostname, Type: "MX", Value: "mail.example.com", TTL: 60, Managed: false},
	}
	plan := reconciler.Diff(desired, existing)
	if len(plan.Create) != 2 || len(plan.Delete) != 1 || plan.Delete[0].ID != "old" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	provider := &MemoryProvider{}
	reconciler := Reconciler{
		Provider: provider, Hostname: "gateway.example.com", TTL: 60,
		MaxRecords: 10, MaxMutations: 10,
	}
	desired := []Record{{Name: reconciler.Hostname, Type: "A", Value: "8.8.8.8", TTL: 60, Managed: true}}
	if _, err := reconciler.Reconcile(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	plan, err := reconciler.Reconcile(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Create)+len(plan.Update)+len(plan.Delete) != 0 {
		t.Fatalf("second reconcile was not idempotent: %#v", plan)
	}
}
