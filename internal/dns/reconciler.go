package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/syndichan/maniwani/storage-client/internal/gateway"
)

type Record struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	TTL     int    `json:"ttl"`
	Managed bool   `json:"managed"`
}

type Provider interface {
	ListRecords(context.Context, string) ([]Record, error)
	CreateRecord(context.Context, Record) error
	UpdateRecord(context.Context, Record) error
	DeleteRecord(context.Context, Record) error
}

type Reconciler struct {
	Provider     Provider
	Hostname     string
	TTL          int
	MaxRecords   int
	MaxMutations int
	DryRun       bool
	Freeze       bool
}

type Plan struct {
	Create []Record
	Update []Record
	Delete []Record
}

func (r Reconciler) Desired(registrations []gateway.Registration, nowUnix int64, blocked map[string]bool) ([]Record, error) {
	if err := validateHostname(r.Hostname); err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var records []Record
	for _, registration := range registrations {
		if registration.RecordType != "verified_gateway" ||
			registration.HealthState != gateway.StateHealthy ||
			registration.ExpiresAt <= nowUnix || blocked[registration.NodeID] {
			continue
		}
		for _, address := range registration.Addresses {
			ip, err := netip.ParseAddr(address.Address)
			if err != nil || !gateway.PublicAddress(ip) || address.Port != 443 {
				continue
			}
			ip = ip.Unmap()
			recordType := "AAAA"
			if ip.Is4() {
				recordType = "A"
			}
			key := recordType + "\x00" + ip.String()
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			records = append(records, Record{
				Name: r.Hostname, Type: recordType, Value: ip.String(),
				TTL: r.TTL, Managed: true,
			})
		}
	}
	if len(records) > r.MaxRecords {
		return nil, fmt.Errorf("desired gateway records exceed safety limit %d", r.MaxRecords)
	}
	sortRecords(records)
	return records, nil
}

func (r Reconciler) Diff(desired, existing []Record) Plan {
	wanted := make(map[string]Record, len(desired))
	for _, record := range desired {
		wanted[key(record)] = record
	}
	current := map[string]Record{}
	for _, record := range existing {
		if record.Managed && strings.EqualFold(record.Name, r.Hostname) &&
			(record.Type == "A" || record.Type == "AAAA") {
			current[key(record)] = record
		}
	}
	var plan Plan
	for k, record := range wanted {
		if old, ok := current[k]; !ok {
			plan.Create = append(plan.Create, record)
		} else if old.TTL != record.TTL {
			record.ID = old.ID
			plan.Update = append(plan.Update, record)
		}
	}
	for k, record := range current {
		if _, ok := wanted[k]; !ok {
			plan.Delete = append(plan.Delete, record)
		}
	}
	sortRecords(plan.Create)
	sortRecords(plan.Update)
	sortRecords(plan.Delete)
	return plan
}

func (r Reconciler) Reconcile(ctx context.Context, desired []Record) (Plan, error) {
	if r.Provider == nil {
		return Plan{}, errors.New("DNS provider is not configured")
	}
	if r.Freeze {
		return Plan{}, errors.New("DNS emergency freeze is active")
	}
	existing, err := r.Provider.ListRecords(ctx, r.Hostname)
	if err != nil {
		return Plan{}, err
	}
	plan := r.Diff(desired, existing)
	total := len(plan.Create) + len(plan.Update) + len(plan.Delete)
	if total > r.MaxMutations {
		return plan, fmt.Errorf("DNS plan has %d mutations, exceeds safety limit %d", total, r.MaxMutations)
	}
	if r.DryRun {
		return plan, nil
	}
	for _, record := range plan.Create {
		if err := r.Provider.CreateRecord(ctx, record); err != nil {
			return plan, err
		}
	}
	for _, record := range plan.Update {
		if err := r.Provider.UpdateRecord(ctx, record); err != nil {
			return plan, err
		}
	}
	for _, record := range plan.Delete {
		if err := r.Provider.DeleteRecord(ctx, record); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

func validateHostname(value string) error {
	_, addressError := netip.ParseAddr(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@ \t\r\n") ||
		addressError == nil {
		return errors.New("invalid managed DNS hostname")
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") ||
			strings.HasSuffix(label, "-") {
			return errors.New("invalid managed DNS hostname")
		}
	}
	return nil
}

func key(record Record) string {
	return strings.ToLower(strings.TrimSuffix(record.Name, ".")) + "\x00" +
		record.Type + "\x00" + record.Value
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool { return key(records[i]) < key(records[j]) })
}

type MemoryProvider struct {
	Records []Record
}

func (p *MemoryProvider) ListRecords(_ context.Context, hostname string) ([]Record, error) {
	return append([]Record(nil), p.Records...), nil
}
func (p *MemoryProvider) CreateRecord(_ context.Context, record Record) error {
	record.ID = fmt.Sprintf("memory-%d", len(p.Records)+1)
	p.Records = append(p.Records, record)
	return nil
}
func (p *MemoryProvider) UpdateRecord(_ context.Context, record Record) error {
	for index := range p.Records {
		if p.Records[index].ID == record.ID {
			p.Records[index] = record
			return nil
		}
	}
	return errors.New("record not found")
}
func (p *MemoryProvider) DeleteRecord(_ context.Context, record Record) error {
	for index := range p.Records {
		if p.Records[index].ID == record.ID {
			p.Records = append(p.Records[:index], p.Records[index+1:]...)
			return nil
		}
	}
	return errors.New("record not found")
}
