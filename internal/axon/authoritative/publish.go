package authoritative

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
)

type ZoneConfig struct {
	Origin      string   `json:"origin"`
	File        string   `json:"file"`
	Nameservers []string `json:"nameservers"`
	Mailbox     string   `json:"mailbox"`
}

// CutData keeps delegations and only necessary in-bailiwick glue below each cut.
// Child SOA and other authoritative data belong to a separately configured child zone.
func CutData(origin string, rrs []dns.RR) []dns.RR {
	origin = dns.Fqdn(origin)
	cuts := map[string]map[string]bool{}
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok && !strings.EqualFold(ns.Hdr.Name, origin) {
			n := strings.ToLower(ns.Hdr.Name)
			if cuts[n] == nil {
				cuts[n] = map[string]bool{}
			}
			cuts[n][strings.ToLower(ns.Ns)] = true
		}
	}
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		h := rr.Header()
		cut := ""
		for n := range cuts {
			if dns.IsSubDomain(n, h.Name) && (cut == "" || len(n) < len(cut)) {
				cut = n
			}
		}
		if cut == "" {
			out = append(out, rr)
			continue
		}
		if strings.EqualFold(h.Name, cut) && (h.Rrtype == dns.TypeNS || h.Rrtype == dns.TypeDS) {
			out = append(out, rr)
			continue
		}
		if (h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA) && cuts[cut][strings.ToLower(h.Name)] {
			out = append(out, rr)
		}
	}
	return out
}
func (z ZoneConfig) Validate() error {
	n, err := OwnerName(z.Origin)
	if err != nil {
		return err
	}
	if n != z.Origin+"." || strings.ContainsAny(z.Origin, "*_") {
		return errors.New("origin must be a canonical hostname without final dot")
	}
	if !filepath.IsAbs(z.File) {
		return errors.New("zone file must be an absolute path")
	}
	if len(z.Nameservers) == 0 {
		return errors.New("bootstrap nameservers required")
	}
	for _, n := range append(append([]string{}, z.Nameservers...), z.Mailbox) {
		if n == "" || !strings.HasSuffix(n, ".") {
			return errors.New("nameservers/mailbox must be absolute DNS names")
		}
		if _, ok := dns.IsDomainName(n); !ok || strings.ContainsAny(n, "\";\r\n\\ ") {
			return errors.New("invalid nameserver/mailbox")
		}
	}
	return nil
}
func (z ZoneConfig) Records(s Snapshot) ([]dns.RR, error) {
	if err := z.Validate(); err != nil {
		return nil, err
	}
	rrs := CutData(z.Origin, s.Records)
	soa, ns := false, false
	for _, rr := range rrs {
		if strings.EqualFold(rr.Header().Name, z.Origin+".") {
			soa = soa || rr.Header().Rrtype == dns.TypeSOA
			ns = ns || rr.Header().Rrtype == dns.TypeNS
		}
	}
	// Bootstrap authority metadata is local server configuration, never a substitute for registry user data.
	if !soa {
		rrs = append(rrs, &dns.SOA{Hdr: dns.RR_Header{Name: z.Origin + ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: z.Nameservers[0], Mbox: z.Mailbox, Refresh: 300, Retry: 60, Expire: 86400, Minttl: 60})
	}
	if !ns {
		for _, server := range z.Nameservers {
			rrs = append(rrs, &dns.NS{Hdr: dns.RR_Header{Name: z.Origin + ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: server})
		}
	}
	if err := ValidateZone(z.Origin, rrs); err != nil {
		return nil, err
	}
	return rrs, nil
}

// Publisher's commands are executable argument arrays, never shell fragments.
// Check defaults to named-checkzone; Reload defaults empty for initial provisioning.
type Publisher struct {
	Check  []string
	Reload []string
}

func command(ctx context.Context, argv []string, extra ...string) error {
	if len(argv) == 0 {
		return errors.New("empty command")
	}
	args := append(append([]string{}, argv[1:]...), extra...)
	out, err := exec.CommandContext(ctx, argv[0], args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", argv[0], err, out)
	}
	return nil
}
func parseZone(text string) ([]dns.RR, error) {
	parser := dns.NewZoneParser(strings.NewReader(text), ".", "")
	var rrs []dns.RR
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		rrs = append(rrs, rr)
	}
	if parser.Err() != nil {
		return nil, parser.Err()
	}
	return rrs, nil
}
func atomicFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".axon-zone-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func (p Publisher) Publish(ctx context.Context, z ZoneConfig, s Snapshot) (bool, error) {
	rrs, err := z.Records(s)
	if err != nil {
		return false, err
	}
	lock, err := os.OpenFile(z.File+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return false, fmt.Errorf("another publisher owns %s: %w", z.File, err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	old, err := os.ReadFile(z.File)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	serial := uint32(1)
	if exists {
		previous, err := parseZone(string(old))
		if err != nil {
			return false, fmt.Errorf("existing managed zone: %w", err)
		}
		if err = ValidateZone(z.Origin, previous); err != nil {
			return false, err
		}
		if zoneText(previous, 0) == zoneText(rrs, 0) {
			return false, nil
		}
		for _, rr := range previous {
			if soa, ok := rr.(*dns.SOA); ok {
				serial = soa.Serial + 1
			}
		}
	}
	text := zoneText(rrs, serial)
	f, err := os.CreateTemp(filepath.Dir(z.File), ".axon-check-*")
	if err != nil {
		return false, err
	}
	candidate := f.Name()
	defer os.Remove(candidate)
	if _, err = f.WriteString(text); err != nil {
		f.Close()
		return false, err
	}
	if err = f.Close(); err != nil {
		return false, err
	}
	check := p.Check
	if len(check) == 0 {
		check = []string{"named-checkzone"}
	}
	if err = command(ctx, check, z.Origin, candidate); err != nil {
		return false, err
	}
	if err = atomicFile(z.File, []byte(text)); err != nil {
		return false, err
	}
	if len(p.Reload) > 0 {
		if err = command(ctx, p.Reload, z.Origin); err != nil {
			var rollback error
			if exists {
				rollback = atomicFile(z.File, old)
			} else {
				rollback = os.Remove(z.File)
			}
			if rollback != nil {
				return false, fmt.Errorf("reload failed: %v; rollback failed: %w", err, rollback)
			}
			if exists {
				if restoreErr := command(ctx, p.Reload, z.Origin); restoreErr != nil {
					return false, fmt.Errorf("reload failed: %v; file restored but server reload failed: %w", err, restoreErr)
				}
			}
			return false, err
		}
	}
	return true, nil
}
