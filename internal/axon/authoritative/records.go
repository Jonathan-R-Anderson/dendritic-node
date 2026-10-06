// Package authoritative publishes validated registry snapshots as BIND primary zones.
// BIND handles authoritative DNS protocols; this package never performs recursive lookups.
package authoritative

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/names"
)

// Record mirrors the contract's typed Entry. DNS is TYPE (uint16) + uncompressed RDATA.
type Record struct {
	ID   uint64
	Kind uint8
	TTL  uint32
	Data []byte
}

const DNSKind = 4

// OwnerName matches registry DNS owner syntax. Wildcards are only an entire first label.
func OwnerName(s string) (string, error) {
	for _, c := range []byte(s) {
		if c > 127 {
			return "", errors.New("ASCII names required")
		}
	}
	n := strings.TrimSuffix(strings.ToLower(s), ".")
	labels := strings.Split(n, ".")
	if len(labels) < 2 || len(n) > 253 {
		return "", errors.New("invalid DNS owner")
	}
	if _, err := names.ValidateName(strings.Join(labels[len(labels)-2:], ".")); err != nil {
		return "", err
	}
	for i, l := range labels[:len(labels)-2] {
		if l == "*" && i == 0 {
			continue
		}
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", errors.New("invalid DNS label")
			}
		}
	}
	if n == "key.axon" || strings.HasSuffix(n, ".key.axon") {
		return "", errors.New("reserved namespace")
	}
	return n + ".", nil
}

func allowedType(t uint16) bool { return t != 0 && t != 41 && !(t >= 249 && t <= 255) }

// EncodeRR validates a presentation-format RR and returns registry owner and payload.
// Output is suitable for setRecord(owner, id, 4, ttl, payload).
func EncodeRR(text string) (string, Record, error) {
	if strings.ContainsAny(text, "\r\n") {
		return "", Record{}, errors.New("one record per invocation")
	}
	rr, err := dns.NewRR(text)
	if err != nil {
		return "", Record{}, err
	}
	if rr == nil || rr.Header().Class != dns.ClassINET || !allowedType(rr.Header().Rrtype) {
		return "", Record{}, errors.New("IN data record required")
	}
	owner, err := OwnerName(rr.Header().Name)
	if err != nil {
		return "", Record{}, err
	}
	if rr.Header().Ttl > 604800 {
		return "", Record{}, errors.New("TTL exceeds contract limit")
	}
	typ := rr.Header().Rrtype
	ttl := rr.Header().Ttl
	rr.Header().Name = "."
	wire := make([]byte, 65535)
	end, err := dns.PackRR(rr, wire, 0, nil, false)
	if err != nil {
		return "", Record{}, err
	}
	if end < 11 || end-11 > 4096 {
		return "", Record{}, errors.New("RDATA exceeds registry limit")
	}
	data := make([]byte, 2+end-11)
	binary.BigEndian.PutUint16(data, typ)
	copy(data[2:], wire[11:end])
	return strings.TrimSuffix(owner, "."), Record{Kind: DNSKind, TTL: ttl, Data: data}, nil
}

func DecodeRR(owner string, r Record) (dns.RR, error) {
	n, err := OwnerName(owner)
	if err != nil {
		return nil, err
	}
	if r.TTL > 604800 {
		return nil, errors.New("invalid TTL")
	}
	hdr := dns.RR_Header{Name: n, Class: dns.ClassINET, Ttl: r.TTL}
	switch r.Kind {
	case 0: // Overlay destinations are not IP records and are never emitted as DNS A/AAAA.
		if len(r.Data) != 32 || bytes.Equal(r.Data, make([]byte, 32)) {
			return nil, errors.New("invalid AXON key")
		}
		return nil, nil
	case 1:
		if len(r.Data) != 4 {
			return nil, errors.New("invalid IPv4")
		}
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: net.IP(r.Data)}, nil
	case 2:
		if len(r.Data) != 16 {
			return nil, errors.New("invalid IPv6")
		}
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: net.IP(r.Data)}, nil
	case 3:
		if len(r.Data) < 3 || len(r.Data) > 255 {
			return nil, errors.New("invalid MX")
		}
		host := string(r.Data[2:])
		if strings.ToLower(host) != host || strings.HasSuffix(host, ".") {
			return nil, errors.New("noncanonical MX")
		}
		// Single-label exchange hostnames are permitted by the contract.
		if _, err := names.ValidateName("x." + host); err != nil {
			return nil, err
		}
		hdr.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: hdr, Preference: binary.BigEndian.Uint16(r.Data), Mx: host + "."}, nil
	case DNSKind:
		if len(r.Data) < 2 || len(r.Data) > 4098 {
			return nil, errors.New("invalid DNS payload size")
		}
		typ := binary.BigEndian.Uint16(r.Data)
		if !allowedType(typ) {
			return nil, errors.New("DNS meta type")
		}
		wire := make([]byte, 11+len(r.Data)-2)
		binary.BigEndian.PutUint16(wire[1:3], typ)
		binary.BigEndian.PutUint16(wire[3:5], dns.ClassINET)
		binary.BigEndian.PutUint32(wire[5:9], r.TTL)
		binary.BigEndian.PutUint16(wire[9:11], uint16(len(r.Data)-2))
		copy(wire[11:], r.Data[2:])
		rr, end, err := dns.UnpackRR(wire, 0)
		if err != nil {
			return nil, err
		}
		if end != len(wire) {
			return nil, errors.New("trailing RDATA")
		}
		canonical := make([]byte, 65535)
		end, err = dns.PackRR(rr, canonical, 0, nil, false)
		if err != nil || !bytes.Equal(canonical[:end], wire) {
			return nil, errors.New("noncanonical or compressed RDATA")
		}
		rr.Header().Name = n
		return rr, nil
	default:
		return nil, errors.New("unknown registry record kind")
	}
}

func PayloadHex(r Record) string { return "0x" + hex.EncodeToString(r.Data) }

// ValidateZone catches cross-record errors before named-checkzone's independent validation.
// The authoritative signer owns DNSSEC signatures/keys; on-chain DS is allowed at cuts.
func ValidateZone(origin string, rrs []dns.RR) error {
	origin = dns.Fqdn(origin)
	soa := 0
	ns := 0
	byName := map[string][]dns.RR{}
	ttls := map[string]uint32{}
	seen := map[string]bool{}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Class != dns.ClassINET || !dns.IsSubDomain(origin, h.Name) {
			return errors.New("out-of-zone or non-IN record")
		}
		if seen[rr.String()] {
			return fmt.Errorf("duplicate DNS record: %s", rr)
		}
		seen[rr.String()] = true
		key := strings.ToLower(h.Name) + fmt.Sprint("/", h.Rrtype)
		if ttl, ok := ttls[key]; ok && ttl != h.Ttl {
			return errors.New("RRset TTLs must match")
		}
		ttls[key] = h.Ttl
		byName[strings.ToLower(h.Name)] = append(byName[strings.ToLower(h.Name)], rr)
		if h.Rrtype == dns.TypeSOA {
			if !strings.EqualFold(h.Name, origin) {
				return errors.New("SOA below zone apex")
			}
			soa++
		}
		if h.Rrtype == dns.TypeNS && strings.EqualFold(h.Name, origin) {
			ns++
		}
		switch h.Rrtype {
		case dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
			return errors.New("BIND manages DNSSEC signing records; publish DS in the parent")
		}
	}
	if soa != 1 || ns == 0 {
		return errors.New("zone requires exactly one apex SOA and at least one apex NS")
	}
	for _, set := range byName {
		cn := 0
		for _, rr := range set {
			if rr.Header().Rrtype == dns.TypeCNAME {
				cn++
			}
		}
		if cn > 0 && len(set) != 1 {
			return errors.New("CNAME cannot coexist with other records")
		}
	}
	for _, rr := range rrs {
		var target string
		switch x := rr.(type) {
		case *dns.MX:
			target = x.Mx
		case *dns.NS:
			target = x.Ns
		}
		for _, dest := range byName[strings.ToLower(target)] {
			if dest.Header().Rrtype == dns.TypeCNAME {
				return errors.New("MX/NS target cannot be a CNAME")
			}
		}
	}
	return nil
}

func zoneText(rrs []dns.RR, serial uint32) string {
	lines := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		copyRR := dns.Copy(rr)
		if soa, ok := copyRR.(*dns.SOA); ok {
			soa.Serial = serial
		}
		lines = append(lines, copyRR.String())
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}
