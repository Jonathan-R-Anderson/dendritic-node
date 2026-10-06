package authoritative

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestRecordRoundTrips(t *testing.T) {
	for _, text := range []string{
		`example.com. 300 IN A 192.0.2.1`, `example.com. 300 IN AAAA 2001:db8::1`,
		`example.com. 300 IN MX 10 mail.example.com.`, `example.com. 300 IN TXT "hello" "second"`,
		`www.example.com. 300 IN CNAME example.com.`, `example.com. 300 IN NS ns.example.com.`,
		`example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 300 60 86400 60`,
		`_sip._tcp.example.com. 300 IN SRV 10 20 5060 sip.example.com.`,
		`1.2.0.192.in-addr.arpa. 300 IN PTR host.example.com.`,
		`example.com. 300 IN CAA 0 issue "letsencrypt.org"`, `*.example.com. 300 IN A 192.0.2.2`,
		`example.com. 300 IN HTTPS 1 . alpn="h2"`, `alias.example.com. 300 IN DNAME example.net.`,
		`example.com. 300 IN TYPE65280 \# 3 010203`,
	} {
		t.Run(text, func(t *testing.T) {
			owner, r, err := EncodeRR(text)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeRR(owner, r)
			if err != nil {
				t.Fatal(err)
			}
			want, err := dns.NewRR(text)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != want.String() {
				t.Fatalf("%s != %s", got, want)
			}
		})
	}
}
func TestInvalidRecordsAndNames(t *testing.T) {
	for _, name := range []string{"*.com", "x*.example.com", "a.*.example.com", "a..example.com", "K.example.com", "a.key.axon", "example.com.."} {
		if _, err := OwnerName(name); err == nil {
			t.Fatal(name)
		}
	}
	for _, text := range []string{"example.com. 300 IN TXT \"a\"\nother.com. IN A 1.2.3.4", `example.com. 604801 IN TXT "x"`, `example.com. IN A junk`} {
		if _, _, err := EncodeRR(text); err == nil {
			t.Fatal(text)
		}
	}
	for _, payload := range []string{"00ff", "00010102", "0005c000", "002901"} {
		b, _ := hex.DecodeString(payload)
		if _, err := DecodeRR("example.com", Record{Kind: 4, TTL: 30, Data: b}); err == nil {
			t.Fatal(payload)
		}
	}
}
func testZone() ZoneConfig {
	return ZoneConfig{Origin: "example.com", File: "/tmp/example.zone", Nameservers: []string{"ns.example.net."}, Mailbox: "hostmaster.example.com."}
}
func rr(t *testing.T, text string) dns.RR {
	t.Helper()
	r, e := dns.NewRR(text)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestZoneRules(t *testing.T) {
	for _, records := range [][]dns.RR{
		{rr(t, "www.example.com. 30 IN CNAME example.com."), rr(t, "www.example.com. 30 IN A 192.0.2.1")},
		{rr(t, "www.example.com. 30 IN A 192.0.2.1"), rr(t, "www.example.com. 60 IN A 192.0.2.2")},
		{rr(t, "other.com. 30 IN A 192.0.2.1")},
	} {
		if _, err := testZone().Records(Snapshot{Registered: true, Records: records}); err == nil {
			t.Fatal("invalid zone accepted")
		}
	}
	records := []dns.RR{rr(t, "sub.example.com. 300 IN NS ns.sub.example.com."), rr(t, "ns.sub.example.com. 300 IN A 192.0.2.3"), rr(t, "sub.example.com. 300 IN SOA ns.sub.example.com. hostmaster.sub.example.com. 1 300 60 3600 60"), rr(t, "private.sub.example.com. 300 IN TXT \"child authoritative data\"")}
	out, err := testZone().Records(Snapshot{Registered: true, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("expected delegation, glue, apex SOA/NS; %v", out)
	}
	for _, r := range out {
		if strings.Contains(r.String(), "private.") {
			t.Fatal("data leaked below cut")
		}
	}
}
