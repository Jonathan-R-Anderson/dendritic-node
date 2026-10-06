package authoritative

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Run with AXON_BIND_TEST=1 in the pinned BIND image; no public networking or chain writes.
func TestBINDIntegration(t *testing.T) {
	if os.Getenv("AXON_BIND_TEST") != "1" {
		t.Skip("set AXON_BIND_TEST=1 with named, named-checkzone and rndc installed")
	}
	dir := t.TempDir()
	port := freePort(t)
	control := freePort(t)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	z := testZone()
	z.File = filepath.Join(dir, "example.zone")
	snapshot := Snapshot{Registered: true}
	for _, text := range []string{
		`example.com. 300 IN A 192.0.2.1`, `example.com. 300 IN AAAA 2001:db8::1`,
		`example.com. 300 IN MX 10 mail.example.com.`, `mail.example.com. 300 IN A 192.0.2.3`,
		`www.example.com. 300 IN CNAME example.com.`, `*.wild.example.com. 300 IN A 192.0.2.4`,
		`_sip._tcp.example.com. 300 IN SRV 10 20 5060 mail.example.com.`,
		`example.com. 300 IN CAA 0 issue "letsencrypt.org"`,
		`child.example.com. 300 IN NS ns.child.example.com.`, `ns.child.example.com. 300 IN A 192.0.2.5`,
		`child.example.com. 300 IN DS 12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`,
	} {
		name, r, err := EncodeRR(text)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeRR(name, r)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Records = append(snapshot.Records, decoded)
	}
	long := `big.example.com. 300 IN TXT ` + strings.Repeat(`"`+strings.Repeat("x", 200)+`" `, 4)
	snapshot.Records = append(snapshot.Records, rr(t, long))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	publisher := Publisher{}
	changed, err := publisher.Publish(ctx, z, snapshot)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	secret := base64.StdEncoding.EncodeToString(secretBytes)
	keyFile := filepath.Join(dir, "control.key")
	os.WriteFile(keyFile, []byte(fmt.Sprintf(`key "control" { algorithm hmac-sha256; secret "%s"; };`, secret)), 0600)
	cfg := fmt.Sprintf(`
options { directory "%s"; pid-file "%s/named.pid"; session-keyfile "%s/session.key";
 listen-on port %d { 127.0.0.1; }; listen-on-v6 { none; };
 recursion no; dnssec-validation no; allow-query { any; }; allow-transfer { none; }; };
include "%s";
key "transfer" { algorithm hmac-sha256; secret "%s"; };
controls { inet 127.0.0.1 port %d allow { 127.0.0.1; } keys { "control"; }; };
zone "example.com" { type primary; file "%s";
 dnssec-policy default; inline-signing yes; key-directory "%s";
 allow-transfer { key "transfer"; }; allow-update { none; }; ixfr-from-differences yes; };
`, dir, dir, dir, port, keyFile, secret, control, z.File, dir)
	cfgFile := filepath.Join(dir, "named.conf")
	os.WriteFile(cfgFile, []byte(cfg), 0600)
	if err := command(ctx, []string{"named-checkconf"}, cfgFile); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "named.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("named", "-g", "-c", cfgFile, "-n", "1")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		logFile.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			t.Log(string(data))
		}
	})
	query := func(name string, typ uint16, network string, secure bool) (*dns.Msg, error) {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), typ)
		msg.RecursionDesired = false
		if secure {
			msg.SetEdns0(1232, true)
		}
		c := dns.Client{Net: network, Timeout: time.Second}
		reply, _, err := c.Exchange(msg, address)
		return reply, err
	}
	waitFor := func(name string, typ uint16, condition func(*dns.Msg) bool) *dns.Msg {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			reply, err := query(name, typ, "tcp", true)
			if err == nil && condition(reply) {
				return reply
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("DNS condition timed out: %s %d", name, typ)
		return nil
	}
	hasType := func(rrs []dns.RR, typ uint16) bool {
		for _, r := range rrs {
			if r.Header().Rrtype == typ {
				return true
			}
		}
		return false
	}
	signed := waitFor("example.com", dns.TypeA, func(m *dns.Msg) bool { return hasType(m.Answer, dns.TypeA) && hasType(m.Answer, dns.TypeRRSIG) })
	if !signed.Authoritative || signed.RecursionAvailable {
		t.Fatal("not authoritative-only")
	}
	for _, tc := range []struct {
		name string
		typ  uint16
	}{{"example.com", dns.TypeAAAA}, {"example.com", dns.TypeMX}, {"www.example.com", dns.TypeCNAME}, {"foo.wild.example.com", dns.TypeA}, {"_sip._tcp.example.com", dns.TypeSRV}, {"example.com", dns.TypeCAA}} {
		response, err := query(tc.name, tc.typ, "udp", false)
		if err != nil || response.Rcode != dns.RcodeSuccess || !hasType(response.Answer, tc.typ) {
			t.Fatalf("%+v: %v %v", tc, err, response)
		}
	}
	// Verify an actual DNSSEC signature, not merely the presence of RRSIG records.
	keys, err := query("example.com", dns.TypeDNSKEY, "tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	verified := false
	var rrset []dns.RR
	for _, r := range signed.Answer {
		if r.Header().Rrtype == dns.TypeA {
			rrset = append(rrset, r)
		}
	}
	for _, r := range signed.Answer {
		if sig, ok := r.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA {
			for _, k := range keys.Answer {
				if key, ok := k.(*dns.DNSKEY); ok && sig.Verify(key, rrset) == nil {
					verified = true
				}
			}
		}
	}
	if !verified {
		t.Fatal("DNSSEC verification failed")
	}
	negative, err := query("missing.example.com", dns.TypeA, "tcp", true)
	if err != nil || negative.Rcode != dns.RcodeNameError || !hasType(negative.Ns, dns.TypeSOA) || !hasType(negative.Ns, dns.TypeRRSIG) {
		t.Fatal("unsigned or incorrect NXDOMAIN", negative, err)
	}
	nodata, err := query("mail.example.com", dns.TypeAAAA, "udp", false)
	if err != nil || nodata.Rcode != dns.RcodeSuccess || len(nodata.Answer) != 0 || !hasType(nodata.Ns, dns.TypeSOA) {
		t.Fatal("incorrect NODATA", nodata, err)
	}
	referral, err := query("www.child.example.com", dns.TypeA, "udp", false)
	if err != nil || referral.Authoritative || !hasType(referral.Ns, dns.TypeNS) || !hasType(referral.Extra, dns.TypeA) {
		t.Fatal("incorrect referral/glue", referral, err)
	}
	truncated, err := query("big.example.com", dns.TypeTXT, "udp", false)
	if err != nil || !truncated.Truncated {
		t.Fatal("missing UDP truncation", truncated, err)
	}
	full, err := query("big.example.com", dns.TypeTXT, "tcp", false)
	if err != nil || full.Truncated || !hasType(full.Answer, dns.TypeTXT) {
		t.Fatal("TCP retry", full, err)
	}
	// AXFR requires a TSIG, even though ordinary queries are public.
	transfer := new(dns.Transfer)
	transfer.DialTimeout = time.Second
	transfer.ReadTimeout = time.Second
	unsigned := new(dns.Msg)
	unsigned.SetAxfr("example.com.")
	stream, err := transfer.In(unsigned, address)
	if err == nil {
		for env := range stream {
			if env.Error == nil && len(env.RR) > 0 {
				t.Fatal("unsigned AXFR permitted")
			}
		}
	}
	transfer = &dns.Transfer{TsigSecret: map[string]string{"transfer.": secret}, DialTimeout: time.Second, ReadTimeout: time.Second}
	request := new(dns.Msg)
	request.SetAxfr("example.com.")
	request.SetTsig("transfer.", dns.HmacSHA256, 300, time.Now().Unix())
	stream, err = transfer.In(request, address)
	if err != nil {
		t.Fatal(err)
	}
	transferred := false
	for env := range stream {
		if env.Error != nil {
			t.Fatal(env.Error)
		}
		if hasType(env.RR, dns.TypeA) {
			transferred = true
		}
	}
	if !transferred {
		t.Fatal("empty signed transfer")
	}
	// On-chain edits are reloaded and re-signed; unchanged snapshots do not increment serial.
	publisher.Reload = []string{"rndc", "-s", "127.0.0.1", "-p", fmt.Sprint(control), "-k", keyFile, "reload"}
	changed, err = publisher.Publish(ctx, z, snapshot)
	if err != nil || changed {
		t.Fatal("unchanged zone rewritten", changed, err)
	}
	snapshot.Records[0] = rr(t, "example.com. 300 IN A 192.0.2.99")
	changed, err = publisher.Publish(ctx, z, snapshot)
	if err != nil || !changed {
		t.Fatal("reload", changed, err)
	}
	waitFor("example.com", dns.TypeA, func(m *dns.Msg) bool {
		for _, r := range m.Answer {
			if a, ok := r.(*dns.A); ok && a.A.String() == "192.0.2.99" {
				return true
			}
		}
		return false
	})
	// Release publishes a tombstone zone, so previous registrations are not served forever.
	if _, err = publisher.Publish(ctx, z, Snapshot{}); err != nil {
		t.Fatal(err)
	}
	waitFor("mail.example.com", dns.TypeA, func(m *dns.Msg) bool { return m.Rcode == dns.RcodeNameError })
}
