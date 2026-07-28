package frontend

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func testBackend(t *testing.T, expectProxy bool, observed chan<- []byte) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var header []byte
		if expectProxy {
			header = make([]byte, 28)
			if _, err := io.ReadFull(connection, header); err != nil {
				observed <- nil
				return
			}
		}
		hostname, raw, parseErr := PeekSNI(connection)
		if parseErr != nil {
			observed <- nil
			return
		}
		record := append(header, raw...)
		record = append(record, []byte(hostname)...)
		observed <- record
		_, _ = connection.Write([]byte("OK"))
	}()
	return listener
}

func TestServerRoutesLocalAndOriginTLSWithoutConsumingHello(t *testing.T) {
	originObserved := make(chan []byte, 1)
	localObserved := make(chan []byte, 1)
	origin := testBackend(t, true, originObserved)
	defer origin.Close()
	local := testBackend(t, false, localObserved)
	defer local.Close()

	server, err := New(Config{
		OriginAddress: origin.Addr().String(), LocalAddress: local.Addr().String(),
		LocalHostname: "gw-test.syndichan.org", SNIAllowlist: []string{"syndichan.org"},
		MaxConnections: 8, MaxBytesPerSecond: 1 << 20,
		HandshakeTimeout: time.Second, DialTimeout: time.Second, IdleTimeout: time.Second,
		ProxyProtocol: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(edge) }()
	defer server.Shutdown(context.Background())

	request := func(hostname string) {
		connection, dialErr := net.DialTimeout("tcp", edge.Addr().String(), time.Second)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		defer connection.Close()
		hello := realClientHello(t, hostname)
		if _, err := connection.Write(hello); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 2)
		if _, err := io.ReadFull(connection, response); err != nil {
			t.Fatal(err)
		}
		if string(response) != "OK" {
			t.Fatalf("response = %q", response)
		}
	}

	request("syndichan.org")
	originRecord := <-originObserved
	if len(originRecord) < 28 || !bytes.Equal(originRecord[:12], proxyV2Signature) {
		t.Fatal("origin did not receive a PROXY v2 header")
	}
	if !bytes.Contains(originRecord[28:], []byte("syndichan.org")) {
		t.Fatal("origin did not receive the replayed ClientHello")
	}

	request("gw-test.syndichan.org")
	localRecord := <-localObserved
	if bytes.HasPrefix(localRecord, proxyV2Signature) {
		t.Fatal("local identity endpoint unexpectedly received a PROXY header")
	}
	if !bytes.Contains(localRecord, []byte("gw-test.syndichan.org")) {
		t.Fatal("local identity endpoint did not receive the replayed ClientHello")
	}
}

func TestServerRefusesUnlistedSNI(t *testing.T) {
	originObserved := make(chan []byte, 1)
	origin := testBackend(t, true, originObserved)
	defer origin.Close()
	localObserved := make(chan []byte, 1)
	local := testBackend(t, false, localObserved)
	defer local.Close()
	server, err := New(Config{
		OriginAddress: origin.Addr().String(), LocalAddress: local.Addr().String(),
		LocalHostname: "gw-test.syndichan.org", SNIAllowlist: []string{"syndichan.org"},
		MaxConnections: 1, MaxBytesPerSecond: 1 << 20,
		HandshakeTimeout: time.Second, DialTimeout: time.Second, IdleTimeout: time.Second,
		ProxyProtocol: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(edge) }()
	defer server.Shutdown(context.Background())

	connection, err := net.DialTimeout("tcp", edge.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = connection.Write(realClientHello(t, "attacker.example"))
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if count, _ := connection.Read(buffer); count != 0 {
		t.Fatal("unlisted SNI received a response")
	}
	connection.Close()
	select {
	case <-originObserved:
		t.Fatal("unlisted SNI reached the origin")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestPacedReaderEnforcesBandwidthLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 64)
	started := time.Now()
	read, err := io.ReadAll(newPacedReader(bytes.NewReader(payload), 128))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, payload) {
		t.Fatal("paced reader changed the payload")
	}
	if elapsed := time.Since(started); elapsed < 400*time.Millisecond {
		t.Fatalf("64 bytes at 128 bytes/second completed too quickly: %s", elapsed)
	}
}

func TestShutdownForcesConnectionsClosedAfterDrainDeadline(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := origin.Accept()
		if connection != nil {
			accepted <- connection
		}
	}()
	local, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	server, err := New(Config{
		OriginAddress: origin.Addr().String(), LocalAddress: local.Addr().String(),
		LocalHostname: "gw-test.syndichan.org", SNIAllowlist: []string{"syndichan.org"},
		MaxConnections: 1, MaxBytesPerSecond: 1 << 20,
		HandshakeTimeout: time.Second, DialTimeout: time.Second, IdleTimeout: time.Minute,
		ProxyProtocol: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(edge) }()
	client, err := net.DialTimeout("tcp", edge.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write(realClientHello(t, "syndichan.org")); err != nil {
		t.Fatal(err)
	}
	upstream := <-accepted
	defer upstream.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := server.Shutdown(ctx); err == nil {
		t.Fatal("shutdown reported a clean drain while a connection was held open")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if count, _ := client.Read(make([]byte, 1)); count != 0 {
		t.Fatal("client connection remained usable after forced shutdown")
	}
}
