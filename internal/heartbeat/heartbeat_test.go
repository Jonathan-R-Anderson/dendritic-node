package heartbeat

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type testSigner struct {
	key crypto.PrivKey
	id  peer.ID
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{key: key, id: id}
}

func (s *testSigner) ID() string                    { return s.id.String() }
func (s *testSigner) Sign(m []byte) ([]byte, error) { return s.key.Sign(m) }

type captured struct {
	body      []byte
	userAgent string
	nodeID    string
	signature string
}

func capture(t *testing.T) (*httptest.Server, chan captured) {
	t.Helper()
	seen := make(chan captured, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		seen <- captured{
			body: body, userAgent: r.Header.Get("User-Agent"),
			nodeID:    r.Header.Get("X-Syndichan-Node"),
			signature: r.Header.Get("X-Syndichan-Signature"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server, seen
}

// A dedicated gateway reports zero capacity. That is how the frontend tells it
// apart from a storage node, so it must survive the round trip intact.
func TestGatewayHeartbeatReportsZeroCapacity(t *testing.T) {
	server, seen := capture(t)
	signer := newTestSigner(t)
	client := &Client{
		Signer: signer, Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{CapacityBytes: 0, GatewayEnabled: true, GatewayVerified: false}
		},
	}
	client.Send(context.Background())

	item := <-seen
	if item.userAgent != UserAgent {
		t.Fatalf("User-Agent is %q, want %q", item.userAgent, UserAgent)
	}
	if item.nodeID != signer.ID() {
		t.Fatalf("node header is %q, want %q", item.nodeID, signer.ID())
	}
	var payload map[string]any
	if err := json.Unmarshal(item.body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["capacity_bytes"] != float64(0) {
		t.Fatalf("capacity_bytes is %v, want 0", payload["capacity_bytes"])
	}
	if payload["gateway_enabled"] != true {
		t.Fatal("gateway_enabled was not reported")
	}
	if payload["gateway_verified"] != false {
		t.Fatal("an unverified gateway claimed verification")
	}
	if _, present := payload["gateway_registration"]; present {
		t.Fatal("a registration was attached without one being held")
	}
	// The signature must cover the exact bytes the server received.
	signature, err := base64.RawStdEncoding.DecodeString(item.signature)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := signer.key.GetPublic().Verify(item.body, signature)
	if err != nil || !ok {
		t.Fatalf("heartbeat signature does not verify the transmitted body: %v", err)
	}
}

func TestStorageHeartbeatReportsItsCapacity(t *testing.T) {
	server, seen := capture(t)
	client := &Client{
		Signer: newTestSigner(t), Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{CapacityBytes: 20 << 30}
		},
	}
	client.Send(context.Background())

	var payload map[string]any
	if err := json.Unmarshal((<-seen).body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["capacity_bytes"] != float64(20<<30) {
		t.Fatalf("capacity_bytes is %v, want %d", payload["capacity_bytes"], 20<<30)
	}
	if payload["gateway_enabled"] != false {
		t.Fatal("a storage node reported a gateway role it does not have")
	}
}

// Every send takes a fresh snapshot, so a gateway that becomes verified is
// reflected in the next beacon rather than at the next restart.
func TestSnapshotIsSampledPerSend(t *testing.T) {
	server, seen := capture(t)
	verified := false
	client := &Client{
		Signer: newTestSigner(t), Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{GatewayEnabled: true, GatewayVerified: verified}
		},
	}
	client.Send(context.Background())
	verified = true
	client.Send(context.Background())

	for index, want := range []bool{false, true} {
		var payload map[string]any
		if err := json.Unmarshal((<-seen).body, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["gateway_verified"] != want {
			t.Fatalf("send %d reported gateway_verified=%v, want %v",
				index, payload["gateway_verified"], want)
		}
	}
}

// A node with no identity must not post an unsigned beacon.
func TestSendWithoutSignerIsANoOp(t *testing.T) {
	server, seen := capture(t)
	client := &Client{Endpoint: server.URL, HTTP: server.Client()}
	client.Send(context.Background())
	select {
	case <-seen:
		t.Fatal("a heartbeat was sent without a signing identity")
	default:
	}
}

// The heartbeat must never be routed through a proxy: its whole purpose is to
// originate from the node's real address.
func TestDirectClientHasNoProxy(t *testing.T) {
	transport, ok := DirectHTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatal("heartbeat transport is not an *http.Transport")
	}
	if transport.Proxy != nil {
		t.Fatal("heartbeat transport would honour a proxy")
	}
}
