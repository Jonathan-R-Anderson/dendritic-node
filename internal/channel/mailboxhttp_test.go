package channel

// The mailbox over real HTTP — roadmap P15.
//
// What matters here is that the PUBLIC surface stays public and the OPERATOR
// surface stays absent from it. A tipper has no token; the moment these routes
// demanded one, tipping through a volunteer would be impossible. The moment
// they served the operator API, a web page could spend the node's money.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func mailboxServer(t *testing.T, now int64) (*Mailbox, *httptest.Server) {
	t.Helper()
	m := newTestMailbox(now)
	srv := httptest.NewServer(MailboxHandler(m))
	t.Cleanup(srv.Close)
	return m, srv
}

func TestTheMailboxSurfaceNeedsNoOperatorToken(t *testing.T) {
	// THE POINT OF A PUBLIC SURFACE. A contributor is a stranger.
	m, srv := mailboxServer(t, 1000)
	alice := newSigner(t)
	a := authFor(t, alice, testNode, 2000)

	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/authorize",
		map[string]any{
			"recipient": a.Recipient.Hex(), "node_id": a.NodeID,
			"endpoint": a.Endpoint, "expires": a.Expires, "sig": hexOf(a.Sig),
		}, "")
	if code != http.StatusOK {
		t.Fatalf("authorize with no token: got %d, want 200", code)
	}
	if !m.Serves(alice.address()) {
		t.Fatal("the node did not record the authorization")
	}

	code, _ = do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/deliver",
		map[string]any{"recipient": alice.address().Hex(),
			"envelope": Envelope{Type: MsgStatePropose, Channel: "ab"}}, "")
	if code != http.StatusAccepted {
		t.Fatalf("deliver with no token: got %d, want 202", code)
	}
}

func TestTheMailboxSurfaceDoesNotServeTheOperatorAPI(t *testing.T) {
	// If these ever shared a mux, a web page would reach routes that can move
	// the node's money.
	_, srv := mailboxServer(t, 1000)
	for _, path := range []string{"/v1/channels", "/v1/pool", "/v1/pool/checkpoint"} {
		code, _ := do(t, srv.Client(), http.MethodGet, srv.URL+path, nil, testToken)
		if code != http.StatusNotFound {
			t.Fatalf("%s is reachable from the public mailbox surface (%d)", path, code)
		}
	}
}

func TestDeliveringToAnUnservedRecipientIsRefused(t *testing.T) {
	_, srv := mailboxServer(t, 1000)
	stranger := newSigner(t)
	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/deliver",
		map[string]any{"recipient": stranger.address().Hex(),
			"envelope": Envelope{Type: MsgStatePropose}}, "")
	if code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", code)
	}
}

func TestCollectingOverHTTPNeedsTheRecipientsOwnSignature(t *testing.T) {
	m, srv := mailboxServer(t, 1000)
	alice, mallory := newSigner(t), newSigner(t)
	if err := m.Serve(authFor(t, alice, testNode, 2000)); err != nil {
		t.Fatal(err)
	}
	if err := m.Deliver(alice.address(), Envelope{Type: MsgStatePropose}); err != nil {
		t.Fatal(err)
	}

	ch := MailboxChallenge(testNode, alice.address(), "tok")

	// Mallory signs the same challenge and asks for Alice's mail.
	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/collect",
		map[string]any{"recipient": alice.address().Hex(), "token": "tok",
			"sig": hexOf(mallory.sign(PersonalDigest(ch)))}, "")
	if code != http.StatusForbidden {
		t.Fatalf("mallory collected alice's mail: %d", code)
	}
	if m.Pending(alice.address()) != 1 {
		t.Fatal("a refused collection consumed the queue")
	}

	code, body := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/collect",
		map[string]any{"recipient": alice.address().Hex(), "token": "tok",
			"sig": hexOf(alice.sign(PersonalDigest(ch)))}, "")
	if code != http.StatusOK {
		t.Fatalf("alice could not collect: %d", code)
	}
	frames, _ := body["frames"].([]any)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
}

func TestAuthorizingForAnotherNodeIsRefusedOverHTTP(t *testing.T) {
	m, srv := mailboxServer(t, 1000)
	alice := newSigner(t)
	a := authFor(t, alice, "someone-else", 2000)
	code, _ := do(t, srv.Client(), http.MethodPost, srv.URL+"/mailbox/v1/authorize",
		map[string]any{
			"recipient": a.Recipient.Hex(), "node_id": a.NodeID,
			"endpoint": a.Endpoint, "expires": a.Expires, "sig": hexOf(a.Sig),
		}, "")
	if code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", code)
	}
	if m.Serves(alice.address()) {
		t.Fatal("the node adopted a recipient authorized elsewhere")
	}
}
