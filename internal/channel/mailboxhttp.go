package channel

// The mailbox's public HTTP surface — roadmap P15.
//
// SAME AUDIENCE AS /scpp/v1, SAME RULE. Strangers reach these routes: a
// contributor dropping a frame for somebody it cannot reach directly, and a
// recipient collecting their own mail from their own browser. Neither has an
// operator token and neither must ever be given one.
//
// So authorization here is the same shape webpeer.go uses — a SIGNATURE inside
// the request:
//
//	POST /mailbox/v1/authorize   the recipient's signed appointment of this node
//	POST /mailbox/v1/deliver     anyone may drop a frame for a served recipient
//	POST /mailbox/v1/collect     the recipient proves who they are and takes it
//
// The operator API in api.go is a different surface with a different gate, and
// nothing here may be mounted on it.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type mailboxAuthorizeRequest struct {
	Recipient string `json:"recipient"`
	NodeID    string `json:"node_id"`
	Endpoint  string `json:"endpoint"`
	Expires   int64  `json:"expires"`
	Sig       string `json:"sig"`
}

type mailboxDeliverRequest struct {
	Recipient string   `json:"recipient"`
	Envelope  Envelope `json:"envelope"`
}

type mailboxCollectRequest struct {
	Recipient string `json:"recipient"`
	Token     string `json:"token"`
	Sig       string `json:"sig"`
}

// MailboxHandler serves the public mailbox routes.
func MailboxHandler(m *Mailbox) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mailbox/v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		var req mailboxAuthorizeRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		sig, err := ParseAuthorizationSig(req.Sig)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		auth := MailboxAuthorization{
			Recipient: recipient, NodeID: req.NodeID, Endpoint: req.Endpoint,
			Expires: req.Expires, Sig: sig,
		}
		if err := m.Serve(auth); err != nil {
			// 403 for every refusal. A caller learns that it was refused and
			// not which recipients this node already serves.
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"node_id": m.NodeID, "serving": true})
	})

	mux.HandleFunc("/mailbox/v1/deliver", func(w http.ResponseWriter, r *http.Request) {
		var req mailboxDeliverRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		// The frame is NOT inspected. A mailbox that parsed payments would be a
		// mailbox that could get them wrong.
		if err := m.Deliver(recipient, req.Envelope); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		// "Queued" is deliberately not "delivered" and certainly not "paid".
		// Nothing has happened to any channel: a proposal is waiting for a
		// recipient who has not seen it yet.
		writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
	})

	mux.HandleFunc("/mailbox/v1/collect", func(w http.ResponseWriter, r *http.Request) {
		var req mailboxCollectRequest
		if !readJSON(w, r, &req) {
			return
		}
		recipient, err := ParseAddress(req.Recipient)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad recipient"})
			return
		}
		sig, err := ParseAuthorizationSig(req.Sig)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		frames, err := m.Collect(recipient, MailboxChallenge(m.NodeID, recipient, req.Token), sig)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if frames == nil {
			frames = []Envelope{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"frames": frames})
	})

	return mux
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(into); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return false
	}
	return true
}

// MailboxCollectToken is what a recipient signs alongside their address.
//
// Supplied by the caller and bound into the challenge so a signature made for
// one collection cannot be replayed forever. A node that wanted stronger replay
// protection would issue the token itself; this is the minimum that stops a
// captured signature being reusable against another node, because the node id
// is in the challenge too.
func MailboxCollectToken(s string) string { return strings.TrimSpace(s) }
