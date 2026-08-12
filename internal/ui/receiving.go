package ui

// The recipient's control panel — roadmap P7.
//
// WHY THIS TALKS TO AN INTERFACE AND NOT TO internal/channel
// ----------------------------------------------------------
// A dashboard is a view. It shows what the payment node believes and forwards
// what an operator asks for; it does not compute balances, decide what is
// settleable, or know that a state has a nonce. Everything below is expressed
// in strings and enums that a template can render, and the one file that
// understands channels is receiving_adapter.go.
//
// That boundary is not decoration. The whole payment stack was built so that
// exactly one component turns a request into money, and a dashboard reaching
// past this interface into a Store would be a second one — arriving through the
// least-reviewed door in the system.
//
// AMOUNTS ARE STRINGS ALL THE WAY THROUGH
// ---------------------------------------
// Decimal strings, never numbers, for the reason the rest of the stack uses
// them: one gold award is 1e20 wei and this page is read by a browser.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// ReceivingChannel is one channel, as an operator needs to see it.
type ReceivingChannel struct {
	ID     string `json:"id"`
	Peer   string `json:"peer"`
	Mine   string `json:"mine"`
	Theirs string `json:"theirs"`
	// Locked is value committed to payments in flight. Shown separately from
	// Mine because it is not spendable and an operator who reads it as
	// available will be surprised at settlement.
	Locked     string `json:"locked"`
	Nonce      uint64 `json:"nonce"`
	Conflicted bool   `json:"conflicted"`

	// Settlement, as the local record has it.
	Mode      string `json:"mode"`
	Phase     string `json:"phase"`
	TxHash    string `json:"tx_hash,omitempty"`
	DueAt     int64  `json:"due_at,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// Receiving is everything the panel needs from the payment node.
//
// Deliberately narrow. There is no method here that hands back a state, a
// signature or a nonce to act on — an operator sets a policy and asks for
// settlement, and what that means is decided below.
type Receiving interface {
	// Channels lists what this node is receiving on.
	Channels(ctx context.Context) ([]ReceivingChannel, error)
	// SetPolicy records when the recipient wants value on chain.
	SetPolicy(ctx context.Context, id, mode string, intervalSeconds int64) error
	// SettleNow advances one channel's settlement and reports what happened.
	SettleNow(ctx context.Context, id string) (outcome string, err error)
	// Close asks for the money now and ends the channel.
	Close(ctx context.Context, id string) (outcome string, err error)
}

// SetReceiving attaches a payment node to the dashboard. Without one the
// receiving routes answer 501 — a node that cannot receive should say so rather
// than show an empty panel that looks like "no tips yet".
//
// Called during wiring, before the server starts, exactly like the other
// setters here. This type deliberately has no lock: everything on it is set
// once at startup, and adding one for this field alone would suggest the rest
// are safe to change while serving, which they are not.
func (s *Server) SetReceiving(r Receiving) { s.receiving = r }

func (s *Server) requireReceiving(w http.ResponseWriter) (Receiving, bool) {
	rec := s.receiving
	if rec == nil {
		writeReceivingJSON(w, http.StatusNotImplemented,
			map[string]string{"error": "this node is not configured to receive payments"})
		return nil, false
	}
	return rec, true
}

func writeReceivingJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// serveReceiving lists the channels, for the panel and for anything scripting
// against it.
func (s *Server) serveReceiving(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.requireReceiving(w)
	if !ok {
		return
	}
	channels, err := rec.Channels(r.Context())
	if err != nil {
		writeReceivingJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if channels == nil {
		channels = []ReceivingChannel{}
	}
	writeReceivingJSON(w, http.StatusOK, map[string]any{"channels": channels})
}

// setReceivingPolicy records how often the recipient wants settling.
//
// Form-encoded rather than JSON because it is posted by the dashboard's own
// form. Guarded by the CSRF token, but NOT by "is there a config file" — a node
// with no config can still be owed money.
func (s *Server) setReceivingPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.checkToken(w, r) {
		return
	}
	rec, ok := s.requireReceiving(w)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.FormValue("channel"))
	mode := strings.TrimSpace(r.FormValue("mode"))

	var interval int64
	if raw := strings.TrimSpace(r.FormValue("interval_seconds")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			http.Error(w, "interval must be a positive number of seconds", http.StatusBadRequest)
			return
		}
		interval = parsed
	}
	if err := rec.SetPolicy(r.Context(), id, mode, interval); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// settleReceiving is "Settle Now".
func (s *Server) settleReceiving(w http.ResponseWriter, r *http.Request) {
	s.receivingAction(w, r, func(rec Receiving, id string) (string, error) {
		return rec.SettleNow(r.Context(), id)
	})
}

// closeReceiving is "Close Channel".
func (s *Server) closeReceiving(w http.ResponseWriter, r *http.Request) {
	s.receivingAction(w, r, func(rec Receiving, id string) (string, error) {
		return rec.Close(r.Context(), id)
	})
}

// receivingAction runs one settlement operation and reports its OUTCOME.
//
// The outcome travels even when the operation could not finish, for the same
// reason the payment API separates its three results: "not due", "there are
// locks outstanding" and "the RPC is down" call for different responses, and
// collapsing them into a red box tells an operator nothing.
func (s *Server) receivingAction(w http.ResponseWriter, r *http.Request,
	run func(Receiving, string) (string, error)) {

	if !s.checkToken(w, r) {
		return
	}
	rec, ok := s.requireReceiving(w)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.FormValue("channel"))
	outcome, err := run(rec, id)

	// A browser form gets a redirect; a script asking for JSON gets the detail.
	if wantsJSON(r) {
		body := map[string]any{"outcome": outcome}
		code := http.StatusOK
		if err != nil {
			body["error"] = err.Error()
			code = http.StatusAccepted
		}
		writeReceivingJSON(w, code, body)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}
