package proxy

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/identity"
	"github.com/rabbiit/maniwani/storage-client/internal/axon/names"
)

func TestAliasFailoverAndNoExitOnFailure(t *testing.T) {
	var destinations []string
	for i := byte(1); i <= 6; i++ {
		key := make([]byte, 32)
		key[0] = i
		destinations = append(destinations, identity.FullAddress(key))
	}
	calls := 0
	h := New(func(_ context.Context, _, addr string) (net.Conn, error) {
		if addr != net.JoinHostPort(destinations[calls], "443") {
			t.Errorf("dial order %s", addr)
		}
		calls++
		return nil, errors.New("failed overlay")
	})
	h.NameMatches = func(s string) bool { return s == "example.com" }
	h.ExitVia = "exit.key.axon"
	h.MissingFallback = true
	h.ResolveAll = func(context.Context, string) ([]string, error) { return destinations, nil }
	if _, err := h.dial(context.Background(), "example.com:443"); err == nil || calls != 4 {
		t.Fatalf("calls %d error %v", calls, err)
	}
	calls = 0
	h.Dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("first down")
		}
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	conn, err := h.dial(context.Background(), "example.com:443")
	if err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
	conn.Close()
}

func TestAliasFallbackPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, host string
		fallback   bool
		resolveErr error
		exit       bool
	}{
		{"missing-default", "example.com", false, names.ErrNotRegistered, false},
		{"missing-opt-in", "example.com", true, names.ErrNotRegistered, true},
		{"owned-empty", "example.com", true, names.ErrNoDestination, false},
		{"RPC", "example.com", true, errors.New("RPC failure"), false},
		{"axon-missing", "example.axon", true, names.ErrNotRegistered, false},
		{"reserved", "bad.key.axon", true, errors.New("invalid address"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := New(func(context.Context, string, string) (net.Conn, error) {
				calls++
				return nil, errors.New("exit attempted")
			})
			h.ExitVia = "exit.key.axon"
			h.MissingFallback = tc.fallback
			h.NameMatches = func(string) bool { return true }
			h.ResolveAll = func(context.Context, string) ([]string, error) { return nil, tc.resolveErr }
			h.dial(context.Background(), net.JoinHostPort(tc.host, "80"))
			if (calls == 1) != tc.exit {
				t.Fatalf("exit calls %d", calls)
			}
		})
	}
}

func TestDirectAddressBypassesRegistryAndAxonNeverExits(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	address := identity.FullAddress(key)
	calls := 0
	h := New(func(_ context.Context, _, addr string) (net.Conn, error) {
		calls++
		if addr != address+":80" {
			t.Fatal(addr)
		}
		return nil, errors.New("overlay")
	})
	h.ResolveAll = func(context.Context, string) ([]string, error) {
		t.Fatal("registry read for direct identity")
		return nil, nil
	}
	h.ExitVia = "exit.key.axon"
	h.dial(context.Background(), address+".:80")
	if calls != 1 {
		t.Fatal(calls)
	}
	h.ResolveAll = nil
	h.dial(context.Background(), "missing.axon:80")
	if calls != 1 {
		t.Fatal("unexpected exit")
	}
}

func TestInvalidAliasSpellingsCannotEscapeToExit(t *testing.T) {
	r := names.NewWithPolicy("http://127.0.0.1:1", "0xdead", []string{"com"}, true, false)
	h := New(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("invalid alias reached dial/exit")
		return nil, nil
	})
	h.NameMatches = r.Matches
	h.ResolveAll = r.ResolveAll
	h.MissingFallback = true
	h.ExitVia = "exit.key.axon"
	for _, host := range []string{"example.com..", "example.axon..", "K.com", "x..com", "-x.com"} {
		if _, err := h.dial(context.Background(), host+":80"); err == nil {
			t.Fatalf("accepted %q", host)
		}
	}
}
