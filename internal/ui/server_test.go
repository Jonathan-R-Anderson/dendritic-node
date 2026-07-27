package ui

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/store"
)

type testNode struct{}

func (testNode) ID() string          { return "test-node" }
func (testNode) Addresses() []string { return []string{"/garlic32/test/p2p/12D3Koo"} }
func (testNode) PeerCount() int      { return 3 }

func TestDashboardRejectsDNSRebindingHosts(t *testing.T) {
	for _, allowed := range []string{"localhost:9090", "127.0.0.1:9090", "[::1]:9090"} {
		if !validDashboardHost(allowed) {
			t.Fatalf("local host rejected: %s", allowed)
		}
	}
	for _, denied := range []string{"attacker.example:9090", "0.0.0.0:9090", "192.168.1.4:9090"} {
		if validDashboardHost(denied) {
			t.Fatalf("non-local host accepted: %s", denied)
		}
	}
}

func TestUserCanPersistStorageAllocation(t *testing.T) {
	storage, err := store.Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	server := New(storage, testNode{}, log.New(io.Discard, "", 0))
	form := url.Values{
		"csrf":         {server.csrf},
		"capacity_gib": {"1.5"},
	}
	request := httptest.NewRequest(
		http.MethodPost, "http://127.0.0.1:9090/capacity",
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("capacity update returned %d: %s", response.Code, response.Body.String())
	}
	if storage.Capacity() != int64(1.5*(1<<30)) {
		t.Fatalf("capacity was not updated: %d", storage.Capacity())
	}
}

func TestCapacityUpdateRequiresCSRF(t *testing.T) {
	storage, err := store.Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	server := New(storage, testNode{}, log.New(io.Discard, "", 0))
	request := httptest.NewRequest(
		http.MethodPost, "http://127.0.0.1:9090/capacity",
		strings.NewReader("capacity_gib=1"),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF returned %d", response.Code)
	}
}
