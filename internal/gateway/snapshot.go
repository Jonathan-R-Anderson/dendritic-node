package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SnapshotCache keeps a verified, read-only copy of the site so this gateway can
// still answer when the origin cannot.
//
// THE TIMING IS THE WHOLE DESIGN
// ------------------------------
// The copy is fetched WHILE THE ORIGIN IS HEALTHY, on a slow poll, and sits on
// disk waiting. Fetching it during the outage would be too late twice over: the
// origin that publishes the manifest is the thing that just died, and a fleet of
// gateways all pulling a full snapshot at the moment of failure is a second
// outage arriving on the heels of the first.
//
// So an emergency snapshot costs a little bandwidth every hour and nothing at
// all when it is finally needed.
//
// WHAT IS VERIFIED, AND WHEN
// --------------------------
// The manifest signature is checked on arrival, against a publisher key pinned
// in configuration. Objects are checked against the manifest when stored AND
// again when served, because a cache on a volunteer's disk is not more
// trustworthy than the network it came from — and the whole point of this
// system is that a gateway operator cannot change what syndichan says.
//
// A snapshot that fails verification is discarded, not quarantined. There is no
// use for bytes that are almost right.
type SnapshotCache struct {
	// Origin is where manifests and objects are fetched from while it is up.
	Origin string
	// PublisherKey is the Ed25519 key snapshots are signed with. Pinned, and
	// deliberately NOT the origin's content-signing key: see
	// backend/services/snapshot_key.py.
	PublisherKey ed25519.PublicKey
	// Dir is where the copy lives between restarts.
	Dir string
	// Poll is how often to look for a newer snapshot.
	Poll time.Duration
	// MaxObjectBytes bounds any single object, so a hostile manifest cannot ask
	// this gateway to buy a disk.
	MaxObjectBytes int64
	Logger         interface{ Printf(string, ...any) }

	mu       sync.RWMutex
	manifest *SnapshotManifest
	client   *http.Client
}

// SnapshotManifest is the published description of one frozen copy.
type SnapshotManifest struct {
	Schema       int    `json:"schema"`
	SnapshotID   string `json:"snapshot_id"`
	Sequence     int64  `json:"sequence"`
	CreatedAt    int64  `json:"created_at"`
	RefreshAfter int64  `json:"refresh_after"`
	StaleAfter   int64  `json:"stale_after"`
	ExpiresAt    int64  `json:"expires_at"`
	RootHash     string `json:"root_hash"`
	ObjectCount  int    `json:"object_count"`
	Signature    string `json:"signature"`
	Routes       map[string]struct {
		Object      string `json:"object"`
		ContentType string `json:"content_type"`
		Status      int    `json:"status"`
		Size        int64  `json:"size"`
	} `json:"routes"`
}

// Freshness states from the specification. A reader is told which one they are
// looking at, because "an hour old" and "eleven hours old" are different facts
// and only one of them should worry somebody.
const (
	SnapshotFresh     = "fresh"
	SnapshotStale     = "stale"
	SnapshotEmergency = "emergency-stale"
	SnapshotExpired   = "expired"
)

// State reports how old the held snapshot is.
func (m *SnapshotManifest) State(now time.Time) string {
	unix := now.Unix()
	switch {
	case unix >= m.ExpiresAt:
		return SnapshotExpired
	case unix >= m.StaleAfter:
		return SnapshotEmergency
	case unix >= m.RefreshAfter:
		return SnapshotStale
	default:
		return SnapshotFresh
	}
}

// Usable reports whether this snapshot may be served at all.
func (m *SnapshotManifest) Usable(now time.Time) bool {
	return m != nil && m.State(now) != SnapshotExpired
}

// NewSnapshotCache builds a cache. A nil publisher key disables it entirely:
// an unverifiable snapshot is worse than none, because it would let whoever
// runs this machine decide what syndichan says during an outage.
func NewSnapshotCache(origin, dir string, key ed25519.PublicKey) *SnapshotCache {
	return &SnapshotCache{
		Origin: strings.TrimRight(origin, "/"), PublisherKey: key, Dir: dir,
		Poll: 10 * time.Minute, MaxObjectBytes: 8 << 20,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *SnapshotCache) Enabled() bool {
	return c != nil && len(c.PublisherKey) == ed25519.PublicKeySize && c.Dir != ""
}

// Manifest returns the currently held snapshot, or nil.
func (c *SnapshotCache) Manifest() *SnapshotManifest {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.manifest
}

// Run keeps the local copy up to date until the context is cancelled.
func (c *SnapshotCache) Run(ctx context.Context) {
	if !c.Enabled() {
		return
	}
	// A held snapshot survives a restart; loading it before the first poll means
	// a gateway that reboots during an outage is useful immediately.
	if err := c.loadFromDisk(); err == nil && c.Manifest() != nil {
		c.logf("emergency cache: loaded snapshot %d from disk", c.Manifest().Sequence)
	}
	ticker := time.NewTicker(c.Poll)
	defer ticker.Stop()
	c.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refresh(ctx)
		}
	}
}

func (c *SnapshotCache) refresh(ctx context.Context) {
	manifest, err := c.fetchManifest(ctx)
	if err != nil {
		// The origin being unreachable is the case this whole cache exists for.
		// It is not an error worth shouting about on every poll.
		return
	}
	current := c.Manifest()
	if current != nil && manifest.Sequence <= current.Sequence {
		return
	}
	stored, err := c.download(ctx, manifest)
	if err != nil {
		c.logf("emergency cache: snapshot %d incomplete (%v); keeping %s",
			manifest.Sequence, err, describeHeld(current))
		return
	}
	c.mu.Lock()
	c.manifest = manifest
	c.mu.Unlock()
	_ = c.saveManifest(manifest)
	c.logf("emergency cache: holding snapshot %d (%d objects, %s)",
		manifest.Sequence, stored, manifest.State(time.Now()))
}

func describeHeld(m *SnapshotManifest) string {
	if m == nil {
		return "no snapshot"
	}
	return fmt.Sprintf("snapshot %d", m.Sequence)
}

func (c *SnapshotCache) fetchManifest(ctx context.Context) (*SnapshotManifest, error) {
	body, err := c.get(ctx, c.Origin+"/.well-known/syndichan/snapshot.json", 1<<22)
	if err != nil {
		return nil, err
	}
	var manifest SnapshotManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, err
	}
	if err := c.verify(&manifest); err != nil {
		return nil, err
	}
	// Never accept a lower sequence than one already held, even signed. That is
	// the rollback defence: an old snapshot is genuinely signed, which is
	// exactly why the sequence has to be checked separately.
	if held := c.Manifest(); held != nil && manifest.Sequence < held.Sequence {
		return nil, fmt.Errorf("sequence %d is older than the held %d",
			manifest.Sequence, held.Sequence)
	}
	return &manifest, nil
}

// verify checks the publisher signature over the canonical manifest fields.
func (c *SnapshotCache) verify(m *SnapshotManifest) error {
	if m.Signature == "" {
		return fmt.Errorf("snapshot %d is unsigned", m.Sequence)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimRight(m.Signature, "="))
	if err != nil || len(signature) != ed25519.SignatureSize {
		signature, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(m.Signature, "="))
		if err != nil {
			return fmt.Errorf("snapshot signature is not base64: %w", err)
		}
	}
	message := []byte(strings.Join([]string{
		"syndichan-snapshot:v1", m.SnapshotID, strconv.FormatInt(m.Sequence, 10),
		m.RootHash, strconv.FormatInt(m.CreatedAt, 10),
		strconv.FormatInt(m.ExpiresAt, 10), strconv.Itoa(m.ObjectCount),
	}, "\n"))
	if !ed25519.Verify(c.PublisherKey, message, signature) {
		return fmt.Errorf("snapshot %d is not signed by the publisher key", m.Sequence)
	}
	return nil
}

// download fetches every object the manifest names that is not already held.
func (c *SnapshotCache) download(ctx context.Context, m *SnapshotManifest) (int, error) {
	stored := 0
	for path, entry := range m.Routes {
		if ctx.Err() != nil {
			return stored, ctx.Err()
		}
		if c.have(entry.Object) {
			stored++
			continue
		}
		body, err := c.get(ctx, c.Origin+"/snapshot/object/"+entry.Object, c.MaxObjectBytes)
		if err != nil {
			return stored, fmt.Errorf("%s: %w", path, err)
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != entry.Object {
			// The manifest is signed, so bytes that do not match it did not come
			// from the publisher — whoever served them substituted something.
			return stored, fmt.Errorf("%s: object does not match the signed manifest", path)
		}
		if err := c.put(entry.Object, body); err != nil {
			return stored, err
		}
		stored++
	}
	return stored, nil
}

// Object returns the bytes for a route, or nil. Verified again on the way out.
func (c *SnapshotCache) Object(path string) ([]byte, string, bool) {
	manifest := c.Manifest()
	if manifest == nil || !manifest.Usable(time.Now()) {
		return nil, "", false
	}
	entry, found := manifest.Routes[path]
	if !found {
		return nil, "", false
	}
	body, err := os.ReadFile(c.objectPath(entry.Object))
	if err != nil {
		return nil, "", false
	}
	// Re-checked on serve, not only on store. This disk belongs to whoever runs
	// the gateway, and the guarantee being offered to a reader is that the
	// operator cannot change what they are handed.
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != entry.Object {
		return nil, "", false
	}
	return body, entry.ContentType, true
}

// HasRoute reports whether a path is in the verified manifest.
//
// The lookup guard: an object is only ever fetched for a route the SIGNED
// manifest names. Without it, a request for a random path becomes a cache miss,
// a disk probe and eventually a network fetch — so anyone with a loop could
// point this gateway's storage at the network as an amplifier.
func (c *SnapshotCache) HasRoute(path string) bool {
	manifest := c.Manifest()
	if manifest == nil {
		return false
	}
	_, found := manifest.Routes[path]
	return found
}

// -- disk ------------------------------------------------------------------

func (c *SnapshotCache) objectPath(digest string) string {
	if len(digest) < 4 {
		return filepath.Join(c.Dir, "objects", "invalid")
	}
	return filepath.Join(c.Dir, "objects", digest[:2], digest[2:4], digest)
}

func (c *SnapshotCache) have(digest string) bool {
	info, err := os.Stat(c.objectPath(digest))
	return err == nil && info.Size() > 0
}

func (c *SnapshotCache) put(digest string, body []byte) error {
	path := c.objectPath(digest)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Temp-and-rename, so a reader can never see half an object under a name
	// that promises the whole of it.
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, body, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func (c *SnapshotCache) saveManifest(m *SnapshotManifest) error {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return err
	}
	temporary := filepath.Join(c.Dir, "current.json.tmp")
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(c.Dir, "current.json"))
}

func (c *SnapshotCache) loadFromDisk() error {
	body, err := os.ReadFile(filepath.Join(c.Dir, "current.json"))
	if err != nil {
		return err
	}
	var manifest SnapshotManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return err
	}
	// Verified again on load. A file on this disk is not evidence of anything;
	// the signature is.
	if err := c.verify(&manifest); err != nil {
		return err
	}
	c.mu.Lock()
	c.manifest = &manifest
	c.mu.Unlock()
	return nil
}

func (c *SnapshotCache) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", url, response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, limit))
}

func (c *SnapshotCache) logf(format string, args ...any) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
	}
}
