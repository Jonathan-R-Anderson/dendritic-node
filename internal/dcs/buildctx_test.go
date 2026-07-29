package dcs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// A build context (Dockerfile + files) round-trips through pack/unpack and is
// content-addressed: identical inputs yield an identical digest.
func TestBuildContextRoundTripAndDeterminism(t *testing.T) {
	files := []BuildFile{
		{Path: "Dockerfile", Data: []byte("FROM alpine\nCOPY run.sh /run.sh\n")},
		{Path: "run.sh", Mode: 0o755, Data: []byte("#!/bin/sh\necho hi\n")},
		{Path: "conf/app.ini", Data: []byte("[main]\nx=1\n")},
	}
	blob, err := PackBuildContext(files)
	if err != nil {
		t.Fatal(err)
	}
	// Same files in a DIFFERENT order pack to the SAME bytes (sorted, fixed mtime).
	shuffled := []BuildFile{files[2], files[0], files[1]}
	blob2, err := PackBuildContext(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if BlobDigest(blob) != BlobDigest(blob2) {
		t.Fatal("build context digest is not deterministic across input order")
	}

	back, err := UnpackBuildContext(blob)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range back {
		got[f.Path] = string(f.Data)
	}
	if got["Dockerfile"] == "" || got["run.sh"] == "" || got["conf/app.ini"] == "" {
		t.Fatalf("files lost in round trip: %v", got)
	}
}

func TestBuildContextRequiresDockerfile(t *testing.T) {
	if _, err := PackBuildContext([]BuildFile{{Path: "run.sh", Data: []byte("x")}}); !errors.Is(err, ErrNoDockerfile) {
		t.Fatalf("a context without a Dockerfile was accepted: %v", err)
	}
}

// Path traversal in an archive is the classic build-context escape. Reject it
// on the way in AND out.
func TestBuildContextRejectsUnsafePaths(t *testing.T) {
	for _, bad := range []string{"../evil", "/etc/passwd", "a/../../b", "win\\path"} {
		_, err := PackBuildContext([]BuildFile{
			{Path: "Dockerfile", Data: []byte("FROM alpine")},
			{Path: bad, Data: []byte("x")},
		})
		if !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("unsafe path %q was accepted: %v", bad, err)
		}
	}
}

// The DHT-shard store round-trip: store a build context, fetch it by digest,
// get the same files. Uses an in-memory BlobStore standing in for the shard
// store (which chunks + Reed-Solomon-encodes + Provides to the DHT).
type memBlobStore struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func newMemBlobStore() *memBlobStore { return &memBlobStore{blobs: map[string][]byte{}} }

func (m *memBlobStore) PutBlob(_ context.Context, data []byte) (string, error) {
	digest := BlobDigest(data)
	m.mu.Lock()
	m.blobs[digest] = append([]byte(nil), data...)
	m.mu.Unlock()
	return digest, nil
}
func (m *memBlobStore) GetBlob(_ context.Context, digest string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.blobs[digest]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), b...), nil
}

func TestBuildContextStoreAndFetch(t *testing.T) {
	store := newMemBlobStore()
	files := []BuildFile{
		{Path: "Dockerfile", Data: []byte("FROM nginx\n")},
		{Path: "index.html", Data: []byte("<h1>vulnerable lab</h1>")},
	}
	digest, err := StoreBuildContext(context.Background(), store, files)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest is not a content address: %q", digest)
	}
	fetched, err := FetchBuildContext(context.Background(), store, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 2 {
		t.Fatalf("fetched %d files, want 2", len(fetched))
	}
}

// A tampered blob fails the digest check on fetch, so a hostile provider cannot
// substitute a different build context.
func TestFetchRejectsTamperedBlob(t *testing.T) {
	store := newMemBlobStore()
	files := []BuildFile{{Path: "Dockerfile", Data: []byte("FROM alpine\n")}}
	digest, _ := StoreBuildContext(context.Background(), store, files)
	// Corrupt the stored bytes under the same digest key.
	store.blobs[digest] = []byte("not the real build context")
	if _, err := FetchBuildContext(context.Background(), store, digest); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("a tampered build context was accepted: %v", err)
	}
}
