package store

import (
	"bytes"
	"os"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	storage, err := Open(t.TempDir(), 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if err := storage.CreateBucket("test-bucket"); err != nil {
		t.Fatal(err)
	}
	return storage
}

func TestEncryptedErasureRoundTripWithTwoMissingShards(t *testing.T) {
	storage := openTestStore(t)
	plain := bytes.Repeat([]byte("private content must not appear in peer shards\n"), 5000)
	manifest, err := storage.PutObject("test-bucket", "folder/file.txt", "text/plain", bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ObjectID == "" || len(manifest.Chunks) < 2 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			raw, err := os.ReadFile(storage.shardPath(ref.ID))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte("private content")) {
				t.Fatal("plaintext leaked into an encrypted shard")
			}
		}
		for _, ref := range chunk.Shards[:manifest.ParityShards] {
			if err := os.Remove(storage.shardPath(ref.ID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	var recovered bytes.Buffer
	if _, err := storage.GetObject("test-bucket", "folder/file.txt", &recovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.Bytes(), plain) {
		t.Fatal("recovered plaintext differs")
	}
}

func TestTamperedShardIsRejected(t *testing.T) {
	storage := openTestStore(t)
	manifest, err := storage.PutObject("test-bucket", "file.bin", "application/octet-stream", bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4}, 1000)))
	if err != nil {
		t.Fatal(err)
	}
	chunk := manifest.Chunks[0]
	for _, ref := range chunk.Shards[:manifest.ParityShards+1] {
		if err := os.WriteFile(storage.shardPath(ref.ID), bytes.Repeat([]byte{0xff}, ref.Size), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if _, err := storage.GetObject("test-bucket", "file.bin", &output); err == nil {
		t.Fatal("expected reconstruction failure after too many corrupt shards")
	}
}

func TestRejectRemovesAndDeniesObject(t *testing.T) {
	storage := openTestStore(t)
	manifest, err := storage.PutObject("test-bucket", "reject.bin", "application/octet-stream", bytes.NewReader([]byte("reject me")))
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.RejectAndRemove("object", manifest.ObjectID); err != nil {
		t.Fatal(err)
	}
	if !storage.IsRejected("object", manifest.ObjectID) {
		t.Fatal("object ID was not denied")
	}
	if _, err := storage.HeadObject("test-bucket", "reject.bin"); !os.IsNotExist(err) {
		t.Fatalf("object metadata remains: %v", err)
	}
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			if _, err := os.Stat(storage.shardPath(ref.ID)); !os.IsNotExist(err) {
				t.Fatalf("shard %s remains after rejection", ref.ID)
			}
		}
	}
}

func TestExpectedDigestMismatchNeverPublishesObject(t *testing.T) {
	storage := openTestStore(t)
	_, err := storage.PutObjectVerified(
		"test-bucket", "bad.bin", "application/octet-stream",
		bytes.NewReader([]byte("actual")), string(make([]byte, 64)),
	)
	if err != ErrDigestMismatch {
		t.Fatalf("expected ErrDigestMismatch, got %v", err)
	}
	if _, err := storage.HeadObject("test-bucket", "bad.bin"); !os.IsNotExist(err) {
		t.Fatalf("mismatched object was published: %v", err)
	}
}

func TestCapacityChoicePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	storage, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	const chosen = int64(3 << 30)
	if err := storage.SetCapacity(chosen); err != nil {
		t.Fatal(err)
	}
	if storage.Capacity() != chosen {
		t.Fatalf("capacity is %d, want %d", storage.Capacity(), chosen)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Capacity() != chosen {
		t.Fatalf("persisted capacity is %d, want %d", reopened.Capacity(), chosen)
	}
}

func TestBucketPolicyPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	storage, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateBucket("public-media"); err != nil {
		t.Fatal(err)
	}
	policy := []byte(`{"Statement":[{"Effect":"Allow"}]}`)
	if err := storage.SetBucketPolicy("public-media", policy); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, 3, 2, 64<<10, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.BucketPolicy("public-media")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, policy) {
		t.Fatalf("persisted policy is %q, want %q", got, policy)
	}
}
