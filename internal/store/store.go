package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	bucketBuckets     = []byte("buckets")
	bucketObjects     = []byte("objects")
	bucketDenied      = []byte("denied")
	bucketRemote      = []byte("remote_shards")
	bucketSettings    = []byte("settings")
	bucketPolicies    = []byte("bucket_policies")
	keyCapacity       = []byte("capacity_bytes")
	ErrDigestMismatch = errors.New("object payload digest mismatch")
)

const (
	MinCapacityBytes int64 = 64 << 20
	MaxCapacityBytes int64 = 8 << 50
)

type Store struct {
	dir          string
	db           *bolt.DB
	masterKey    []byte
	dataShards   int
	parityShards int
	chunkBytes   int
	capacity     int64
	mu           sync.RWMutex
	allocationMu sync.Mutex
	fetchShard   func(context.Context, string) ([]byte, error)
	advertise    func(string)
	distribute   func(Manifest)
}

func Open(dir string, dataShards, parityShards, chunkBytes int, capacity int64) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "shards"), 0700); err != nil {
		return nil, err
	}
	masterKey, err := loadOrCreateSecret(filepath.Join(dir, "master.key"), chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dir, "metadata.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{
		dir: dir, db: db, masterKey: masterKey, dataShards: dataShards,
		parityShards: parityShards, chunkBytes: chunkBytes, capacity: capacity,
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{
			bucketBuckets, bucketObjects, bucketDenied, bucketRemote,
			bucketSettings, bucketPolicies,
		} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		settings := tx.Bucket(bucketSettings)
		if existing := settings.Get(keyCapacity); len(existing) == 8 {
			persisted := int64(binary.BigEndian.Uint64(existing))
			if persisted >= MinCapacityBytes && persisted <= MaxCapacityBytes {
				s.capacity = persisted
				return nil
			}
		}
		return settings.Put(keyCapacity, encodeInt64(capacity))
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) SetShardFetcher(fetcher func(context.Context, string) ([]byte, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetchShard = fetcher
}

func (s *Store) SetShardAdvertiser(advertiser func(string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advertise = advertiser
}

func (s *Store) SetObjectDistributor(distributor func(Manifest)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.distribute = distributor
}

func loadOrCreateSecret(path string, size int) ([]byte, error) {
	value, err := os.ReadFile(path)
	if err == nil {
		if len(value) != size {
			return nil, fmt.Errorf("%s has invalid key length", path)
		}
		return value, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	value = make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, value, 0600); err != nil {
		return nil, err
	}
	return value, nil
}

func objectKey(bucket, key string) []byte { return []byte(bucket + "\x00" + key) }

func (s *Store) CreateBucket(name string) error {
	if !validBucket(name) {
		return errors.New("invalid bucket name")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBuckets).Put([]byte(name), []byte(time.Now().UTC().Format(time.RFC3339Nano)))
	})
}

func validBucket(name string) bool {
	if len(name) < 3 || len(name) > 63 || strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func (s *Store) BucketExists(name string) bool {
	var found bool
	s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket(bucketBuckets).Get([]byte(name)) != nil
		return nil
	})
	return found
}

func (s *Store) ListBuckets() ([]string, error) {
	var result []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBuckets).ForEach(func(k, _ []byte) error {
			result = append(result, string(k))
			return nil
		})
	})
	sort.Strings(result)
	return result, err
}

func (s *Store) DeleteBucket(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		prefix := []byte(name + "\x00")
		cursor := tx.Bucket(bucketObjects).Cursor()
		if key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix) {
			return errors.New("bucket is not empty")
		}
		if err := tx.Bucket(bucketPolicies).Delete([]byte(name)); err != nil {
			return err
		}
		return tx.Bucket(bucketBuckets).Delete([]byte(name))
	})
}

func (s *Store) SetBucketPolicy(bucket string, policy []byte) error {
	if !s.BucketExists(bucket) {
		return errors.New("bucket does not exist")
	}
	value := append([]byte(nil), policy...)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPolicies).Put([]byte(bucket), value)
	})
}

func (s *Store) BucketPolicy(bucket string) ([]byte, error) {
	var policy []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketPolicies).Get([]byte(bucket))
		if value != nil {
			policy = append([]byte(nil), value...)
		}
		return nil
	})
	return policy, err
}

func (s *Store) DeleteBucketPolicy(bucket string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPolicies).Delete([]byte(bucket))
	})
}

func (s *Store) PutObject(bucket, key, contentType string, r io.Reader) (*Manifest, error) {
	return s.putObject(bucket, key, contentType, r, "", true)
}

func (s *Store) PutObjectVerified(bucket, key, contentType string, r io.Reader, expectedSHA256 string) (*Manifest, error) {
	return s.putObject(bucket, key, contentType, r, strings.ToLower(expectedSHA256), true)
}

func (s *Store) PutTemporaryObject(bucket, key string, r io.Reader, expectedSHA256 string) (*Manifest, error) {
	return s.putObject(bucket, key, "application/octet-stream", r, strings.ToLower(expectedSHA256), false)
}

func (s *Store) putObject(bucket, key, contentType string, r io.Reader, expectedSHA256 string, distribute bool) (*Manifest, error) {
	if !s.BucketExists(bucket) {
		return nil, os.ErrNotExist
	}
	if key == "" || strings.ContainsRune(key, '\x00') {
		return nil, errors.New("invalid object key")
	}
	objectKeyBytes := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(objectKeyBytes); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(objectKeyBytes)
	if err != nil {
		return nil, err
	}
	encoder, err := reedsolomon.New(s.dataShards, s.parityShards)
	if err != nil {
		return nil, err
	}
	manifest := &Manifest{
		Version: FormatVersion, Bucket: bucket, Key: key, ContentType: contentType,
		DataShards: s.dataShards, ParityShards: s.parityShards, ChunkBytes: s.chunkBytes,
		CreatedAt: time.Now().UTC(),
	}
	plainHash := sha256.New()
	buffer := make([]byte, s.chunkBytes)
	for index := 0; ; index++ {
		n, readErr := io.ReadFull(r, buffer)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return nil, readErr
		}
		plain := buffer[:n]
		plainHash.Write(plain)
		manifest.PlainSize += int64(n)
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		aad := chunkAAD(bucket, key, index)
		ciphertext := aead.Seal(nil, nonce, plain, aad)
		shards, err := encoder.Split(ciphertext)
		if err != nil {
			return nil, err
		}
		if err := encoder.Encode(shards); err != nil {
			return nil, err
		}
		chunk := ChunkManifest{
			Index: index, Nonce: nonce, CipherLength: len(ciphertext),
			ShardSize: len(shards[0]),
		}
		for shardIndex, shard := range shards {
			id := digest(shard)
			if err := s.writeShard(id, shard); err != nil {
				return nil, err
			}
			chunk.Shards = append(chunk.Shards, ShardRef{ID: id, Index: shardIndex, Size: len(shard)})
		}
		manifest.Chunks = append(manifest.Chunks, chunk)
		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	manifest.PlainSHA256 = hex.EncodeToString(plainHash.Sum(nil))
	if expectedSHA256 != "" && manifest.PlainSHA256 != expectedSHA256 {
		s.removeUnreferenced(manifestShardIDs(*manifest))
		return nil, ErrDigestMismatch
	}
	wrap, err := chacha20poly1305.NewX(s.masterKey)
	if err != nil {
		return nil, err
	}
	manifest.WrapNonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(manifest.WrapNonce); err != nil {
		return nil, err
	}
	manifest.WrappedKey = wrap.Seal(nil, manifest.WrapNonce, objectKeyBytes, []byte(bucket+"\x00"+key))
	idBytes, err := canonicalManifest(manifest)
	if err != nil {
		return nil, err
	}
	manifest.ObjectID = digest(idBytes)
	if s.IsRejected("object", manifest.ObjectID) {
		return nil, errors.New("object was rejected by this node")
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	var oldShards []string
	err = s.db.Update(func(tx *bolt.Tx) error {
		if old := tx.Bucket(bucketObjects).Get(objectKey(bucket, key)); old != nil {
			var previous Manifest
			if err := json.Unmarshal(old, &previous); err != nil {
				return err
			}
			oldShards = manifestShardIDs(previous)
		}
		return tx.Bucket(bucketObjects).Put(objectKey(bucket, key), encoded)
	})
	if err == nil {
		s.removeUnreferenced(oldShards)
		s.mu.RLock()
		distributor := s.distribute
		s.mu.RUnlock()
		if distribute && distributor != nil {
			go distributor(*manifest)
		}
	}
	return manifest, err
}

func canonicalManifest(manifest *Manifest) ([]byte, error) {
	copyValue := *manifest
	copyValue.ObjectID = ""
	return json.Marshal(copyValue)
}

func chunkAAD(bucket, key string, index int) []byte {
	return []byte(fmt.Sprintf("syndichan-object-v1\x00%s\x00%s\x00%d", bucket, key, index))
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func (s *Store) shardPath(id string) string {
	return filepath.Join(s.dir, "shards", id[:2], id)
}

func (s *Store) writeShard(id string, value []byte) error {
	if len(id) != 64 || digest(value) != id {
		return errors.New("invalid shard digest")
	}
	path := s.shardPath(id)
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := s.ensureCapacity(int64(len(value))); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".incoming-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(value); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	s.mu.RLock()
	advertiser := s.advertise
	s.mu.RUnlock()
	if advertiser != nil {
		go advertiser(id)
	}
	return nil
}

func (s *Store) ensureCapacity(incoming int64) error {
	used, err := s.UsedBytes()
	if err != nil {
		return err
	}
	if used+incoming > s.capacity {
		return errors.New("storage capacity exceeded")
	}
	return nil
}

func (s *Store) Capacity() int64 {
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	return s.capacity
}

// SetCapacity changes the amount of disk space made available to the node.
// Reducing the allocation never deletes data implicitly; the user must first
// remove stored items until usage is at or below the requested limit.
func (s *Store) SetCapacity(capacity int64) error {
	if capacity < MinCapacityBytes || capacity > MaxCapacityBytes {
		return fmt.Errorf(
			"storage allocation must be between %d MiB and %d TiB",
			MinCapacityBytes>>20, MaxCapacityBytes>>40,
		)
	}
	s.allocationMu.Lock()
	defer s.allocationMu.Unlock()
	used, err := s.UsedBytes()
	if err != nil {
		return err
	}
	if capacity < used {
		return fmt.Errorf("storage allocation cannot be below current usage of %d bytes", used)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSettings).Put(keyCapacity, encodeInt64(capacity))
	}); err != nil {
		return err
	}
	s.capacity = capacity
	return nil
}

func encodeInt64(value int64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, uint64(value))
	return encoded
}

func (s *Store) UsedBytes() (int64, error) {
	var total int64
	err := filepath.Walk(filepath.Join(s.dir, "shards"), func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func (s *Store) getManifest(bucket, key string) (*Manifest, error) {
	var encoded []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketObjects).Get(objectKey(bucket, key))
		if value == nil {
			return os.ErrNotExist
		}
		encoded = append([]byte(nil), value...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func (s *Store) HeadObject(bucket, key string) (*Manifest, error) {
	return s.getManifest(bucket, key)
}

func (s *Store) GetObject(bucket, key string, w io.Writer) (*Manifest, error) {
	manifest, err := s.getManifest(bucket, key)
	if err != nil {
		return nil, err
	}
	wrap, err := chacha20poly1305.NewX(s.masterKey)
	if err != nil {
		return nil, err
	}
	objectKeyBytes, err := wrap.Open(nil, manifest.WrapNonce, manifest.WrappedKey, []byte(bucket+"\x00"+key))
	if err != nil {
		return nil, errors.New("object key authentication failed")
	}
	aead, err := chacha20poly1305.NewX(objectKeyBytes)
	if err != nil {
		return nil, err
	}
	encoder, err := reedsolomon.New(manifest.DataShards, manifest.ParityShards)
	if err != nil {
		return nil, err
	}
	verifyHash := sha256.New()
	for _, chunk := range manifest.Chunks {
		shards := make([][]byte, manifest.DataShards+manifest.ParityShards)
		for _, ref := range chunk.Shards {
			value, err := os.ReadFile(s.shardPath(ref.ID))
			if err != nil {
				s.mu.RLock()
				fetcher := s.fetchShard
				s.mu.RUnlock()
				if fetcher != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					value, err = fetcher(ctx, ref.ID)
					cancel()
					if err == nil && digest(value) == ref.ID {
						_ = s.writeShard(ref.ID, value)
					}
				}
			}
			if err == nil && digest(value) == ref.ID {
				shards[ref.Index] = value
			}
		}
		if err := encoder.Reconstruct(shards); err != nil {
			return nil, fmt.Errorf("reconstruct chunk %d: %w", chunk.Index, err)
		}
		var ciphertext []byte
		for i := 0; i < manifest.DataShards; i++ {
			ciphertext = append(ciphertext, shards[i]...)
		}
		ciphertext = ciphertext[:chunk.CipherLength]
		plain, err := aead.Open(nil, chunk.Nonce, ciphertext, chunkAAD(bucket, key, chunk.Index))
		if err != nil {
			return nil, fmt.Errorf("authenticate chunk %d: %w", chunk.Index, err)
		}
		verifyHash.Write(plain)
		if _, err := w.Write(plain); err != nil {
			return nil, err
		}
	}
	if hex.EncodeToString(verifyHash.Sum(nil)) != manifest.PlainSHA256 {
		return nil, errors.New("plaintext object digest mismatch")
	}
	return manifest, nil
}

func (s *Store) ListObjects(bucket, prefix string) ([]Manifest, error) {
	var result []Manifest
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(bucketObjects).Cursor()
		seek := []byte(bucket + "\x00" + prefix)
		bucketPrefix := []byte(bucket + "\x00")
		for k, v := cursor.Seek(seek); k != nil && bytes.HasPrefix(k, bucketPrefix); k, v = cursor.Next() {
			var manifest Manifest
			if err := json.Unmarshal(v, &manifest); err != nil {
				return err
			}
			if strings.HasPrefix(manifest.Key, prefix) {
				result = append(result, manifest)
			}
		}
		return nil
	})
	return result, err
}

func (s *Store) DeleteObject(bucket, key string) error {
	var candidates []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketObjects).Get(objectKey(bucket, key))
		if value != nil {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			candidates = manifestShardIDs(manifest)
		}
		return tx.Bucket(bucketObjects).Delete(objectKey(bucket, key))
	})
	if err == nil {
		s.removeUnreferenced(candidates)
	}
	return err
}

func (s *Store) CleanupObjectPrefix(prefix string) error {
	var targets [][2]string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			if strings.HasPrefix(manifest.Key, prefix) {
				targets = append(targets, [2]string{manifest.Bucket, manifest.Key})
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := s.DeleteObject(target[0], target[1]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) IsRejected(kind, id string) bool {
	var rejected bool
	s.db.View(func(tx *bolt.Tx) error {
		rejected = tx.Bucket(bucketDenied).Get([]byte(kind+"\x00"+id)) != nil
		return nil
	})
	return rejected
}

func (s *Store) Reject(kind, id string) error {
	if kind != "object" && kind != "shard" {
		return errors.New("invalid rejection kind")
	}
	if len(id) != 64 {
		return errors.New("invalid content ID")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDenied).Put([]byte(kind+"\x00"+id), []byte(time.Now().UTC().Format(time.RFC3339Nano)))
	})
}

func (s *Store) RejectAndRemove(kind, id string) error {
	if err := s.Reject(kind, id); err != nil {
		return err
	}
	var candidates []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		if kind == "shard" {
			candidates = append(candidates, id)
			return tx.Bucket(bucketRemote).Delete([]byte(id))
		}
		objects := tx.Bucket(bucketObjects)
		var objectKeys [][]byte
		if err := objects.ForEach(func(key, value []byte) error {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			if manifest.ObjectID != id {
				return nil
			}
			objectKeys = append(objectKeys, append([]byte(nil), key...))
			for _, chunk := range manifest.Chunks {
				for _, shard := range chunk.Shards {
					candidates = append(candidates, shard.ID)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range objectKeys {
			if err := objects.Delete(key); err != nil {
				return err
			}
		}
		remote := tx.Bucket(bucketRemote)
		var remoteKeys [][]byte
		if err := remote.ForEach(func(key, value []byte) error {
			var shard RemoteShard
			if err := json.Unmarshal(value, &shard); err != nil {
				return err
			}
			if shard.ObjectID == id {
				remoteKeys = append(remoteKeys, append([]byte(nil), key...))
				candidates = append(candidates, shard.ID)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range remoteKeys {
			if err := remote.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, shardID := range candidates {
		if err := s.removeUnreferenced([]string{shardID}); err != nil {
			return err
		}
	}
	return nil
}

func manifestShardIDs(manifest Manifest) []string {
	var result []string
	for _, chunk := range manifest.Chunks {
		for _, shard := range chunk.Shards {
			result = append(result, shard.ID)
		}
	}
	return result
}

func (s *Store) removeUnreferenced(candidates []string) error {
	for _, shardID := range candidates {
		referenced, err := s.shardReferenced(shardID)
		if err != nil {
			return err
		}
		if !referenced {
			_ = os.Remove(s.shardPath(shardID))
		}
	}
	return nil
}

func (s *Store) shardReferenced(shardID string) (bool, error) {
	var referenced bool
	err := s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketRemote).Get([]byte(shardID)) != nil {
			referenced = true
			return nil
		}
		return tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
			if referenced {
				return nil
			}
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			for _, chunk := range manifest.Chunks {
				for _, shard := range chunk.Shards {
					if shard.ID == shardID {
						referenced = true
						return nil
					}
				}
			}
			return nil
		})
	})
	return referenced, err
}

func (s *Store) PutRemoteShard(shard RemoteShard, value []byte) error {
	if len(shard.ID) != 64 || digest(value) != shard.ID || int64(len(value)) != shard.Size {
		return errors.New("remote shard failed content-address verification")
	}
	if s.IsRejected("shard", shard.ID) || s.IsRejected("object", shard.ObjectID) {
		return errors.New("shard or object is rejected by this node")
	}
	if err := s.writeShard(shard.ID, value); err != nil {
		return err
	}
	shard.CreatedAt = time.Now().UTC()
	encoded, err := json.Marshal(shard)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRemote).Put([]byte(shard.ID), encoded)
	})
}

func (s *Store) ReadShard(id string) ([]byte, error) {
	if len(id) != 64 {
		return nil, errors.New("invalid shard ID")
	}
	value, err := os.ReadFile(s.shardPath(id))
	if err != nil {
		return nil, err
	}
	if digest(value) != id {
		return nil, errors.New("stored shard digest mismatch")
	}
	return value, nil
}

func (s *Store) ListShardIDs() ([]string, error) {
	var result []string
	err := filepath.Walk(filepath.Join(s.dir, "shards"), func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && len(info.Name()) == 64 {
			result = append(result, info.Name())
		}
		return nil
	})
	return result, err
}

func (s *Store) ListStored() ([]StoredItem, error) {
	var result []StoredItem
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketObjects).ForEach(func(_, value []byte) error {
			var manifest Manifest
			if err := json.Unmarshal(value, &manifest); err != nil {
				return err
			}
			result = append(result, StoredItem{
				Kind: "object", ID: manifest.ObjectID, DisplayName: manifest.Bucket + "/" + manifest.Key,
				ContentType: manifest.ContentType, Size: manifest.PlainSize, LocalObject: true,
				Rejected:  tx.Bucket(bucketDenied).Get([]byte("object\x00"+manifest.ObjectID)) != nil,
				CreatedAt: manifest.CreatedAt,
			})
			return nil
		}); err != nil {
			return err
		}
		return tx.Bucket(bucketRemote).ForEach(func(_, value []byte) error {
			var shard RemoteShard
			if err := json.Unmarshal(value, &shard); err != nil {
				return err
			}
			result = append(result, StoredItem{
				Kind: "shard", ID: shard.ID, DisplayName: "Encrypted shard " + shard.ID[:12],
				Size: shard.Size, Rejected: tx.Bucket(bucketDenied).Get([]byte("shard\x00"+shard.ID)) != nil,
				CreatedAt: shard.CreatedAt,
			})
			return nil
		})
	})
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, err
}
