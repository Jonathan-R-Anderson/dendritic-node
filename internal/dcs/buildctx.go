package dcs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// A build context is the Dockerfile plus the supporting files it needs, packed
// into one content-addressed blob and distributed over the DHT as shards --
// exactly the same store that holds encrypted object shards. A worker does not
// pull a prebuilt image from a registry; it fetches the build context by
// digest, verifies it, and `docker build`s it locally. That keeps the whole
// system registry-free and lets any peer reproduce the image from source.

// BlobStore is the content-addressed shard store. *store.Store satisfies it
// (its Put chunks, Reed-Solomon-encodes and Provides to the DHT; Get fetches
// and verifies). The interface keeps this package testable without the store.
type BlobStore interface {
	// PutBlob stores data and returns its content digest ("sha256:...").
	PutBlob(ctx context.Context, data []byte) (string, error)
	// GetBlob fetches and verifies a blob by digest.
	GetBlob(ctx context.Context, digest string) ([]byte, error)
}

// BuildFile is one file in a build context.
type BuildFile struct {
	Path string // relative, forward-slash, no "..", no leading "/"
	Mode int64  // unix mode; 0 defaults to 0644
	Data []byte
}

// MaxBuildContextBytes bounds a build context so a hostile deployer cannot ask
// a worker to reassemble an enormous archive. Generous for a Dockerfile plus
// scripts and small assets; not for shipping a base image.
const MaxBuildContextBytes = 64 << 20 // 64 MiB uncompressed

// fixedModTime is stamped on every archive entry so identical files hash
// identically regardless of when they were packed. Content addressing must be
// reproducible across machines and runs, which real mtimes would break.
var fixedModTime = time.Unix(1_000_000_000, 0).UTC()

var (
	ErrNoDockerfile    = errors.New("dcs: build context has no Dockerfile")
	ErrContextTooLarge = errors.New("dcs: build context exceeds the maximum size")
	ErrUnsafePath      = errors.New("dcs: build context contains an unsafe path")
	ErrDigestMismatch  = errors.New("dcs: build context digest does not match")
)

// PackBuildContext deterministically tars+gzips the files into a build context
// blob. Deterministic (sorted paths, fixed timestamps) so the SAME files always
// produce the SAME digest -- content addressing depends on it, and it means two
// deployers submitting identical source dedup to one blob in the store.
func PackBuildContext(files []BuildFile) ([]byte, error) {
	hasDockerfile := false
	total := 0
	// Copy + sort so the archive order is stable regardless of caller order.
	sorted := make([]BuildFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	for _, f := range sorted {
		clean := path.Clean("/" + f.Path)
		if clean == "/Dockerfile" {
			hasDockerfile = true
		}
		if !safeRelPath(f.Path) {
			return nil, fmt.Errorf("%w: %q", ErrUnsafePath, f.Path)
		}
		total += len(f.Data)
	}
	if !hasDockerfile {
		return nil, ErrNoDockerfile
	}
	if total > MaxBuildContextBytes {
		return nil, ErrContextTooLarge
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range sorted {
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{
			Name: f.Path, Mode: mode, Size: int64(len(f.Data)),
			// Fixed metadata: identical files must hash identically. Real mtimes
			// or uid/gid would make the digest nondeterministic.
			ModTime: fixedModTime, Uid: 0, Gid: 0, Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnpackBuildContext reverses PackBuildContext, enforcing the same size and path
// safety on the way OUT -- because the blob may have arrived from an untrusted
// peer, and a malicious archive is the classic way to escape a build directory.
func UnpackBuildContext(blob []byte) ([]BuildFile, error) {
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var files []BuildFile
	total := 0
	hasDockerfile := false
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			// Only regular files. No symlinks (a symlink to /etc/shadow in a
			// build context is a known escape), no devices, no hardlinks.
			return nil, fmt.Errorf("%w: non-regular entry %q", ErrUnsafePath, header.Name)
		}
		if !safeRelPath(header.Name) {
			return nil, fmt.Errorf("%w: %q", ErrUnsafePath, header.Name)
		}
		total += int(header.Size)
		if total > MaxBuildContextBytes {
			return nil, ErrContextTooLarge
		}
		data := make([]byte, header.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return nil, err
		}
		if path.Clean("/"+header.Name) == "/Dockerfile" {
			hasDockerfile = true
		}
		files = append(files, BuildFile{Path: header.Name, Mode: header.Mode, Data: data})
	}
	if !hasDockerfile {
		return nil, ErrNoDockerfile
	}
	return files, nil
}

// StoreBuildContext packs the files and stores the blob in the DHT-backed shard
// store, returning the digest a deploy request references.
func StoreBuildContext(ctx context.Context, blobs BlobStore, files []BuildFile) (string, error) {
	blob, err := PackBuildContext(files)
	if err != nil {
		return "", err
	}
	return blobs.PutBlob(ctx, blob)
}

// FetchBuildContext retrieves a build context by digest from the shard store and
// unpacks it, verifying the digest end to end. A worker calls this before
// building. A mismatch means a corrupt or tampered blob -- discard and refetch.
func FetchBuildContext(ctx context.Context, blobs BlobStore, digest string) ([]BuildFile, error) {
	blob, err := blobs.GetBlob(ctx, digest)
	if err != nil {
		return nil, err
	}
	if got := BlobDigest(blob); got != digest {
		return nil, fmt.Errorf("%w: got %s want %s", ErrDigestMismatch, got, digest)
	}
	return UnpackBuildContext(blob)
}

// BlobDigest is the canonical "sha256:<hex>" content address for a blob.
func BlobDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// safeRelPath rejects anything that could write outside the build directory:
// absolute paths, "..", empty, or backslashes (a Windows-style separator that
// path.Clean does not treat as a separator, so it can smuggle traversal).
func safeRelPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	if p != path.Clean(p) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}
