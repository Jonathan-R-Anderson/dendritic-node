package store

import "time"

const FormatVersion = 1

type ShardRef struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
	Size  int    `json:"size"`
}

type ChunkManifest struct {
	Index        int        `json:"index"`
	Nonce        []byte     `json:"nonce"`
	CipherLength int        `json:"cipher_length"`
	ShardSize    int        `json:"shard_size"`
	Shards       []ShardRef `json:"shards"`
}

type Manifest struct {
	Version      int             `json:"version"`
	ObjectID     string          `json:"object_id"`
	Bucket       string          `json:"bucket"`
	Key          string          `json:"key"`
	ContentType  string          `json:"content_type"`
	PlainSize    int64           `json:"plain_size"`
	PlainSHA256  string          `json:"plain_sha256"`
	WrappedKey   []byte          `json:"wrapped_key"`
	WrapNonce    []byte          `json:"wrap_nonce"`
	DataShards   int             `json:"data_shards"`
	ParityShards int             `json:"parity_shards"`
	ChunkBytes   int             `json:"chunk_bytes"`
	Chunks       []ChunkManifest `json:"chunks"`
	CreatedAt    time.Time       `json:"created_at"`
}

type StoredItem struct {
	Kind        string    `json:"kind"`
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	ContentType string    `json:"content_type,omitempty"`
	Size        int64     `json:"size"`
	LocalObject bool      `json:"local_object"`
	Rejected    bool      `json:"rejected"`
	CreatedAt   time.Time `json:"created_at"`
}

type RemoteShard struct {
	ID        string    `json:"id"`
	ObjectID  string    `json:"object_id"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}
