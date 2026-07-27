package p2p

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	coretransport "github.com/libp2p/go-libp2p/core/transport"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	syndii2p "github.com/syndichan/maniwani/storage-client/internal/i2p"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

const (
	ProtocolID       = protocol.ID("/syndichan/storage/1.0.0")
	maxHeaderBytes   = 64 << 10
	maxNetworkShard  = 32 << 20
	bootstrapRefresh = 15 * time.Minute
	heartbeatRefresh = 5 * time.Minute
	// An I2P dial is nothing like a TCP dial. Before libp2p's Noise handshake
	// can even begin, the router must look the destination's LeaseSet up from
	// the floodfills, build or reuse a tunnel pair, and complete several
	// garlic-encrypted round trips -- each hop adding its own latency. A cold
	// dial routinely takes 20-60 seconds.
	//
	// This was 10 seconds for both cases, which expired during the LeaseSet
	// lookup. Every bootstrap attempt failed with "all dials failed" no matter
	// how healthy both routers were: correct destination, established tunnels,
	// unfirewalled router, and still no peer ever connected.
	i2pDialTimeout    = 2 * time.Minute
	directDialTimeout = 10 * time.Second
	// Retry cadence WHILE STILL PEERLESS. A freshly installed I2P router needs
	// 10-30 minutes to integrate into the network, so the first attempts are
	// expected to fail. At the 15-minute steady-state cadence that is roughly
	// one doomed attempt per 15 minutes, and a new node can sit peerless for
	// hours. Retry quickly until the first peer sticks, then back off.
	bootstrapRetry = 60 * time.Second
	// Backfill cadence for shards stored before any peer existed. Deliberately
	// unhurried and small: each shard needs a coordinator lease over I2P before
	// it can be placed, so this is a trickle, not a flush.
	replicateInterval = 5 * time.Minute
	replicateBatch    = 5
	StorageUserAgent  = "Syndichan-Storage-Client/1.0"
)

var heartbeatEndpoint = "https://syndichan.org/api/v1/storage/nodes/heartbeat"

// A var, like heartbeatEndpoint above, so tests can point the lease exchange at
// a local server instead of reaching the production coordinator.
var leaseURL = "https://syndichan.org/api/v1/storage/leases"

type BootstrapDocument struct {
	Version              int       `json:"version"`
	Peers                []string  `json:"peers"`
	CoordinatorPublicKey string    `json:"coordinator_public_key"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type Lease struct {
	Version   int    `json:"version"`
	ObjectID  string `json:"object_id"`
	ShardID   string `json:"shard_id"`
	Size      int64  `json:"size"`
	Recipient string `json:"recipient"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
}

type requestHeader struct {
	Operation string `json:"operation"`
	ShardID   string `json:"shard_id"`
	ObjectID  string `json:"object_id,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Lease     *Lease `json:"lease,omitempty"`
}

type responseHeader struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Present bool   `json:"present,omitempty"`
	Size    int64  `json:"size,omitempty"`
}

type leaseRequest struct {
	Version   int    `json:"version"`
	Requester string `json:"requester"`
	Recipient string `json:"recipient"`
	ObjectID  string `json:"object_id"`
	ShardID   string `json:"shard_id"`
	Size      int64  `json:"size"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
}

type heartbeatRequest struct {
	Version       int    `json:"version"`
	NodeID        string `json:"node_id"`
	Timestamp     int64  `json:"timestamp"`
	Nonce         string `json:"nonce"`
	CapacityBytes int64  `json:"capacity_bytes"`
	Platform      string `json:"platform"`
}

type Node struct {
	host           host.Host
	dht            *dht.IpfsDHT
	store          *store.Store
	logger         *log.Logger
	bootstrap      string
	http           *http.Client
	directHTTP     *http.Client
	keyMu          sync.RWMutex
	coordKey       ed25519.PublicKey
	peerMu         sync.RWMutex
	bootstrapPeers map[peer.ID]struct{}
	i2pOnly        bool
	replicaMu      sync.Mutex
	replicated     map[string]struct{}
	// cacheOnly nodes serve their own content but host nothing for anyone
	// else; see the "store" branch of handleStream.
	cacheOnly bool
}

// SetCacheOnly makes this node refuse to host other peers' shards. Set once at
// startup, before the stream handler can see traffic.
func (n *Node) SetCacheOnly(value bool) { n.cacheOnly = value }

func Open(ctx context.Context, dataDir, samAddr, httpProxy string, storage *store.Store, logger *log.Logger) (*Node, error) {
	identity, err := loadOrCreateIdentity(filepath.Join(dataDir, "p2p.key"))
	if err != nil {
		return nil, err
	}
	session, err := syndii2p.Open(ctx, samAddr, filepath.Join(dataDir, "i2p.destination"))
	if err != nil {
		return nil, err
	}
	local, err := syndii2p.Multiaddr(session.Base32())
	if err != nil {
		session.Close()
		return nil, err
	}
	h, err := libp2p.New(
		libp2p.Identity(identity),
		libp2p.NoTransports,
		libp2p.Transport(func(upgrader coretransport.Upgrader, rcmgr network.ResourceManager) (coretransport.Transport, error) {
			return syndii2p.NewTransport(upgrader, rcmgr, session)
		}),
		libp2p.ListenAddrs(local),
		libp2p.DisableRelay(),
		libp2p.AddrsFactory(i2pAddressesOnly),
	)
	if err != nil {
		session.Close()
		return nil, err
	}
	proxyURL, err := url.Parse(httpProxy)
	if err != nil {
		h.Close()
		return nil, err
	}
	httpClient := &http.Client{
		Timeout: 75 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	directHTTP := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			// Intentionally direct: heartbeat presence is the one connection the
			// user explicitly requires to bypass I2P. A nil Proxy also prevents
			// HTTP_PROXY/HTTPS_PROXY environment variables from changing that.
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	return finishNode(ctx, h, storage, logger, httpClient, directHTTP, true, true)
}

func openNode(ctx context.Context, dataDir string, listen []string, storage *store.Store, logger *log.Logger, useCoordinatorBootstrap bool) (*Node, error) {
	identity, err := loadOrCreateIdentity(filepath.Join(dataDir, "p2p.key"))
	if err != nil {
		return nil, err
	}
	h, err := libp2p.New(
		libp2p.Identity(identity),
		libp2p.ListenAddrStrings(listen...),
		libp2p.NATPortMap(),
		libp2p.EnableHolePunching(),
	)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
	}
	return finishNode(ctx, h, storage, logger, httpClient, httpClient, useCoordinatorBootstrap, false)
}

func finishNode(
	ctx context.Context,
	h host.Host,
	storage *store.Store,
	logger *log.Logger,
	httpClient *http.Client,
	directHTTP *http.Client,
	useCoordinatorBootstrap bool,
	i2pOnly bool,
) (*Node, error) {
	kad, err := dht.New(h, dht.Mode(dht.ModeAutoServer))
	if err != nil {
		h.Close()
		return nil, err
	}
	n := &Node{
		host: h, dht: kad, store: storage, logger: logger, bootstrap: config.BootstrapURL,
		bootstrapPeers: make(map[peer.ID]struct{}), http: httpClient,
		directHTTP: directHTTP, i2pOnly: i2pOnly,
		replicated: make(map[string]struct{}),
	}
	h.SetStreamHandler(ProtocolID, n.handleStream)
	if err := kad.Bootstrap(ctx); err != nil {
		h.Close()
		return nil, err
	}
	if useCoordinatorBootstrap {
		go n.bootstrapLoop(ctx)
	}
	if i2pOnly {
		go n.heartbeatLoop(ctx)
	}
	go n.ReplicateStored(ctx)
	return n, nil
}

func i2pAddressesOnly(values []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	result := make([]multiaddr.Multiaddr, 0, len(values))
	for _, value := range values {
		if syndii2p.IsI2PAddr(value) {
			result = append(result, value)
		}
	}
	return result
}

func (n *Node) Close() error {
	_ = n.dht.Close()
	return n.host.Close()
}

func (n *Node) ID() string { return n.host.ID().String() }

// PeerCount is how many peers this node is connected to RIGHT NOW. Volunteers
// are dial-in only behind NAT, so this drops to zero whenever the connection
// lapses and recovers on the next bootstrap retry -- it is a live gauge, not a
// count of everyone who has ever joined.
func (n *Node) PeerCount() int { return len(n.host.Network().Peers()) }

func (n *Node) Addresses() []string {
	result := make([]string, 0, len(n.host.Addrs()))
	for _, addr := range n.host.Addrs() {
		result = append(result, addr.String()+"/p2p/"+n.host.ID().String())
	}
	return result
}

func loadOrCreateIdentity(path string) (crypto.PrivKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(raw)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		return nil, err
	}
	raw, err = crypto.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func (n *Node) bootstrapLoop(ctx context.Context) {
	for {
		n.refreshBootstrap(ctx)
		// Pace on OUTCOME, not on a fixed clock. While the node has no live
		// bootstrap peer it has no network at all, so retrying is the only
		// useful thing it can do; once a peer sticks, the document only needs
		// an occasional refresh.
		delay := bootstrapRefresh
		if n.liveBootstrapPeers() == 0 {
			delay = bootstrapRetry
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// liveBootstrapPeers counts bootstrap peers there is currently a connection to.
// Membership in n.bootstrapPeers only records that a dial once succeeded, which
// stays true long after the connection has dropped -- so it cannot be used to
// decide whether the node still has a network.
func (n *Node) liveBootstrapPeers() int {
	n.peerMu.Lock()
	ids := make([]peer.ID, 0, len(n.bootstrapPeers))
	for id := range n.bootstrapPeers {
		ids = append(ids, id)
	}
	n.peerMu.Unlock()
	live := 0
	for _, id := range ids {
		if n.host.Network().Connectedness(id) == network.Connected {
			live++
		}
	}
	return live
}

func (n *Node) heartbeatLoop(ctx context.Context) {
	n.sendHeartbeat(ctx, heartbeatEndpoint)
	ticker := time.NewTicker(heartbeatRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.sendHeartbeat(ctx, heartbeatEndpoint)
		}
	}
}

func (n *Node) sendHeartbeat(ctx context.Context, endpoint string) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return
	}
	payload := heartbeatRequest{
		Version: 1, NodeID: n.host.ID().String(), Timestamp: time.Now().UTC().Unix(),
		Nonce:         base64.RawURLEncoding.EncodeToString(nonceBytes),
		CapacityBytes: n.store.Capacity(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	privateKey := n.host.Peerstore().PrivKey(n.host.ID())
	if privateKey == nil {
		n.logger.Printf("storage heartbeat skipped: node identity unavailable")
		return
	}
	signature, err := privateKey.Sign(body)
	if err != nil {
		n.logger.Printf("storage heartbeat signing failed: %v", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", StorageUserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Syndichan-Node", n.host.ID().String())
	req.Header.Set("X-Syndichan-Signature", base64.RawStdEncoding.EncodeToString(signature))
	resp, err := n.directHTTP.Do(req)
	if err != nil {
		n.logger.Printf("storage heartbeat unavailable: %v", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHeaderBytes))
	if resp.StatusCode != http.StatusOK {
		n.logger.Printf("storage heartbeat returned HTTP %d", resp.StatusCode)
	}
}

func (n *Node) refreshBootstrap(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.bootstrap, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/json")
	resp, err := n.http.Do(req)
	if err != nil {
		n.logger.Printf("bootstrap unavailable; local services remain active: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		n.logger.Printf("bootstrap returned HTTP %d", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}
	var document BootstrapDocument
	if err := json.Unmarshal(body, &document); err != nil || document.Version != 1 {
		n.logger.Printf("bootstrap document rejected")
		return
	}
	if !document.ExpiresAt.IsZero() && time.Now().After(document.ExpiresAt) {
		n.logger.Printf("bootstrap document expired")
		return
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(document.CoordinatorPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		n.logger.Printf("bootstrap coordinator key rejected")
		return
	}
	n.keyMu.Lock()
	n.coordKey = append(ed25519.PublicKey(nil), publicKey...)
	n.keyMu.Unlock()
	for _, value := range document.Peers {
		address, err := multiaddr.NewMultiaddr(value)
		if err != nil || n.i2pOnly && !syndii2p.IsI2PAddr(address) {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(address)
		if err != nil || info.ID == n.host.ID() {
			continue
		}
		info.Addrs = n.acceptablePeerAddrs(info.Addrs)
		if len(info.Addrs) == 0 {
			continue
		}
		dialTimeout := directDialTimeout
		if n.i2pOnly {
			dialTimeout = i2pDialTimeout
		}
		connectCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		err = n.host.Connect(connectCtx, *info)
		cancel()
		if err != nil {
			n.logger.Printf("bootstrap peer %s unavailable: %v", info.ID, err)
			continue
		}
		// Worth a line of its own: until this appears, nothing can be stored on
		// or fetched from the network, and the only other evidence was the
		// absence of a message.
		n.logger.Printf("bootstrap peer %s connected", info.ID)
		n.host.ConnManager().Protect(info.ID, "syndichan-bootstrap")
		n.peerMu.Lock()
		n.bootstrapPeers[info.ID] = struct{}{}
		n.peerMu.Unlock()
	}
}

func leaseMessage(lease Lease) []byte {
	return []byte(fmt.Sprintf(
		"syndichan-storage-lease-v1\n%d\n%s\n%s\n%d\n%s\n%d",
		lease.Version, lease.ObjectID, lease.ShardID, lease.Size, lease.Recipient, lease.ExpiresAt,
	))
}

func (n *Node) validateLease(lease *Lease, header requestHeader) error {
	if lease == nil || lease.Version != 1 {
		return errors.New("coordinator lease required")
	}
	if lease.ObjectID != header.ObjectID || lease.ShardID != header.ShardID || lease.Size != header.Size {
		return errors.New("lease does not match shard request")
	}
	if lease.Recipient != "" && lease.Recipient != n.host.ID().String() {
		return errors.New("lease was issued to another node")
	}
	now := time.Now().Unix()
	if lease.ExpiresAt <= now || lease.ExpiresAt > now+3600 {
		return errors.New("lease is expired or excessively long")
	}
	signature, err := base64.RawStdEncoding.DecodeString(lease.Signature)
	if err != nil {
		return errors.New("invalid lease signature encoding")
	}
	n.keyMu.RLock()
	key := append(ed25519.PublicKey(nil), n.coordKey...)
	n.keyMu.RUnlock()
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, leaseMessage(*lease), signature) {
		return errors.New("invalid coordinator lease signature")
	}
	return nil
}

func (n *Node) handleStream(stream network.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(stream)
	var header requestHeader
	if err := readJSONFrame(reader, &header); err != nil {
		writeJSONFrame(stream, responseHeader{Error: "invalid request"})
		return
	}
	switch header.Operation {
	case "have":
		_, err := n.store.ReadShard(header.ShardID)
		writeJSONFrame(stream, responseHeader{OK: true, Present: err == nil})
	case "get":
		value, err := n.store.ReadShard(header.ShardID)
		if err != nil {
			writeJSONFrame(stream, responseHeader{Error: "not found"})
			return
		}
		if err := writeJSONFrame(stream, responseHeader{OK: true, Size: int64(len(value))}); err == nil {
			_, _ = stream.Write(value)
		}
	case "store":
		if n.cacheOnly {
			// This node contributes no storage to the network. It keeps only
			// what it caches of its OWN content, so it must not become a host
			// for other peers' shards -- accepting them would make its disk
			// grow with the network rather than with the site.
			writeJSONFrame(stream, responseHeader{Error: "node is cache-only and does not host shards"})
			return
		}
		if header.Size <= 0 || header.Size > maxNetworkShard || len(header.ShardID) != 64 {
			writeJSONFrame(stream, responseHeader{Error: "invalid shard size or ID"})
			return
		}
		if err := n.validateLease(header.Lease, header); err != nil {
			writeJSONFrame(stream, responseHeader{Error: err.Error()})
			return
		}
		if err := writeJSONFrame(stream, responseHeader{OK: true}); err != nil {
			return
		}
		value := make([]byte, header.Size)
		if _, err := io.ReadFull(reader, value); err != nil {
			return
		}
		err := n.store.PutRemoteShard(store.RemoteShard{
			ID: header.ShardID, ObjectID: header.ObjectID, Size: header.Size,
		}, value)
		if err != nil {
			writeJSONFrame(stream, responseHeader{Error: err.Error()})
			return
		}
		writeJSONFrame(stream, responseHeader{OK: true})
		go n.Provide(context.Background(), header.ShardID)
	default:
		writeJSONFrame(stream, responseHeader{Error: "unsupported operation"})
	}
}

func cidForShard(id string) (cid.Cid, error) {
	digest, err := hex.DecodeString(id)
	if err != nil || len(digest) != 32 {
		return cid.Undef, errors.New("invalid shard ID")
	}
	mh, err := multihash.Encode(digest, multihash.SHA2_256)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, mh), nil
}

func (n *Node) Provide(ctx context.Context, shardID string) error {
	contentID, err := cidForShard(shardID)
	if err != nil {
		return err
	}
	return n.dht.Provide(ctx, contentID, true)
}

// advertiseInterval re-announces stored shards periodically. DHT provider
// records expire anyway, so a one-shot announce would go stale even in the
// happy case.
const advertiseInterval = 10 * time.Minute

// AdvertiseStored announces every locally stored shard to the DHT, and keeps
// doing so.
//
// It used to run exactly once, at startup, and return. That is precisely when it
// cannot work: I2P tunnels take minutes to build, so the routing table is still
// empty and every announce fails with "failed to find any peer in table". The
// backlog was then never advertised again for the lifetime of the process, so a
// node that had accumulated shards before meeting a peer stayed invisible --
// peers could not discover the content it was holding no matter how healthy the
// network later became.
func (n *Node) AdvertiseStored(ctx context.Context) {
	for {
		n.advertiseOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(advertiseInterval):
		}
	}
}

func (n *Node) advertiseOnce(ctx context.Context) {
	ids, err := n.store.ListShardIDs()
	if err != nil {
		n.logger.Printf("could not enumerate stored shards: %v", err)
		return
	}
	if len(n.host.Network().Peers()) == 0 {
		// Nothing to announce to. Say so ONCE rather than emitting a line per
		// shard -- the old behaviour buried every other message under thousands
		// of identical "failed to find any peer in table" errors.
		n.logger.Printf("advertise: %d shard(s) pending, no peers connected yet", len(ids))
		return
	}
	announced, failed := 0, 0
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		provideCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := n.Provide(provideCtx, id)
		cancel()
		if err != nil {
			failed++
			if failed <= 3 {
				n.logger.Printf("could not advertise shard %s: %v", id[:12], err)
			}
			continue
		}
		announced++
	}
	n.logger.Printf("advertise: %d announced, %d failed, of %d stored", announced, failed, len(ids))
}

// ReplicateStored pushes the shards of objects that were stored while this node
// had no peers.
//
// DistributeManifest only ever runs at PUT time. Anything written before a peer
// connected -- which, on the server's own node, was every single object -- took
// the "retained locally; no storage peers are connected" branch and was never
// sent anywhere afterwards. AdvertiseStored does NOT make up for that: it
// publishes DHT provider records saying "I have this shard", not the bytes.
//
// The visible consequence was a node that looked entirely healthy -- peered,
// advertising, heartbeating -- while every volunteer's shard directory stayed
// empty, because no code path existed that would ever push an already-stored
// shard to a peer that showed up later.
func (n *Node) ReplicateStored(ctx context.Context) {
	for {
		timer := time.NewTimer(replicateInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		n.replicateOnce(ctx)
	}
}

func (n *Node) replicateOnce(ctx context.Context) {
	if len(n.host.Network().Peers()) == 0 {
		return
	}
	buckets, err := n.store.ListBuckets()
	if err != nil {
		n.logger.Printf("replicate: cannot list buckets: %v", err)
		return
	}
	pushed, remaining := 0, 0
	for _, bucket := range buckets {
		manifests, err := n.store.ListObjects(bucket, "")
		if err != nil {
			continue
		}
		for _, manifest := range manifests {
			if ctx.Err() != nil {
				return
			}
			n.replicaMu.Lock()
			_, already := n.replicated[manifest.ObjectID]
			n.replicaMu.Unlock()
			if already {
				continue
			}
			// Bounded per pass. Every shard costs a coordinator lease fetched
			// over the I2P outproxy plus a stream to the peer, so draining a
			// large backlog in one pass would stall the node for hours and bury
			// the lease service. Count the rest so the backlog is visible.
			if pushed >= replicateBatch {
				remaining++
				continue
			}
			n.DistributeManifest(ctx, manifest)
			n.replicaMu.Lock()
			n.replicated[manifest.ObjectID] = struct{}{}
			n.replicaMu.Unlock()
			pushed++
		}
	}
	if pushed > 0 || remaining > 0 {
		n.logger.Printf("replicate: pushed %d object(s), %d awaiting backfill", pushed, remaining)
	}
}

func (n *Node) DistributeManifest(ctx context.Context, manifest store.Manifest) {
	peers := n.host.Network().Peers()
	if len(peers) == 0 {
		n.logger.Printf("object %s retained locally; no storage peers are connected", manifest.ObjectID[:12])
		return
	}
	limit := make(chan struct{}, 4)
	var wg sync.WaitGroup
	shardNumber := 0
	for _, chunk := range manifest.Chunks {
		for _, ref := range chunk.Shards {
			target := peers[shardNumber%len(peers)]
			shardNumber++
			if target == n.host.ID() {
				continue
			}
			wg.Add(1)
			go func(target peer.ID, ref store.ShardRef) {
				defer wg.Done()
				select {
				case limit <- struct{}{}:
					defer func() { <-limit }()
				case <-ctx.Done():
					return
				}
				value, err := n.store.ReadShard(ref.ID)
				if err != nil {
					return
				}
				lease, err := n.requestLease(ctx, target, manifest.ObjectID, ref.ID, int64(len(value)))
				if err != nil {
					n.logger.Printf("coordinator did not lease shard %s: %v", ref.ID[:12], err)
					return
				}
				if err := n.storeOnPeer(ctx, target, manifest.ObjectID, ref.ID, value, lease); err != nil {
					n.logger.Printf("peer %s rejected shard %s: %v", target, ref.ID[:12], err)
				}
			}(target, ref)
		}
	}
	wg.Wait()
}

func (n *Node) requestLease(ctx context.Context, target peer.ID, objectID, shardID string, size int64) (*Lease, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	payload := leaseRequest{
		Version: 1, Requester: n.host.ID().String(), Recipient: target.String(),
		ObjectID: objectID, ShardID: shardID, Size: size,
		Timestamp: time.Now().UTC().Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	privateKey := n.host.Peerstore().PrivKey(n.host.ID())
	if privateKey == nil {
		return nil, errors.New("node identity unavailable")
	}
	signature, err := privateKey.Sign(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, leaseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Syndichan-Node", n.host.ID().String())
	req.Header.Set("X-Syndichan-Signature", base64.RawStdEncoding.EncodeToString(signature))
	resp, err := n.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lease service returned HTTP %d", resp.StatusCode)
	}
	var lease Lease
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHeaderBytes)).Decode(&lease); err != nil {
		return nil, err
	}
	header := requestHeader{ObjectID: objectID, ShardID: shardID, Size: size}
	if err := n.validateLeaseForRecipient(&lease, header, target.String()); err != nil {
		return nil, err
	}
	return &lease, nil
}

func (n *Node) validateLeaseForRecipient(lease *Lease, header requestHeader, recipient string) error {
	if lease == nil || lease.Version != 1 || lease.ObjectID != header.ObjectID ||
		lease.ShardID != header.ShardID || lease.Size != header.Size ||
		lease.Recipient != recipient {
		return errors.New("lease fields do not match storage request")
	}
	now := time.Now().Unix()
	if lease.ExpiresAt <= now || lease.ExpiresAt > now+3600 {
		return errors.New("lease is expired or excessively long")
	}
	signature, err := base64.RawStdEncoding.DecodeString(lease.Signature)
	if err != nil {
		return err
	}
	n.keyMu.RLock()
	key := append(ed25519.PublicKey(nil), n.coordKey...)
	n.keyMu.RUnlock()
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, leaseMessage(*lease), signature) {
		return errors.New("invalid coordinator signature")
	}
	return nil
}

func (n *Node) storeOnPeer(ctx context.Context, target peer.ID, objectID, shardID string, value []byte, lease *Lease) error {
	stream, err := n.host.NewStream(ctx, target, ProtocolID)
	if err != nil {
		return err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{
		Operation: "store", ObjectID: objectID, ShardID: shardID,
		Size: int64(len(value)), Lease: lease,
	}); err != nil {
		return err
	}
	reader := bufio.NewReader(stream)
	var ready responseHeader
	if err := readJSONFrame(reader, &ready); err != nil {
		return err
	}
	if !ready.OK {
		return errors.New(ready.Error)
	}
	if _, err := stream.Write(value); err != nil {
		return err
	}
	var stored responseHeader
	if err := readJSONFrame(reader, &stored); err != nil {
		return err
	}
	if !stored.OK {
		return errors.New(stored.Error)
	}
	return nil
}

func (n *Node) FetchShard(ctx context.Context, shardID string) ([]byte, error) {
	if value, err := n.store.ReadShard(shardID); err == nil {
		return value, nil
	}
	seen := make(map[peer.ID]struct{})
	n.peerMu.RLock()
	var trusted []peer.ID
	for candidate := range n.bootstrapPeers {
		trusted = append(trusted, candidate)
	}
	n.peerMu.RUnlock()
	for _, candidate := range trusted {
		seen[candidate] = struct{}{}
		if value, err := n.fetchFromPeer(ctx, candidate, shardID); err == nil {
			return value, nil
		}
	}
	for _, candidate := range n.host.Network().Peers() {
		if _, exists := seen[candidate]; exists || candidate == n.host.ID() {
			continue
		}
		seen[candidate] = struct{}{}
		if value, err := n.fetchFromPeer(ctx, candidate, shardID); err == nil {
			return value, nil
		}
	}
	contentID, err := cidForShard(shardID)
	if err != nil {
		return nil, err
	}
	for provider := range n.dht.FindProvidersAsync(ctx, contentID, 20) {
		if provider.ID == n.host.ID() {
			continue
		}
		if _, exists := seen[provider.ID]; exists {
			continue
		}
		seen[provider.ID] = struct{}{}
		provider.Addrs = n.acceptablePeerAddrs(provider.Addrs)
		if len(provider.Addrs) == 0 {
			continue
		}
		if err := n.host.Connect(ctx, provider); err != nil {
			continue
		}
		if value, err := n.fetchFromPeer(ctx, provider.ID, shardID); err == nil {
			return value, nil
		}
	}
	return nil, errors.New("no peer supplied a valid shard")
}

func (n *Node) acceptablePeerAddrs(values []multiaddr.Multiaddr) []multiaddr.Multiaddr {
	if !n.i2pOnly {
		return values
	}
	return i2pAddressesOnly(values)
}

func (n *Node) fetchFromPeer(ctx context.Context, candidate peer.ID, shardID string) ([]byte, error) {
	stream, err := n.host.NewStream(ctx, candidate, ProtocolID)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeJSONFrame(stream, requestHeader{Operation: "get", ShardID: shardID}); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(stream)
	var response responseHeader
	if err := readJSONFrame(reader, &response); err != nil || !response.OK ||
		response.Size <= 0 || response.Size > maxNetworkShard {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("peer does not have shard")
	}
	value := make([]byte, response.Size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, err
	}
	if fmt.Sprintf("%x", sha256Sum(value)) != shardID {
		return nil, errors.New("peer returned corrupt shard")
	}
	return value, nil
}

func sha256Sum(value []byte) [32]byte {
	return sha256.Sum256(value)
}

func readJSONFrame(reader *bufio.Reader, target any) error {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return err
	}
	if size == 0 || size > maxHeaderBytes {
		return errors.New("invalid frame size")
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return err
	}
	return json.Unmarshal(value, target)
}

func writeJSONFrame(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > maxHeaderBytes {
		return errors.New("frame too large")
	}
	if err := binary.Write(writer, binary.BigEndian, uint32(len(encoded))); err != nil {
		return err
	}
	_, err = writer.Write(encoded)
	return err
}
