package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/gateway"
	gatewayfrontend "github.com/syndichan/maniwani/storage-client/internal/gateway/frontend"
	"github.com/syndichan/maniwani/storage-client/internal/heartbeat"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
	"github.com/syndichan/maniwani/storage-client/internal/s3api"
	"github.com/syndichan/maniwani/storage-client/internal/store"
	"github.com/syndichan/maniwani/storage-client/internal/ui"
)

var runTray func(context.Context, string, *log.Logger, func())

func main() {
	var configFile string
	var dataDir string
	var showCredentials bool
	var s3Listen string
	var cacheOnly bool
	var tlsCert string
	var tlsKey string
	var s3AccessKeyFile string
	var s3SecretKeyFile string
	var capacityGiB float64
	var gatewayStatus bool
	var gatewayEnable bool
	var gatewayDisable bool
	var gatewayOnly bool
	var probeOnly bool
	flag.StringVar(&configFile, "config", "", "path to config.json")
	// Data location is deliberately separate from config location. Previously
	// DataDir was always the config file's own directory, so putting shards on
	// a big secondary drive meant relocating the config (and its keys) too.
	// This lets the small, secret config stay in the OS config dir while the
	// bulk shard store lives wherever there is room.
	flag.BoolVar(&showCredentials, "show-credentials", false,
		"print this node's local S3 endpoint and credentials, then exit")
	flag.StringVar(&dataDir, "data-dir", "",
		"directory for shard/object storage (default: the config file's directory)")
	// Serving the S3 gateway off loopback is a deliberate, TLS-gated act:
	// Validate() refuses a non-loopback S3Listen unless both cert and key are
	// set. These flags exist so a container deployment can express that without
	// hand-editing config.json, and they persist like -data-dir.
	flag.BoolVar(&cacheOnly, "cache-only", false,
		"serve only our own cached content; refuse to host other peers' shards")
	flag.StringVar(&s3Listen, "s3-listen", "",
		"address for the S3 gateway (non-loopback requires -tls-cert/-tls-key)")
	flag.StringVar(&tlsCert, "tls-cert", "", "TLS certificate for a non-loopback S3 gateway")
	flag.StringVar(&tlsKey, "tls-key", "", "TLS private key for a non-loopback S3 gateway")
	flag.StringVar(&s3AccessKeyFile, "s3-access-key-file", "",
		"read the S3 access key from this file and persist it in the secure config")
	flag.StringVar(&s3SecretKeyFile, "s3-secret-key-file", "",
		"read the S3 secret key from this file and persist it in the secure config")
	flag.Float64Var(&capacityGiB, "capacity-gib", 0,
		"initial local shard allocation in GiB when the store has no saved choice")
	flag.BoolVar(&gatewayStatus, "gateway-status", false, "show persisted gateway configuration, then exit")
	flag.BoolVar(&gatewayEnable, "gateway-enable", false, "enable configured volunteer gateway mode")
	flag.BoolVar(&gatewayDisable, "gateway-disable", false, "disable volunteer gateway mode")
	flag.BoolVar(&gatewayOnly, "gateway-only", false,
		"run gateway/probe services without storage sharing, S3, dashboard, or I2P")
	flag.BoolVar(&probeOnly, "probe-only", false,
		"run only a signed verification probe; no storage, I2P, S3, or dashboard")
	flag.Parse()

	logger := log.New(os.Stderr, "syndichan-node ", log.LstdFlags|log.LUTC)

	// The runtime role is resolved from the command line FIRST, before the
	// configuration is read or validated. Everything downstream -- which
	// settings are required, which subsystems are constructed -- is derived
	// from it, so a dedicated gateway is never asked for storage settings it
	// will not use.
	role, err := runtimeRole(gatewayOnly, probeOnly)
	if err != nil {
		logger.Fatal(err)
	}
	// These four flags read or edit config.json and then return -- they never
	// reach subsystem startup below. Holding them to a runtime role would mean
	// a dedicated gateway could not inspect its own storage-free config file.
	if gatewayStatus || gatewayEnable || gatewayDisable || showCredentials {
		role = config.RoleManagement
	}
	path, err := config.ConfigPath(configFile)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Printf("runtime role: %s (%s)", role, role.Description())
	logger.Printf("loading configuration: %s", path)
	cfg, created, err := config.LoadOrCreate(path, role)
	if err != nil {
		logger.Fatalf("configuration %s: %v", path, err)
	}
	logger.Printf("configuration accepted for the %s role", role)
	if gatewayEnable && gatewayDisable {
		logger.Fatal("-gateway-enable and -gateway-disable are mutually exclusive")
	}
	if gatewayEnable || gatewayDisable {
		cfg.Gateway.Enabled = gatewayEnable
		if err := config.Save(path, cfg, role); err != nil {
			logger.Fatalf("persist gateway mode: %v", err)
		}
		fmt.Printf("Gateway mode enabled: %t\n", cfg.Gateway.Enabled)
		return
	}
	if gatewayStatus {
		fmt.Printf("Enabled: %t\nListen: %s:%d\nPublic hostname: %s\nProbe role: %t\nRegistration API: %s\n",
			cfg.Gateway.Enabled, cfg.Gateway.ListenAddress, cfg.Gateway.ListenPort,
			cfg.Gateway.PublicHostname, cfg.Gateway.ProbeEnabled, cfg.Gateway.RegistrationAPI)
		return
	}
	// Apply the listen/TLS overrides BEFORE anything validates or binds, and
	// persist them so a restart without the flags keeps the same posture rather
	// than silently reverting to loopback and going unreachable.
	if s3Listen != "" || tlsCert != "" || tlsKey != "" ||
		s3AccessKeyFile != "" || s3SecretKeyFile != "" {
		changed := false
		if s3Listen != "" && cfg.S3Listen != s3Listen {
			cfg.S3Listen = s3Listen
			changed = true
		}
		if tlsCert != "" && cfg.TLSCert != tlsCert {
			cfg.TLSCert = tlsCert
			changed = true
		}
		if tlsKey != "" && cfg.TLSKey != tlsKey {
			cfg.TLSKey = tlsKey
			changed = true
		}
		if s3AccessKeyFile != "" {
			value, err := readSecretFile(s3AccessKeyFile)
			if err != nil {
				logger.Fatalf("-s3-access-key-file: %v", err)
			}
			if cfg.AccessKey != value {
				cfg.AccessKey = value
				changed = true
			}
		}
		if s3SecretKeyFile != "" {
			value, err := readSecretFile(s3SecretKeyFile)
			if err != nil {
				logger.Fatalf("-s3-secret-key-file: %v", err)
			}
			if cfg.SecretKey != value {
				cfg.SecretKey = value
				changed = true
			}
		}
		if changed {
			if err := cfg.ValidateForRole(role); err != nil {
				logger.Fatalf("listen/TLS flags: %v", err)
			}
			if err := config.Save(path, cfg, role); err != nil {
				logger.Fatalf("persist listen/TLS flags: %v", err)
			}
			fmt.Fprintf(os.Stderr, "S3 gateway configured on %s\n", cfg.S3Listen)
		}
	}

	if dataDir != "" {
		resolved, err := filepath.Abs(dataDir)
		if err != nil {
			logger.Fatalf("-data-dir: %v", err)
		}
		// 0700: the store holds encrypted shards and local object manifests.
		if err := os.MkdirAll(resolved, 0700); err != nil {
			logger.Fatalf("-data-dir %s: %v", resolved, err)
		}
		if cfg.DataDir != resolved {
			cfg.DataDir = resolved
			// Persist it so restarts (and the systemd/LaunchAgent/Task
			// Scheduler entries in the README) do not need the flag repeated,
			// and so a forgotten flag cannot silently start a second, empty
			// store in the default location.
			if err := config.Save(path, cfg, role); err != nil {
				logger.Fatalf("persist -data-dir: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Storage directory set to %s\n", resolved)
		}
	}
	if capacityGiB != 0 {
		if math.IsNaN(capacityGiB) || math.IsInf(capacityGiB, 0) || capacityGiB <= 0 {
			logger.Fatal("-capacity-gib must be a positive finite number")
		}
		cfg.CapacityBytes = int64(math.Round(capacityGiB * (1 << 30)))
		if err := cfg.ValidateForRole(role); err != nil {
			logger.Fatalf("-capacity-gib: %v", err)
		}
	}
	noStorage := !role.NeedsStorage()
	if showCredentials {
		// Deliberate, explicit retrieval. The operator owns this machine and
		// this mode-0600 file, so this reveals nothing they cannot already
		// read -- it just saves them grepping JSON. It is opt-in so the secret
		// never lands somewhere it was not asked for.
		fmt.Printf("S3 endpoint:   %s\n", cfg.S3Listen)
		fmt.Printf("S3 access key: %s\n", cfg.AccessKey)
		fmt.Printf("S3 secret key: %s\n", cfg.SecretKey)
		return
	}
	if created {
		// Deliberately NOT printing the secret key.
		//
		// These credentials authenticate the LOOPBACK S3 gateway only. They are
		// never sent to the coordinator, never appear in a heartbeat or lease,
		// and the server does not need them -- peers exchange shards over I2P
		// under coordinator-signed leases, not S3.
		//
		// Echoing a secret to stderr puts it in shell scrollback, the systemd
		// journal, screen shares and screenshots -- exposure well beyond the
		// 0600 file it already lives in, for no benefit. Point at the file
		// instead, and let the operator ask for it explicitly.
		fmt.Fprintf(os.Stderr, "Created secure configuration: %s\n", path)
		fmt.Fprintf(os.Stderr, "S3 access key: %s\n", cfg.AccessKey)
		fmt.Fprintln(os.Stderr, "The secret key is in that mode-0600 file; it is not printed here.")
		fmt.Fprintln(os.Stderr, "Retrieve it deliberately with:  syndichan-node -show-credentials")
	}

	var storageNode *store.Store
	if noStorage {
		logger.Printf("storage subsystems skipped: shard store, S3, dashboard, I2P")
	}
	if !noStorage {
		logger.Printf("opening encrypted shard store: %s", filepath.Join(cfg.DataDir, "storage"))
		storageNode, err = store.Open(
			filepath.Join(cfg.DataDir, "storage"),
			cfg.DataShards, cfg.ParityShards, cfg.ChunkBytes, cfg.CapacityBytes,
		)
		if err != nil {
			logger.Fatal(err)
		}
		defer storageNode.Close()
		if err := storageNode.CleanupObjectPrefix(".syndichan-multipart/"); err != nil {
			logger.Fatal("clean interrupted multipart uploads: ", err)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var node *p2p.Node
	var signer gateway.Signer
	if noStorage {
		logger.Printf("loading standalone gateway identity from %s", cfg.DataDir)
		signer, err = gateway.LoadOrCreateFileIdentity(cfg.DataDir)
	} else {
		logger.Printf("starting I2P transport and storage DHT via SAM %s", cfg.I2PSAM)
		node, err = p2p.Open(ctx, cfg.DataDir, cfg.I2PSAM, cfg.I2PHTTPProxy, storageNode, logger)
	}
	if err != nil {
		logger.Fatal(err)
	}
	if node != nil {
		defer node.Close()
		signer = node
		node.SetGatewayState(cfg.Gateway.Enabled, false)
		// node is non-nil only in the storage role, which is also the only role
		// that sends the five-minute storage heartbeat.
		go node.RefreshHeartbeat(ctx)
	}
	if node != nil {
		gatewayValidator := gateway.DHTValidator{
			TrustedProbes:   cfg.Gateway.TrustedProbes,
			MinimumProbes:   cfg.Gateway.Verification.MinimumSuccessfulProbes,
			MinimumNetworks: cfg.Gateway.Verification.MinimumDistinctNetworks,
		}
		if err := node.ConfigureGatewayRecords(gatewayValidator); err != nil {
			logger.Fatal("configure gateway DHT records: ", err)
		}
	}
	// Shared with the presence heartbeat so a gateway that gains or loses
	// verification is reflected in the next beacon.
	var gatewayVerified atomic.Bool
	var gatewayManager *gateway.Manager
	var gatewayRegistry *gateway.RegistryClient
	if cfg.Gateway.Enabled {
		gatewayRegistry, err = gateway.NewRegistryClient(
			cfg.Gateway.RegistrationAPI, cfg.Gateway.PublicHostname, signer,
		)
		if err != nil {
			logger.Fatalf("gateway registration API: %v", err)
		}
		if cfg.Gateway.TLS.Mode == "acme" {
			reservationCtx, reservationCancel := context.WithTimeout(ctx, 6*time.Minute)
			var reservation gateway.HostnameReservation
			var reserveErr error
			for {
				reservation, reserveErr = gatewayRegistry.ReserveHostname(reservationCtx)
				var httpError *gateway.RegistryHTTPError
				if reserveErr == nil || !errors.As(reserveErr, &httpError) ||
					httpError.StatusCode != http.StatusServiceUnavailable {
					break
				}
				delay := httpError.RetryAfter
				if delay <= 0 {
					delay = 60 * time.Second
				}
				logger.Printf("gateway DNS reservation temporarily unavailable; retrying in %s", delay)
				timer := time.NewTimer(delay)
				select {
				case <-reservationCtx.Done():
					timer.Stop()
					reserveErr = reservationCtx.Err()
					break
				case <-timer.C:
					continue
				}
				break
			}
			if reserveErr == nil {
				reserveErr = gatewayRegistry.WaitForReservedDNS(
					reservationCtx, reservation, 3*time.Second,
				)
			}
			reservationCancel()
			if reserveErr != nil {
				logger.Fatalf("reserve gateway hostname before ACME: %v", reserveErr)
			}
			if cfg.Gateway.PublicHostname != reservation.Hostname {
				cfg.Gateway.PublicHostname = reservation.Hostname
				if saveErr := config.Save(path, cfg, role); saveErr != nil {
					logger.Fatalf("persist controller-assigned gateway hostname: %v", saveErr)
				}
			}
			logger.Printf("controller reserved %s for ACME", reservation.Hostname)
		}
	}
	if !noStorage && (cacheOnly || cfg.CacheOnly) {
		// Contribute no storage to the network: this node keeps only what it
		// caches of its own content, so its disk grows with the site rather
		// than with the number of peers.
		node.SetCacheOnly(true)
		logger.Printf("cache-only: this node will not host shards for other peers")
	}
	var s3Server, uiServer *http.Server
	if !noStorage {
		storageNode.SetShardFetcher(node.FetchShard)
		storageNode.SetShardAdvertiser(func(shardID string) {
			provideCtx, provideCancel := context.WithTimeout(ctx, 30*time.Second)
			defer provideCancel()
			if err := node.Provide(provideCtx, shardID); err != nil {
				logger.Printf("could not advertise shard %s: %v", shardID[:12], err)
			}
		})
		storageNode.SetObjectDistributor(func(manifest store.Manifest) {
			distributeCtx, distributeCancel := context.WithTimeout(ctx, 5*time.Minute)
			defer distributeCancel()
			node.DistributeManifest(distributeCtx, manifest)
		})
		go node.AdvertiseStored(ctx)

		s3Server = &http.Server{
			Addr: cfg.S3Listen, Handler: s3api.New(storageNode, cfg.AccessKey, cfg.SecretKey, logger),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Minute,
			WriteTimeout: 10 * time.Minute, IdleTimeout: 90 * time.Second,
			MaxHeaderBytes: 64 << 10,
		}
		uiServer = &http.Server{
			Addr: cfg.UIListen, Handler: ui.New(storageNode, node, logger),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
			MaxHeaderBytes: 32 << 10,
		}
	}
	var gatewayServer *http.Server
	var gatewayACMEHTTPServer *http.Server
	var gatewayListener net.Listener
	var gatewayService *gateway.Service
	var gatewayFrontend *gatewayfrontend.Server
	if cfg.Gateway.Enabled || cfg.Gateway.ProbeEnabled {
		gatewayService = gateway.NewService(signer, "1.0.0", cfg.Gateway.TrustedProbes, logger)
		gatewayService.SetTrustLoopbackProxy(cfg.Gateway.TLS.Mode == "reverse_proxy")
		// The storage DHT only exists in the storage role; a standalone
		// gateway or probe reports readiness from its listener alone.
		gatewayService.SetRequireDHTReady(!noStorage)
		if cfg.Gateway.ProbeEnabled {
			gatewayService.SetProber(&gateway.Prober{
				Signer: signer, Network: cfg.Gateway.ProbeNetwork,
				PublicHostname: cfg.Gateway.PublicHostname,
				Timeout:        time.Duration(cfg.Gateway.Verification.VerificationTimeoutSeconds) * time.Second,
				ResultValidity: time.Duration(cfg.Gateway.Verification.ProbeResultValiditySeconds) * time.Second,
			})
		}
		gatewayAddress := net.JoinHostPort(
			cfg.Gateway.ListenAddress, fmt.Sprint(cfg.Gateway.ListenPort),
		)
		serviceAddress := gatewayAddress
		if cfg.Gateway.Frontend.Enabled {
			// The SNI frontend owns the public listener. The identity service
			// still terminates its own TLS, but only on an ephemeral loopback
			// socket selected here and unreachable from other hosts.
			serviceAddress = "127.0.0.1:0"
		}
		gatewayServer = &http.Server{
			Addr:    serviceAddress,
			Handler: gatewayService, ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
			IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		}
		gatewayListener, err = net.Listen("tcp", gatewayServer.Addr)
		if err != nil {
			logger.Fatalf("HTTPS gateway bind failed: %v", err)
		}
		switch cfg.Gateway.TLS.Mode {
		case "existing":
			certificate, err := tls.LoadX509KeyPair(
				cfg.Gateway.TLS.CertificatePath, cfg.Gateway.TLS.PrivateKeyPath,
			)
			if err != nil {
				logger.Fatalf("HTTPS gateway TLS configuration failed: %v", err)
			}
			gatewayListener = tls.NewListener(gatewayListener, &tls.Config{
				Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
			})
		case "acme":
			cacheDirectory := cfg.Gateway.TLS.ACMECacheDirectory
			if cacheDirectory == "" {
				cacheDirectory = filepath.Join(cfg.DataDir, "gateway-acme")
			}
			acmeManager, managerErr := gateway.NewACMEManager(
				cfg.Gateway.PublicHostname, cfg.Gateway.TLS.ACMEEmail, cacheDirectory,
			)
			if managerErr != nil {
				logger.Fatalf("HTTPS gateway ACME configuration failed: %v", managerErr)
			}
			acmeHTTPListener, listenErr := net.Listen("tcp", cfg.Gateway.TLS.ACMEHTTPAddress)
			if listenErr != nil {
				logger.Fatalf("HTTPS gateway ACME HTTP bind failed: %v", listenErr)
			}
			gatewayACMEHTTPServer = &http.Server{
				Handler:           acmeManager.HTTPHandler(nil),
				ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
				WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
				MaxHeaderBytes: 16 << 10,
			}
			go func() {
				if serveErr := gatewayACMEHTTPServer.Serve(acmeHTTPListener); serveErr != nil && serveErr != http.ErrServerClosed {
					logger.Printf("gateway ACME HTTP listener failed: %v", serveErr)
				}
			}()
			tlsConfig := acmeManager.TLSConfig()
			tlsConfig.MinVersion = tls.VersionTLS12
			gatewayListener = tls.NewListener(gatewayListener, tlsConfig)
		}
		if cfg.Gateway.Frontend.Enabled {
			frontendListener, listenErr := net.Listen("tcp", gatewayAddress)
			if listenErr != nil {
				logger.Fatalf("gateway frontend bind failed: %v", listenErr)
			}
			gatewayFrontend, err = gatewayfrontend.New(gatewayfrontend.Config{
				OriginAddress:     cfg.Gateway.Frontend.OriginAddress,
				LocalAddress:      gatewayListener.Addr().String(),
				LocalHostname:     cfg.Gateway.PublicHostname,
				SNIAllowlist:      cfg.Gateway.Frontend.SNIAllowlist,
				MaxConnections:    cfg.Gateway.Frontend.MaxConnections,
				MaxBytesPerSecond: cfg.Gateway.Frontend.MaxBytesPerSecond,
				HandshakeTimeout: time.Duration(
					cfg.Gateway.Frontend.HandshakeTimeoutSeconds,
				) * time.Second,
				DialTimeout: time.Duration(
					cfg.Gateway.Frontend.DialTimeoutSeconds,
				) * time.Second,
				IdleTimeout: time.Duration(
					cfg.Gateway.Frontend.IdleTimeoutSeconds,
				) * time.Second,
				ProxyProtocol: cfg.Gateway.Frontend.ProxyProtocol,
			}, logger)
			if err != nil {
				_ = frontendListener.Close()
				logger.Fatalf("gateway frontend configuration failed: %v", err)
			}
			go func() {
				if serveErr := gatewayFrontend.Serve(frontendListener); serveErr != nil && serveErr != gatewayfrontend.ErrServerClosed {
					logger.Fatalf("gateway frontend failed: %v", serveErr)
				}
			}()
		}
		gatewayService.SetListenerReady(true)
		go func() {
			if err := gatewayServer.Serve(gatewayListener); err != nil && err != http.ErrServerClosed {
				logger.Fatalf("HTTPS gateway failed: %v", err)
			}
		}()
		logger.Printf("volunteer gateway candidate listening on %s for %s",
			gatewayAddress, cfg.Gateway.PublicHostname)
	}
	// Registration is what makes a gateway reachable, so it runs whenever the
	// gateway role is on. external_verification only decides HOW the address
	// is proven: by a peer probe quorum, or by the controller's own
	// independent connect-back alone.
	// Registering puts this host's IP into the PUBLIC syndichan.org answer set.
	// Without the SNI frontend this process serves only its own gw-<id>
	// hostname, so a visitor whose DNS lands here gets a completed TCP connect
	// and then a failed TLS handshake ("host not configured in HostWhitelist").
	// Browsers do not fail over from a TLS error the way they do from a refused
	// connection, so that visitor is simply broken -- an outage caused purely
	// by joining the pool. Serve the site, or stay out of the pool.
	if cfg.Gateway.Enabled && !cfg.Gateway.Frontend.Enabled {
		logger.Printf("gateway.frontend is disabled: NOT registering with the controller.")
		logger.Printf("  This node cannot serve %s, so publishing its IP in that DNS answer",
			cfg.Gateway.Frontend.OriginServerName)
		logger.Printf("  set would break every visitor routed to it. It still serves its own")
		logger.Printf("  %s endpoints and sends the presence heartbeat.", cfg.Gateway.PublicHostname)
		logger.Printf("  Set gateway.frontend.enabled=true (with a reachable origin_address) to join the pool.")
	}
	if cfg.Gateway.Enabled && cfg.Gateway.Frontend.Enabled {
		// One definition, shared with validation: a quorum is only in play when
		// the operator actually named a probe fleet.
		quorumInPlay := cfg.Gateway.Verification.Enabled &&
			config.ProbeQuorumConfigured(cfg.Gateway)
		if cfg.Gateway.Verification.Enabled && !quorumInPlay {
			logger.Printf("no probe_urls/trusted_probes configured: verifying through the " +
				"controller alone. It still connect-backs to this host before publishing DNS, " +
				"but this node will not report itself as independently verified.")
		}
		addresses := make([]gateway.Address, 0, len(cfg.Gateway.PublicAddresses))
		for _, value := range cfg.Gateway.PublicAddresses {
			ip := net.ParseIP(value)
			if ip != nil && ip.To4() != nil && !cfg.Gateway.AdvertiseIPv4 {
				continue
			}
			if ip != nil && ip.To4() == nil && !cfg.Gateway.AdvertiseIPv6 {
				continue
			}
			addresses = append(addresses, gateway.Address{Address: value, Port: 443})
		}
		if gatewayRegistry == nil {
			logger.Fatal("gateway registration client was not initialized")
		}
		gatewayRegistry.PublicHostname = cfg.Gateway.PublicHostname
		var publisher gateway.RegistrationPublisher = gatewayRegistry
		if node != nil {
			publisher = gateway.MultiPublisher{
				// The central controller verifies the direct source IP and owns
				// DNS. The DHT receives the record only after that request succeeds.
				Publishers: []gateway.RegistrationPublisher{gatewayRegistry, node},
			}
		}
		var manager *gateway.Manager
		manager, err = gateway.NewManager(signer, publisher, gateway.ManagerConfig{
			Addresses: addresses, PublicHostname: cfg.Gateway.PublicHostname,
			ProbeURLs:            cfg.Gateway.ProbeURLs,
			TrustedProbes:        cfg.Gateway.TrustedProbes,
			MinimumProbes:        cfg.Gateway.Verification.MinimumSuccessfulProbes,
			MinimumNetworks:      cfg.Gateway.Verification.MinimumDistinctNetworks,
			RequestTimeout:       time.Duration(cfg.Gateway.Verification.VerificationTimeoutSeconds) * time.Second,
			ResultValidity:       time.Duration(cfg.Gateway.Verification.ProbeResultValiditySeconds) * time.Second,
			RegistrationValidity: time.Duration(cfg.Gateway.Verification.RegistrationValiditySeconds) * time.Second,
			Interval:             time.Duration(cfg.Gateway.Verification.ReverifyIntervalSeconds) * time.Second,
			StatePath:            filepath.Join(cfg.DataDir, "gateway-registration.json"),
			SoftwareVersion:      "1.0.0",
			FailureThreshold:     cfg.Gateway.Health.FailureThreshold,
			RecoveryThreshold:    cfg.Gateway.Health.RecoveryThreshold,
			DrainDuration:        time.Duration(cfg.Gateway.Health.DrainSeconds) * time.Second,
			RequireProbeQuorum:   quorumInPlay,
		}, logger, func(verified bool) {
			gatewayVerified.Store(verified)
			if node != nil {
				node.SetGatewayState(true, verified)
				if verified && manager != nil {
					node.SetGatewayRegistration(manager.Current())
				} else {
					node.SetGatewayRegistration(nil)
				}
				go node.RefreshHeartbeat(ctx)
			}
		})
		if err != nil {
			logger.Fatalf("gateway verification manager: %v", err)
		}
		gatewayManager = manager
		go manager.Run(ctx)
	}
	// Presence heartbeat for the storage-free roles. A storage node sends its
	// own from inside the p2p node; a dedicated gateway or probe has no p2p
	// node, but it still has a persistent identity and the operator still
	// needs to see it. It reports zero capacity, which is exactly how the
	// frontend tells a gateway apart from a storage node.
	if noStorage {
		presence := &heartbeat.Client{
			Signer: signer, Logger: logger,
			Snapshot: func() heartbeat.State {
				state := heartbeat.State{
					CapacityBytes:   0,
					GatewayEnabled:  cfg.Gateway.Enabled,
					GatewayVerified: gatewayVerified.Load(),
				}
				if state.GatewayVerified && gatewayManager != nil {
					state.Registration = gatewayManager.Current()
				}
				return state
			},
		}
		logger.Printf("presence heartbeat every %s to %s", heartbeat.Interval, heartbeat.Endpoint)
		go presence.Run(ctx)
	}
	if !noStorage {
		uiServer.Handler.(*ui.Server).SetStoragePaths(cfg.DataDir, func(target string) error {
			// Persist only; the store is open and moving it live would risk
			// corrupting it. Takes effect on the next start (see ui.setStorageDir).
			next := cfg
			next.DataDir = target
			return config.Save(path, next, role)
		})
		logger.Printf("starting S3 gateway on %s", cfg.S3Listen)
		go serve(s3Server, cfg, logger, "S3 gateway")
		logger.Printf("starting storage dashboard on %s", cfg.UIListen)
		go serve(uiServer, cfg, logger, "dashboard")
	}
	// Distributed Container Service. Off unless dcs.enabled + role.worker; a
	// no-op otherwise, and non-fatal if Docker is unreachable. Needs the full
	// storage node (host, DHT, I2P, store), so it is wired here in that path.
	if !noStorage {
		startDCSWorker(ctx, cfg, node, storageNode, logger)
	}
	// Tray icon when built with -tags tray; nil otherwise. It does not keep the
	// node alive -- the node is a service and outlives any window -- it just
	// makes that visible and gives the dashboard somewhere to be reopened from.
	if runTray != nil {
		runTray(ctx, "http://"+cfg.UIListen, logger, cancel)
	}
	if node != nil {
		logger.Printf("node %s started on %s; bootstrap=%s", signer.ID(), config.PlatformLabel(), config.BootstrapURL)
	} else {
		logger.Printf("node %s started on %s", signer.ID(), config.PlatformLabel())
	}
	if noStorage {
		logger.Printf("%s mode: %s", role, role.Description())
	} else {
		logger.Printf("S3 gateway: %s; dashboard: %s", cfg.S3Listen, cfg.UIListen)
	}

	<-ctx.Done()
	shutdownTimeout := 15 * time.Second
	if cfg.Gateway.Frontend.Enabled {
		configuredDrain := time.Duration(cfg.Gateway.Frontend.DrainSeconds) * time.Second
		if configuredDrain > shutdownTimeout {
			shutdownTimeout = configuredDrain
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if gatewayService != nil {
		gatewayService.Drain()
	}
	if gatewayFrontend != nil {
		_ = gatewayFrontend.Shutdown(shutdownCtx)
	}
	if gatewayServer != nil {
		_ = gatewayServer.Shutdown(shutdownCtx)
	}
	if gatewayACMEHTTPServer != nil {
		_ = gatewayACMEHTTPServer.Shutdown(shutdownCtx)
	}
	if s3Server != nil {
		_ = s3Server.Shutdown(shutdownCtx)
	}
	if uiServer != nil {
		_ = uiServer.Shutdown(shutdownCtx)
	}
	logger.Printf("shutdown complete")
}

// runtimeRole maps the mutually exclusive role flags onto a config.Role. It
// touches no configuration, so the role is known before the config file is
// even opened.
func runtimeRole(gatewayOnly, probeOnly bool) (config.Role, error) {
	switch {
	case gatewayOnly && probeOnly:
		return "", errors.New("-gateway-only and -probe-only are mutually exclusive")
	case gatewayOnly:
		return config.RoleGatewayOnly, nil
	case probeOnly:
		return config.RoleProbeOnly, nil
	default:
		return config.RoleStorage, nil
	}
}

func readSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return value, nil
}

func serve(server *http.Server, cfg config.Config, logger *log.Logger, label string) {
	var err error
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		err = server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		logger.Fatalf("%s failed: %v", label, err)
	}
}
