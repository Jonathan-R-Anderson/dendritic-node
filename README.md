# Syndichan Storage Node

`syndichan-node` is a native, cross-platform storage client for Windows, Linux,
and macOS. It can replace the application's S3 endpoint while using volunteer
nodes for encrypted shard storage and recovery.

## What is implemented

- an AWS Signature Version 4, path-style S3 gateway for bucket and object
  create/list/head/get/put/delete, encrypted multipart uploads, bucket policies,
  and multi-object deletion;
- SHA-256 content IDs for encrypted shards and canonical object manifests;
- XChaCha20-Poly1305 end-to-end encryption with a random object key and nonce
  per chunk;
- 6+3 Reed-Solomon coding by default, allowing any three unavailable/corrupt
  shards per chunk;
- an I2P-only libp2p Kademlia DHT for provider discovery, with persistent
  Ed25519 libp2p identity and a separate persistent I2P destination;
- BitTorrent-style `HAVE`, `GET`, and `STORE` shard exchange with bounded frames,
  hash verification, parallel distribution, and provider announcements;
- mandatory short-lived Ed25519 coordinator leases before a peer accepts
  remotely supplied bytes;
- hard-coded TLS bootstrap and lease coordination through
  `syndichan.org`, forced through the I2P HTTP proxy without direct
  fallback;
- a local dashboard listing locally named S3 objects and anonymous encrypted
  peer shards, with **Reject & remove** controls and persistent content-ID
  denials;
- a dashboard allocation control that lets the user choose and persist the
  maximum disk space donated to the node, enforced immediately without restart.
- a signed presence heartbeat sent directly to the Syndichan frontend every
  five minutes with User-Agent `Syndichan-Storage-Client/1.0`.
- an optional public HTTPS gateway candidate service with signed identity and
  one-use challenge endpoints, strict probe admission, public-address/CGNAT
  filtering, multi-network quorum evaluation, expiring registrations, gateway
  health states, and signed server registration.
- independently signed probe results published as short-lived Kademlia gateway
  records; a local listener or self-reported role cannot satisfy verification;
- candidate and probe roles in the same binary, with self-verification
  forbidden even when an installation enables both roles;
- verified role reporting for the admin map: storage is blue, gateway+storage
  is green/blue, visitor+storage is red/blue, and all three are red/blue/green;
- a credential-free HTTPS registration client signed by the persistent node
  identity. Name.com access and DNS mutation exist only in the separate
  server-side `gateway-controller`.
- a `-gateway-only` runtime mode for dedicated edge hosts. It retains gateway
  identity, ACME, verification, gateway DHT publication, and SNI forwarding
  while disabling shard storage/exchange, S3, the storage dashboard, and
  storage-node heartbeats.

## Volunteer HTTPS gateway mode

Gateway mode is disabled by default. Ordinary storage nodes need no inbound
port and continue to exchange shards only over I2P. The storage binary has no
DNS-provider credential field or DNS mutation code.

One installation can have one or more explicit roles:

| Role | Configuration | Public inbound port |
| --- | --- | --- |
| Ordinary storage peer | Both gateway flags false | Not required |
| Candidate gateway | `gateway.enabled: true` | TCP 443 |
| Probe node | `gateway.probe_enabled: true` | TCP 443 |
| Verified gateway | Assigned only after probe quorum | TCP 443 |

The public gateway and probe protocol is:

```text
GET  /healthz
GET  /readyz
GET  /gateway/identity
POST /gateway/challenge
POST /probe/verify        # probe role only
```

Identity and challenge responses use the node's existing persistent libp2p
Ed25519 key. Challenges are accepted only from configured probe identities,
expire within 60 seconds, are one-use, size-limited, and rate-limited.
Verification policy rejects private, loopback, link-local, documentation,
multicast, CGNAT (`100.64.0.0/10`), IPv6 ULA, and Teredo addresses. A valid
registration requires three admitted probe identities across at least two
configured network trust domains by default.

### Verification and DHT publication

```text
candidate signs its configured public address
    -> admitted probes observe the request's source IP
    -> each probe connects back to that exact IP on TCP 443
    -> TLS, identity, one-use challenge, and readiness are verified
    -> candidate verifies probe identities, signatures, expiry, and networks
    -> quorum creates a signed, short-lived registration
    -> server registry derives the direct source IP and independently verifies it
    -> server registry reconciles only controller-owned Name.com records
    -> registration is published at /syndichan-gateway/<node-id> in Kademlia
```

A probe never connects to an arbitrary address merely because a request named
it. The claimed address must equal the source address the probe observed.
Probes connect to the validated literal IP while retaining TLS hostname
verification and refusing redirects. This blocks private-network,
metadata-service, redirect, and DNS-rebinding SSRF.

Verification repeats on the configured interval. Failures move a gateway
through `healthy`, `suspect`, and `draining`; recovery requires consecutive
successful rounds. Graceful shutdown publishes a draining state. After a hard
crash, the short-lived registration expires naturally.

### Configure a candidate

Copy the `gateway` section from
[`gateway.example.json`](gateway.example.json) into the generated `config.json`.
A candidate needs:

- one or more literal `public_addresses`;
- at least as many HTTPS `probe_urls` as the required quorum;
- `trusted_probes`, mapping node IDs to base64 libp2p public keys;
- the public, credential-free `registration_api` (normally the built-in
  `https://syndichan.org/api/v1/gateways`);
- existing certificate paths, client-managed ACME, or reverse-proxy TLS mode.

For direct TLS, install a browser-trusted certificate and set `tls.mode` to
`existing`. To let the client issue and renew its own per-node certificate, set
`tls.mode` to `acme`, provide an optional `acme_email`, and forward public TCP
80 and 443 to the client. Before ACME begins, the client signs a reservation
request with its existing node identity. The server derives and temporarily
publishes `gw-<identity-hash>.syndichan.org` to the request's actual source IP;
the client cannot choose a DNS name or submit an IP address. After public DNS
propagates, the exact-host ACME policy authorizes only that assigned hostname.
Private keys remain in the owner-only data-directory cache and renewed
certificates are selected without restarting the listener.

For nginx, Caddy, or HAProxy, set `tls.mode` to `reverse_proxy`,
bind the client to a private high port, and forward the public protocol routes
from Internet TCP 443. External probes still test public port 443; a local
listener is never sufficient for DNS eligibility.

To serve the public site through the volunteer as well, enable
`gateway.frontend`. The frontend reads only the bounded TLS ClientHello, accepts
only literal names in `sni_allowlist`, routes the gateway's own hostname to its
local identity endpoint, and splices the public hostname to `origin_address`.
It prepends PROXY protocol v2 so the origin retains the visitor's real address.
The origin must trust PROXY headers only from verified gateways; trusting them
from arbitrary sources lets an attacker forge IP bans, geolocation, and bot
locks.

Useful local controls:

```sh
syndichan-node -gateway-status
syndichan-node -gateway-enable
syndichan-node -gateway-disable
```

`-gateway-enable` validates the hostname and TLS configuration before saving.
Do not copy a private wildcard key to volunteer machines. The compatible
deployment is a per-node browser-trusted certificate obtained by the operator,
or TLS termination at a trusted project edge. Certificate verification is
never disabled.

### Run a dedicated gateway without storage

Use `-gateway-only` on an edge server that should forward HTTPS traffic but
must not donate disk or appear as a storage node. This is a real role boundary,
not a cosmetic dashboard setting. In gateway-only mode the process does not:

- open the encrypted shard/object store;
- accept, fetch, advertise, or replicate storage shards;
- start the loopback S3 service on port 9000;
- start the storage dashboard on port 9090; or
- send the five-minute storage-node heartbeat.

It still opens the persistent node identity and I2P DHT transport because
verified gateway registrations are signed and published in the gateway DHT.
I2P and its SAM bridge therefore remain required. Public TCP 80 is required
when `gateway.tls.mode` is `acme`, and public TCP 443 is required for the
gateway listener.

Generate the configuration without starting storage services:

```sh
./syndichan-node -gateway-status
```

Edit the generated `config.json`, copy in the `gateway` object from
[`gateway.example.json`](gateway.example.json), and configure at minimum:

- `gateway.enabled: true`;
- the host's literal `public_addresses`;
- `tls.mode: "acme"` or paths for an existing certificate;
- `frontend.enabled: true` to forward `syndichan.org`;
- the supplied origin address and exact SNI allowlist; and
- the admitted probe URLs and public keys required by the verification quorum.

Then start only the gateway role:

```sh
# Linux
./syndichan-node-linux-amd64 -gateway-only

# macOS (Apple Silicon)
./syndichan-node-darwin-arm64 -gateway-only
```

```powershell
# Windows
.\syndichan-node-windows-amd64.exe -gateway-only
```

Pass `-config` and `-data-dir` when using service-owned paths:

```sh
/usr/local/bin/syndichan-node \
  -gateway-only \
  -config /var/lib/syndichan/config.json \
  -data-dir /var/lib/syndichan/data
```

For the packaged Linux systemd unit, create an override so package updates do
not erase the role selection:

```sh
sudo systemctl edit syndichan-node
```

Enter:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/syndichan-node -gateway-only -config /var/lib/syndichan/config.json -data-dir /var/lib/syndichan/data
```

Then reload and start it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now syndichan-node
sudo systemctl status syndichan-node
```

Do not launch a second copy while the system service is running; only one
process can own ports 80 and 443. Verify the role and listeners with:

```sh
systemctl show syndichan-node -p ExecStart
ss -lnt | grep -E ':80 |:443 |:9000 |:9090 '
curl --fail https://gw-NODE-ID.syndichan.org/healthz
curl --fail https://gw-NODE-ID.syndichan.org/readyz
```

Only 80/443 should be present; 9000/9090 must be absent. `/healthz` proves the
process is running. `/readyz` must return 200 before the controller can admit
the gateway to the shared `syndichan.org` DNS answer set. A 503 normally means
the I2P DHT has no live peer yet or the gateway is draining.

### Configure a probe

Set `gateway.probe_enabled` to true, configure its public TLS listener, and
assign a stable `probe_network` trust domain representing an independently
operated network, ASN, or routed prefix. Install the probe node ID and public
key in candidate and controller trust lists. Several probe keys on one network
do not satisfy network diversity. An installation may be both a candidate and
a probe, but its own result is never counted.

### DNS registration security boundary

The node posts the signed registration directly—not through I2P—so the
controller can derive the candidate's public source IPv4. The controller
ignores every client-supplied IP, verifies TCP 443/TLS/HTTP independently,
requires HTTP 200 plus `X-Gateway-Version`, and publishes DNS only after the
check succeeds. Requests are timestamped, nonce-protected, sequence-checked,
and limited to five registrations per source IP per minute.

Name.com username/token values are never configured on this client. Do not add
them to `config.json`, environment variables, command-line flags, source code,
or release artifacts. The server implementation and Kubernetes secret setup
are documented in [`../gateway-controller/README.md`](../gateway-controller/README.md).

Gateway diagnostics:

```sh
# Local process only; this does not prove Internet reachability
curl --fail http://127.0.0.1:8443/healthz

# Test the real public TLS endpoint from a different network
curl --fail https://gateway.example.com/readyz
openssl s_client -connect PUBLIC_IP:443 -servername gateway.example.com
```

Common verification failures are missing router forwarding, host/cloud
firewalls, CGNAT, double NAT, an occupied port, an invalid hostname certificate,
or an IPv6 firewall. Automatic UPnP is intentionally not used.

See [`GATEWAY.md`](GATEWAY.md) for the detailed role, protocol, deployment, and
security guide.

Peers never receive object keys, plaintext file data, filenames, S3 bucket
names, MIME types, or IP addresses. A peer can see encrypted shard IDs, byte
sizes, the opaque encrypted object ID, the node's I2P destination, and transfer
timing.

## Build all supported platforms

Go 1.25.12 or newer is required. I2P is required to run the client, but not to
compile it. The release build uses `CGO_ENABLED=0`, so Go can cross-compile all
targets from one machine without platform SDKs or C compilers.

Clone the repository, enter this directory, download dependencies, and run the
tests:

```sh
cd storage-client
go mod download
go test ./...
```

On Linux or macOS, build every release target with:

```sh
./scripts/build-release.sh
```

On Windows, run this from PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build-release.ps1
```

The scripts produce these portable executables under `dist/`:

| Target machine | Executable |
| --- | --- |
| 64-bit Intel/AMD Linux | `syndichan-node-linux-amd64` |
| 64-bit ARM Linux | `syndichan-node-linux-arm64` |
| Intel Mac | `syndichan-node-darwin-amd64` |
| Apple Silicon Mac | `syndichan-node-darwin-arm64` |
| 64-bit Intel/AMD Windows | `syndichan-node-windows-amd64.exe` |
| Windows on ARM | `syndichan-node-windows-arm64.exe` |

`amd64` means ordinary x86-64 Intel/AMD hardware. `arm64` includes Apple
Silicon and 64-bit ARM Windows/Linux devices.

To build only the current computer instead:

```sh
go build -trimpath -o syndichan-node ./cmd/syndichan-node
```

Checksum release artifacts after building:

```sh
# Linux
sha256sum dist/*

# macOS
shasum -a 256 dist/*
```

On Windows:

```powershell
Get-ChildItem .\dist\* | Get-FileHash -Algorithm SHA256
```

These are currently portable, unsigned binaries rather than an MSI, PKG, DEB,
or RPM. Public releases should be code-signed; macOS distribution should also
be notarized.

## Install and configure I2P

Install and start an I2P router before starting the storage client:

- **Windows:** use the
  [official I2P Easy Install Bundle](https://i2p.net/en/docs/guides/installing-i2p-on-windows/).
  It includes the required Java runtime and router.
- **macOS:** use an installer from the
  [official I2P downloads page](https://i2p.net/en/downloads/). Use the Easy
  Install Bundle where supported, or the cross-platform Java installer.
- **Linux:** on Ubuntu, use the official I2P-maintainers repository shown
  below. Debian users should follow the
  [official Debian/Ubuntu guide](https://i2p.net/en/docs/guides/installing-i2p-on-debian-and-ubuntu/).
  Other distributions can use the cross-platform Java installer. i2pd can also
  be used if its SAM and HTTP proxy services use the ports below.

Ubuntu installation:

```sh
sudo apt-add-repository ppa:i2p-maintainers/i2p
sudo apt-get update
sudo apt-get install i2p
```

Open the I2P router console at `http://127.0.0.1:7657`. With Java I2P, open
**Configure I2P Internals > Clients**, find the **SAM application bridge**,
start it, and enable **Run at Startup**. Java I2P does not enable SAM by
default. Keep SAM on loopback: it is normally neither encrypted nor
authenticated. See I2P's
[SAM v3 documentation](https://i2p.net/en/docs/api/samv3/) for the protocol and
router-specific details.

The client expects:

| Local I2P service | Address |
| --- | --- |
| SAM v3 bridge | `127.0.0.1:7656` |
| HTTP proxy | `127.0.0.1:4444` |
| Router console | `127.0.0.1:7657` |

The HTTP proxy needs a working outproxy because bootstrap begins at
`node.syndichan.org` and coordinator leases use `syndichan.org`, both through
I2P. Allow a newly installed router
several minutes to integrate into the I2P network before diagnosing initial
connection failures.

Check the two required ports on Linux or macOS:

```sh
nc -vz 127.0.0.1 7656
nc -vz 127.0.0.1 4444
```

Check them on Windows:

```powershell
Test-NetConnection 127.0.0.1 -Port 7656
Test-NetConnection 127.0.0.1 -Port 4444
```

Do not expose ports 4444 or 7656 to a LAN or the Internet.

## Run on Linux

Copy the matching binary to a convenient location, mark it executable, and run
it as your normal user:

```sh
chmod 755 syndichan-node-linux-amd64
./syndichan-node-linux-amd64
```

For 64-bit ARM, substitute `syndichan-node-linux-arm64`. Do not run the storage
client as root.

For a dedicated Linux host, the hardened system service in
[`packaging/systemd/syndichan-node.service`](packaging/systemd/syndichan-node.service)
runs the client as an unprivileged `syndichan` account and grants only
`CAP_NET_BIND_SERVICE` for optional ACME/gateway ports 80 and 443. The companion
[`i2pd-syndichan.default`](packaging/systemd/i2pd-syndichan.default) enables SAM
and the HTTP proxy on loopback. Review paths and storage capacity, then install
them as `/etc/systemd/system/syndichan-node.service` and `/etc/default/i2pd`;
do not put S3 keys, DNS tokens, or account credentials in either file.

## Run on macOS

Use `darwin-arm64` on Apple Silicon (M-series) or `darwin-amd64` on an Intel
Mac:

```sh
chmod 755 syndichan-node-darwin-arm64
./syndichan-node-darwin-arm64
```

A locally compiled binary should run directly. A publicly downloaded build
must be signed and notarized by its distributor to avoid Gatekeeper warnings.

## Run on Windows

Use `syndichan-node-windows-amd64.exe` on most PCs, or the ARM64 executable on
Windows on ARM. Start it from PowerShell so startup errors remain visible:

```powershell
.\syndichan-node-windows-amd64.exe
```

A self-built executable is not publisher-signed, so Windows may label it as
unrecognized. Production releases should be signed rather than instructing
users to disable Windows security controls.

## First run and verification

Start I2P first, then start the storage client. The client fails closed if the
SAM bridge is unavailable; it never substitutes the host's public IP for peer
traffic.

On first start the client creates a mode-0600 configuration, S3 credentials,
master encryption key, and libp2p identity in the operating system's standard
user configuration directory. It also creates `i2p.destination`, the
mode-0600 private key for the node's stable `.b32.i2p` identity:

- Linux: usually `~/.config/Syndichan/storage-node`
- macOS: `~/Library/Application Support/Syndichan/storage-node`
- Windows: `%AppData%\Syndichan\storage-node`

Defaults:

- S3 endpoint: `http://127.0.0.1:9000`
- dashboard: `http://127.0.0.1:9090`
- storage allocation: 20 GiB
- erasure layout: 6 data + 3 parity shards
- encrypted plaintext chunk size: 1 MiB
- I2P SAM bridge: `127.0.0.1:7656`
- I2P HTTP proxy: `http://127.0.0.1:4444`

### Choosing where files are stored

By default the shard/object store lives beside the configuration in the OS
config directory. To keep the small secret config there but put the bulk data
on another drive, pass `-data-dir` on the first run:

```sh
# Linux / macOS
./syndichan-node-linux-amd64 -data-dir /mnt/bigdisk/syndichan
```

```powershell
# Windows
.\syndichan-node-windows-amd64.exe -data-dir D:\syndichan
```

The directory is created at mode 0700 if missing and the choice is written back
to `config.json`, so later launches do not need the flag. You can also edit
`data_dir` in `config.json` directly while the node is stopped. Use a path on a
disk with room for the allocation you intend to donate; the dashboard refuses an
allocation smaller than current usage.

Open `http://127.0.0.1:9090` to see the files and encrypted shards stored by
the node, reject unwanted content IDs, and choose the maximum disk space to
donate. On Linux or macOS, check the dashboard API with:

```sh
curl http://127.0.0.1:9090/api/status
```

On Windows:

```powershell
Invoke-RestMethod http://127.0.0.1:9090/api/status
```

The storage allocation can be changed from the dashboard. A smaller allocation
cannot be saved below current usage; remove unwanted objects or shards first.
The choice is persisted in encrypted-store metadata and survives restarts.

Peer networking is fail-closed. There are no TCP, QUIC, DNS, WebSocket, relay,
NAT-traversal, or clearnet fallback transports in the production node. If SAM
is unavailable, startup stops rather than creating a clearnet host. If the I2P
HTTP proxy or its outproxy is unavailable, coordinator operations fail without
falling back to a direct request.

The presence heartbeat is the deliberate exception to I2P-only networking. It
POSTs directly over HTTPS to
`https://syndichan.org/api/v1/storage/nodes/heartbeat` immediately at startup
and every five minutes. This reveals the client's public egress IP to the
frontend and its normal web-server logs. The heartbeat body is signed by the
node's persistent libp2p identity so the server counts unique node IDs rather
than requests. The application database stores node ID, first/last seen time,
capacity, platform, User-Agent, and the egress IP of the last heartbeat, which
is geolocated to COUNTRY level only (a country centroid, no city database) so the
operator's admin map can show where capacity is coming from.

When gateway mode is active, the heartbeat also carries the current signed
gateway registration. The frontend independently validates the candidate
signature, admitted probe signatures, freshness, readiness results, and
network quorum before displaying a gateway role. A signed heartbeat that merely
claims `gateway_verified: true` without a valid registration is rejected.

To be precise about what is and is not protected: the guarantee this design makes
is between VOLUNTEERS. Peers cannot identify one another, because shard exchange
runs entirely over I2P and a peer only ever sees a `.b32.i2p` destination -- never
an IP. It is not, and was never, a guarantee that the site operator cannot see
your address: the heartbeat is a plain HTTPS POST, so the same IP already appears
in the web server's logs, exactly as it does when you simply visit the site.

The heartbeat User-Agent is:

```text
Syndichan-Storage-Client/1.0
```

### Credentials

The S3 credentials authenticate this node's **loopback gateway only**. They are
never sent to the coordinator, never appear in a heartbeat or lease, and the
Syndichan server does not hold or need them — peers exchange shards over I2P
under coordinator-signed leases, not S3. A node operator therefore does not need
to share them with anyone.

First run prints the access key and the config path but **not** the secret, so
the secret does not end up in shell scrollback, the systemd journal, or a screen
share. Retrieve it deliberately when you need it:

```sh
syndichan-node -show-credentials
```

This reads the same mode-0600 file you already own; it is a convenience, not a
privilege boundary. Anyone who can read that file (you, or root on your machine)
can read the key regardless — that is inherent to running a service on your own
hardware, and is why the key grants access to nothing beyond your own loopback
gateway.

Point an AWS SDK at the local endpoint with the generated credentials and
enable path-style addressing. For Maniwani:

```text
STORAGE_PROVIDER=S3
S3_ENDPOINT=http://host.docker.internal:9000
S3_ACCESS_KEY=<generated access key>
S3_SECRET_KEY=<generated secret key>
```

The gateway and dashboard bind only to loopback by default. The dashboard is
always required to remain on loopback and rejects non-local Host headers to
resist DNS rebinding. If the S3 gateway is bound to a non-loopback interface,
startup refuses the configuration unless `tls_cert` and `tls_key` are set.

## Firewall and automatic startup

The default S3 gateway and dashboard are loopback-only and should remain so.
The application needs outbound HTTPS for its direct heartbeat and access to
the local I2P router. Peer discovery and shard transfer travel through I2P;
peers see the stable I2P destination rather than one another's IP addresses.
The I2P router manages its own network ports according to its configuration.

For automatic startup, configure the operating system to start I2P first and
the storage client second, under the same unprivileged user that performed the
first run:

- Linux: use a per-user systemd service.
- macOS: use a per-user LaunchAgent.
- Windows: use Task Scheduler with **Run only when user is logged on**.

Always use an absolute executable path and preserve the same user account so
the client finds the same keys, metadata, and configuration directory.

## Troubleshooting

- **`connect to local I2P SAM bridge ... connection refused`:** start I2P,
  enable the SAM application bridge, and verify port 7656.
- **Coordinator/bootstrap requests fail:** verify the I2P HTTP proxy on port
  4444 has a working outproxy. There is intentionally no direct fallback.
- **Heartbeat fails while peer networking works:** verify ordinary DNS, HTTPS,
  and system clock settings. The five-minute heartbeat intentionally does not
  use I2P.
- **Port 9000 or 9090 is already in use:** stop the conflicting application or
  change the corresponding loopback address in `config.json`.
- **A lower storage allocation is rejected:** current stored data exceeds the
  requested limit. Reject/remove shards or delete locally owned objects first.
- **Gateway works locally but never verifies:** test from another network,
  confirm TCP 443 reaches the process or reverse proxy, and make sure every
  probe observes the configured literal address as the request source.
- **Probe quorum is not met:** check that node IDs and public keys exactly match
  `trusted_probes` and that enough distinct `probe_network` values are present.
- **Gateway disappears from DNS:** inspect verification failures and
  registration expiry. Healthy gateways must continually publish fresh records.
- **Registration API rejects the node:** confirm the public request source is
  the configured public IPv4, the hostname begins with the managed `gw-`
  prefix, TCP 443 is reachable, `/readyz` returns 200 with
  `X-Gateway-Version`, and the certificate matches that hostname.

## Availability and recovery

Keep backups of `master.key` and `metadata.db`. Remote peers intentionally
cannot decrypt or reconstruct object names without these files. Reed-Solomon
coding tolerates peer/shard loss; it does not replace backing up the local
manifest/key database.

The client retains a full local shard set until coordinator-leased remote
placements are acknowledged. A failed bootstrap or lease request never deletes
the local copy. The dedicated data-node edge publishes only
`/garlic32/.../p2p/...` peer multiaddresses and the coordinator public key at:

```text
https://node.syndichan.org/.well-known/syndichan/storage-node.json
```

The edge owns and automatically renews its `node.syndichan.org` certificate; it
returns 404 for unrelated paths and receives no Name.com credential.

## Current S3 scope

The ordinary AWS SDK operations used by Maniwani—including multipart upload—are
supported and tested against the official AWS SDK for Go v2. Versioning,
server-side copy, object ACL evaluation beyond the narrow public-read bucket
policy, and presigned-query authentication are not yet supported; unsupported
calls return S3 `NotImplemented` rather than silently changing semantics.

## Tests and current limitations

Run the unit, static-analysis, and concurrency checks with:

```sh
go test ./...
go vet ./...
go test -race ./internal/gateway ./internal/config ./internal/p2p
```

The release scripts build Linux, macOS, and Windows binaries for AMD64 and
ARM64. Client tests never contact the registration service or Name.com.

The following deployment pieces are external or not yet automatic:

- the server-side gateway controller must be deployed separately;
- ACME needs public TCP 80 and 443 plus a gateway DNS record resolving to the
  volunteer before its first issuance;
- UPnP/NAT-PMP port creation is not automatic;
- CPU, free-memory, free-disk, and upload-bandwidth thresholds are represented
  in configuration, but full cross-platform resource measurement is not yet
  enforced;
- a hard-crashed gateway relies on short registration expiry because it cannot
  publish its normal draining record;
- public multi-container Internet/DNS end-to-end tests remain deployment work;
  ordinary tests do not contact production probes or DNS.
