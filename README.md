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

The HTTP proxy needs a working outproxy because the fixed coordinator,
`syndichan.org`, is reached through I2P. Allow a newly installed router
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

## Availability and recovery

Keep backups of `master.key` and `metadata.db`. Remote peers intentionally
cannot decrypt or reconstruct object names without these files. Reed-Solomon
coding tolerates peer/shard loss; it does not replace backing up the local
manifest/key database.

The client retains a full local shard set until coordinator-leased remote
placements are acknowledged. A failed bootstrap or lease request never deletes
the local copy. `syndichan.org` publishes only `/garlic32/.../p2p/...`
peer multiaddresses and the coordinator public key at:

```text
https://syndichan.org/.well-known/syndichan/storage-node.json
```

## Current S3 scope

The ordinary AWS SDK operations used by Maniwani—including multipart upload—are
supported and tested against the official AWS SDK for Go v2. Versioning,
server-side copy, object ACL evaluation beyond the narrow public-read bucket
policy, and presigned-query authentication are not yet supported; unsupported
calls return S3 `NotImplemented` rather than silently changing semantics.
