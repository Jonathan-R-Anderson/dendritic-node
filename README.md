# Syndichan Storage Node

`syndichan-node` is a single program that lets you donate spare disk space, or
spare bandwidth, to Syndichan. It runs on Windows, macOS, and Linux.

It does two jobs, and you choose one or both:

- **Storage node.** It stores encrypted pieces of other people's files and
  keeps a copy of your own. Everything is encrypted and split up before it
  leaves your machine, and all peer traffic goes over I2P, so other volunteers
  never see your IP address or what any file is. It also gives you a local S3
  endpoint your own applications can use.
- **HTTPS gateway.** Your machine acts as one of the public front doors for
  `syndichan.org`. This one needs a public port and is off by default.

That's the whole idea. The rest of this page is how to build it, how to run it,
and what to open on your router if you want to run a gateway from home.

## Build it

You need [Go](https://go.dev/dl/) 1.25.12 or newer. Nothing else — the build
uses `CGO_ENABLED=0`, so one machine can cross-compile every target.

```sh
cd storage-client
go mod download
go test ./...
```

Build for the computer you're on:

```sh
go build -trimpath -o syndichan-node ./cmd/syndichan-node
```

Or build every release binary into `dist/`:

```sh
./scripts/build-release.sh          # Linux / macOS
.\scripts\build-release.ps1         # Windows PowerShell
```

That produces:

| Target machine | Executable |
| --- | --- |
| Intel/AMD Linux | `syndichan-node-linux-amd64` |
| ARM Linux (incl. Raspberry Pi 4/5) | `syndichan-node-linux-arm64` |
| Intel Mac | `syndichan-node-darwin-amd64` |
| Apple Silicon Mac | `syndichan-node-darwin-arm64` |
| Intel/AMD Windows | `syndichan-node-windows-amd64.exe` |
| Windows on ARM | `syndichan-node-windows-arm64.exe` |

These are unsigned binaries. macOS Gatekeeper and Windows SmartScreen will warn
about a build you downloaded rather than compiled yourself.

## Run it as a storage node

**First install I2P**, because the storage node refuses to start without it —
it will never fall back to sending your traffic over the open Internet.

- **Windows / macOS:** the
  [I2P Easy Install Bundle](https://i2p.net/en/downloads/) includes everything.
- **Linux (Ubuntu):**
  ```sh
  sudo apt-add-repository ppa:i2p-maintainers/i2p
  sudo apt-get update && sudo apt-get install i2p
  ```

Then open the router console at `http://127.0.0.1:7657`, go to
**Configure I2P Internals > Clients**, start the **SAM application bridge**, and
tick **Run at Startup**. Java I2P does not turn SAM on by default. Give a fresh
router a few minutes to join the network before worrying about errors.

The node expects I2P's SAM bridge on `127.0.0.1:7656` and its HTTP proxy on
`127.0.0.1:4444`. Both stay on loopback — never expose them.

Now start the node as your normal user (not root):

```sh
chmod 755 syndichan-node-linux-amd64
./syndichan-node-linux-amd64
```

```powershell
.\syndichan-node-windows-amd64.exe
```

On first start it creates a mode-0600 config file, your S3 credentials, and
your encryption keys in your user config directory:

- Linux: `~/.config/Syndichan/storage-node`
- macOS: `~/Library/Application Support/Syndichan/storage-node`
- Windows: `%AppData%\Syndichan\storage-node`

Out of the box you get:

| | |
| --- | --- |
| Dashboard | `http://127.0.0.1:9090` |
| S3 endpoint | `http://127.0.0.1:9000` |
| Disk donated | 20 GiB |

Open the dashboard to see what you're storing, change how much disk you donate,
and reject anything you don't want to host. Both ports are loopback-only and
should stay that way.

Useful flags:

```sh
./syndichan-node -data-dir /mnt/bigdisk/syndichan   # put the bulk data elsewhere
./syndichan-node -capacity-gib 200                  # donate 200 GiB
./syndichan-node -show-credentials                  # print your S3 keys
./syndichan-node -cache-only                        # keep only your own content
```

`-data-dir` is saved to the config, so you only pass it once. The S3 secret is
not printed at startup on purpose (it would end up in your shell history and
logs); ask for it with `-show-credentials` when you need it.

Back up `master.key` and `metadata.db` from your data directory. Without them
your own uploaded files cannot be reassembled — no peer can do it for you,
which is the point.

## Running from home: ports and forwarding

**As a plain storage node you do not need to open anything.** All peer traffic
goes out through I2P, which handles its own connections. If that's all you want
to do, you're finished — skip this section.

**A gateway is different.** It is a public web server, so the Internet has to be
able to reach your machine, and a home router blocks that by default. To run a
gateway from your house you need to do three things on your own network:

1. **Give the machine a fixed address on your LAN.** In your router's DHCP
   settings, reserve an address for it (something like `192.168.1.50`). If the
   address changes, your forwarding rules quietly stop working.

2. **Forward the ports on your router.** In the router admin page — usually
   under *Port Forwarding*, *Virtual Server*, or *NAT* — send incoming traffic
   to that machine:

   | Port | Protocol | Forward to | Needed for |
   | --- | --- | --- | --- |
   | 443 | TCP | your machine's LAN IP, port 443 | the gateway itself |
   | 80 | TCP | your machine's LAN IP, port 80 | only if the node gets its own certificate (`tls.mode: "acme"`) |

   The node deliberately does not use UPnP to punch holes for you. You open the
   ports yourself, knowingly.

3. **Allow the same ports in the machine's own firewall.** Forwarding on the
   router is not enough if the computer itself drops the connection.

   ```sh
   sudo ufw allow 443/tcp && sudo ufw allow 80/tcp    # Linux (ufw)
   ```

   ```powershell
   New-NetFirewallRule -DisplayName "Syndichan 443" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
   ```

Then check from **outside** your network — a phone on mobile data works well.
Testing from inside your own LAN often succeeds even when the Internet cannot
reach you, so it proves nothing:

```sh
curl --fail https://your-gateway-hostname/readyz
```

If it never works from outside, the usual causes are: your ISP puts you behind
CGNAT (a shared address you cannot forward through), you have two routers
chained together and only forwarded through one of them, port 443 is already
taken by something else on that machine, or IPv6 is being filtered separately
from IPv4. CGNAT in particular cannot be fixed from your end — you'd need a
static or public IP from your ISP.

Before a gateway is trusted with real traffic, independent probe nodes on other
networks connect back to your public address and verify it. A gateway that only
answers on your LAN is never admitted.

## Run a dedicated gateway (no storage)

For a VPS or spare box that should only forward HTTPS and store nothing:

```sh
./syndichan-node -gateway-only -config gateway.json -data-dir ./data
```

`-gateway-only` starts the gateway and nothing else. No shard store, no S3, no
dashboard, no I2P — and it asks you for none of that configuration, so a gateway
config file contains gateway settings only. Copy
[`gateway.example.json`](gateway.example.json) as a starting point and set at
minimum `gateway.enabled`, your public address, and how TLS is handled.

It does still send the five-minute presence heartbeat, reporting zero capacity.
That is how the operator's map knows your gateway exists and separates it from
a storage node.

### About `probe_urls`

Before a gateway is trusted, something has to prove it is genuinely reachable
from the outside rather than just claiming to be. Two independent things can do
that, and `gateway.external_verification` picks which you use:

- **`enabled: true` (the default)** — your node asks other volunteers running
  `-probe-only` to connect back to your public address and confirm it. Those
  volunteers' URLs go in `probe_urls`, and you need at least as many as
  `minimum_successful_probes` (3 by default), spread across at least two
  different networks. This is the stronger check, but it needs a probe fleet to
  exist.
- **`enabled: false`** — skip the peer probes. Your node still registers with
  the controller, and the controller still connects back to your address and
  checks `/readyz` itself before putting you in DNS. You just don't get the
  independent multi-network opinion, so your node never reports itself as
  "verified".

If you are standing up the first gateway there are no probes to point at yet,
so use the second form:

```json
"external_verification": { "enabled": false }
```

There is also `-probe-only`, which runs just the verification probe service —
that is what other people would point their `probe_urls` at.

Quick local controls:

```sh
./syndichan-node -gateway-status     # show the saved gateway settings
./syndichan-node -gateway-enable     # turn gateway mode on
./syndichan-node -gateway-disable    # turn it off
```

Full setup — TLS modes, probe quorum, serving `syndichan.org` through your box,
systemd units, and automatic updates — is in [`GATEWAY.md`](GATEWAY.md).

## When something goes wrong

- **`connect to local I2P SAM bridge ... connection refused`** — I2P isn't
  running, or the SAM bridge isn't enabled. See the run section above.
- **Bootstrap or coordinator requests fail** — I2P's HTTP proxy on port 4444
  needs a working outproxy. There is intentionally no direct fallback.
- **Port 9000 or 9090 already in use** — stop whatever else is using it, or
  change the address in `config.json`.
- **The dashboard won't let you lower your donated space** — you're storing
  more than the new limit. Remove some content first.
- **The gateway works locally but never gets verified** — it's a reachability
  problem, not a config problem. Work through the ports section above and test
  from another network.
- **`-gateway-only` won't start** — it needs `gateway.enabled` or
  `gateway.probe_enabled` set to true in the config file you pointed it at.
  The startup log prints the role and the exact config path it loaded.
- **`gateway.external_verification needs 3 probe_urls`** — you have no probe
  fleet to verify against. Set `external_verification.enabled` to false and let
  the controller do the reachability check; see the section above.
- **`gateway public_addresses is empty`** — list this host's literal public IP,
  e.g. `"public_addresses": ["203.0.113.10"]`. Run `curl ifconfig.me` on the
  box to find it.

## More detail

- [`GATEWAY.md`](GATEWAY.md) — gateway roles, verification protocol, and deployment
- [`SECURITY.md`](SECURITY.md) — what is and isn't protected, and from whom
- [`../gateway-controller/README.md`](../gateway-controller/README.md) — the
  server side that owns DNS

Two things worth knowing up front. The node sends a signed heartbeat directly
over HTTPS to `syndichan.org` every five minutes, so the site operator sees your
IP address — exactly as they would if you simply visited the site. The privacy
guarantee is between *volunteers*: other peers only ever see an I2P destination,
never your address. And the local S3 credentials are yours alone; they are never
sent anywhere and the server neither holds nor needs them.

Supported S3 operations cover ordinary AWS SDK use including multipart upload.
Versioning, server-side copy, and presigned-query auth return `NotImplemented`
rather than silently doing something different.
