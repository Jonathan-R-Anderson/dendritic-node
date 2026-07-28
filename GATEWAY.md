# Volunteer gateway operations

## Architecture

The storage client keeps one persistent libp2p Ed25519 identity. Kademlia and
shard exchange remain I2P-only. Gateway verification is the deliberate
exception: candidates contact admitted probes over direct HTTPS so probes see
the candidate's real source address and can connect back to that exact address
on public TCP 443.

Roles are configuration-driven:

- ordinary peers have both `gateway.enabled` and `gateway.probe_enabled` false;
- candidates enable `gateway.enabled`;
- probes enable `gateway.probe_enabled` and set a stable `probe_network` trust
  domain (operator/ASN/prefix);
- verified gateways are candidates whose current signed results meet quorum;
- the separate server-side gateway controller owns all authoritative DNS
  access; the storage binary contains no DNS provider login or mutation path.

One process may be a candidate and probe, but its own probe result never counts.

## Verification flow

1. The candidate signs a short-lived hostname reservation with its persistent
   node identity. The controller deterministically derives
   `gw-<identity-hash>.syndichan.org`, points it only at the observed request
   source IP, and returns after the DNS provider accepts the change.
2. The candidate confirms that public DNS resolves its assigned name to that
   exact address, then starts exact-host ACME and its TLS listener.
3. It signs a short-lived request containing its explicitly configured public
   addresses. Only port 443 is accepted.
4. Each probe accepts the request only when its TCP source address equals the
   claimed address. This prevents victim-address SSRF.
5. The probe connects to that literal address while validating TLS against
   `public_hostname`; redirects are forbidden.
6. It fetches the signed identity, submits a signed one-use challenge, checks
   `/readyz`, then signs its result.
7. The candidate requires three distinct admitted identities across two
   configured network trust domains by default.
8. It signs a five-minute registration and submits it directly to
   `https://syndichan.org/api/v1/gateways/register`. The server ignores claimed
   addresses, derives the HTTPS source IP, and independently checks TCP 443,
   TLS hostname validity, HTTP 200, and `X-Gateway-Version`.
9. Only after server acceptance is it published under
   `/syndichan-gateway/<node-id>` in Kademlia. Every DHT reader independently
   validates the gateway signature, probe signatures, expiry, quorum, address
   policy, and DHT-key binding.
10. The server reconciles its verified healthy registry with Name.com. Durable
   record ownership prevents unrelated DNS records from entering the diff.

## Candidate

Edit the generated `config.json` using `gateway.example.json` as a reference.
Set a real public IP in `public_addresses`, three or more HTTPS probe origins,
the admitted probe node IDs/public keys, and either:

- `tls.mode: existing` with a browser-trusted per-node certificate and key; or
- `tls.mode: acme` to reserve a deterministic `gw-` name and issue automatically; or
- `tls.mode: reverse_proxy`, with nginx/Caddy/HAProxy forwarding public 443 to
  the configured private listener.

Then:

```sh
syndichan-node -gateway-enable
syndichan-node -gateway-status
syndichan-node
```

Forward TCP 443 at the router and permit it through host, IPv6, and cloud
firewalls. A listening socket or UPnP mapping never counts as verification.

## Probe

A probe needs a publicly reachable TLS listener too. Set:

```json
{
  "gateway": {
    "enabled": false,
    "probe_enabled": true,
    "probe_network": "operator-a/as64500"
  }
}
```

Install its public key in each candidate's `trusted_probes`. Run the ordinary
binary; `/probe/verify` appears only when this role is enabled.

## Server-side DNS controller

The controller is deployed from `../gateway-controller` and
`../k8s/gateway-controller`. Name.com credentials are injected only into that
server workload through Kubernetes Secrets. They are not accepted by or
needed on a volunteer node. The client setting `registration_api` is a public,
credential-free HTTPS URL and authentication uses the node signature.

On graceful drain the client posts a signed unregister statement before its
DHT draining record. A hard crash is removed after registration expiry or
three consecutive server health failures.

## Diagnostics

```sh
syndichan-node -gateway-status
curl --fail https://gateway.example.com/healthz
curl --fail https://gateway.example.com/readyz
openssl s_client -connect PUBLIC_IP:443 -servername gateway.example.com
```

If local health works but external probes time out, check router forwarding,
host/cloud firewalls, CGNAT (`100.64.0.0/10`), double NAT, ISP filtering, and
IPv6 firewall policy. If TLS fails, correct the certificate chain, hostname,
and reverse-proxy SNI configuration. No code path disables TLS validation.

## Tests

```sh
cd storage-client
go test ./...
go vet ./...
```

Tests cover restricted IP ranges, CGNAT, signature binding, self-verification,
network diversity, replay rejection, health transitions, DHT record selection,
signed registration requests, I2P-only peer addresses, signed heartbeats,
encrypted transfer leases, S3 compatibility, storage quotas, and UI controls.
