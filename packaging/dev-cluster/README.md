# A dendritic network you can actually run — on one host

`node.rabbiit.io` does not have to exist for the overlay to form. A node joins
through the relays named in its `axon.seeds`; the signed bootstrap document is
only the *default* source of that list, and when it is unreachable the fetch
fails **non-fatally** and the node still joins through whatever `axon.seeds`
names. So a complete AXON dendritic network can run with nothing but config —
no public relay, no coordinator, no internet. `dev-cluster.sh` here does exactly
that, and it is what a single Ubuntu VM needs to host the whole thing for
development.

## Quick start

```sh
make rabbiit-node                         # from the repo root -> build/rabbiit-node
cp build/rabbiit-node packaging/dev-cluster/rabbiit-node
cd packaging/dev-cluster
RABBIIT_NODE_BIN=./rabbiit-node ./dev-cluster.sh start
RABBIIT_NODE_BIN=./rabbiit-node ./dev-cluster.sh test     # expect: {"ok":true,...}
```

`test` drives `svcB -> svcA /expert/health` through the loopback AXON proxy — a
full hidden-service round trip (rendezvous and all), which is the praxis
distributed-expert path (`deps/praxis-shim/dendritic_expert.py`) exercised over
the overlay. Point `EXPERT_A`/`EXPERT_B` at a running praxis expert backend
(default `http://127.0.0.1:7777`) to carry real inference instead of health.

For systemd (one VM hosts the overlay): install the binary and script into
`/usr/local/bin`, drop `rabbiit-dev-cluster.service` into
`/etc/systemd/system`, and `systemctl enable --now rabbiit-dev-cluster`.

## Why it is built this way (the non-obvious constraints)

These were found the hard way; they are properties of AXON, not of the script.

* **Relay count has a floor.** A hidden service keeps `serviceIntroPoints` (3)
  intro points on three *distinct* relays, and a connecting client excludes all
  of its intro-point relays before choosing a rendezvous point. So the overlay
  needs **≥ 4 relays** for any hidden service to be reachable, and a little more
  for the client's two near-disjoint circuits. **Six** is the comfortable floor;
  with three you get `axon/runtime: the directory has too few relays for a circuit`.
* **Relays must not be the services you call.** The rendezvous point is a relay
  chosen by the client, which cannot know which node hosts the service. If a
  node is *both* a relay and the target service, the client can pick that node
  as the rendezvous point and the service then tries to build a circuit ending
  at itself — `a circuit cannot end at this node`. So relays here are
  `probe-only` (they relay but publish no hidden service) and the expert
  services run on separate non-relay nodes.
* **One LAN needs `allow_same_network`.** Path selection normally requires each
  hop in a different network prefix, which rejects every path when all relays
  share one subnet (a single host, or one `/24`). `axon.allow_same_network: true`
  lifts that — **for a test/dev network only**; a real deployment must leave it
  off and spread relays across networks.
* **Pure relays use a non-privileged port.** A `probe-only` relay still opens a
  gateway listener; it is configured onto a high port (`8443+`) so it needs no
  root, with `tls.mode: reverse_proxy` (no certificate files) and
  `external_verification.enabled: false` (no probe peers required).

## Spreading across several machines

Set `HOST` to each machine's reachable IP instead of `127.0.0.1`, run some
relays on each, and give the service nodes the full relay seed list. Keep
`allow_same_network` on only while every machine is still inside one subnet;
once relays span real networks, turn it off and let diversity do its job.
