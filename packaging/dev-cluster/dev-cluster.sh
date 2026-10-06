#!/usr/bin/env bash
# dev-cluster.sh -- bring up a self-contained AXON dendritic network on ONE host
# (one Ubuntu VM is enough), with no dependency on node.rabbiit.io: it needs no
# signed bootstrap document, no public relay and no internet. It runs N dedicated
# relays plus a pair of storage/expert service nodes, wires the service nodes to
# the relays by seed, and -- because every node sits on one LAN/host -- turns on
# axon.allow_same_network so the path-diversity rule does not reject every circuit.
#
# WHY THESE NUMBERS
#   * A hidden service keeps serviceIntroPoints (3) intro points, each on a
#     DISTINCT relay, and the client excludes all of them when it picks a
#     rendezvous point -- so the overlay needs at least 3+1 = 4 relays, and a
#     couple more for the client's two near-disjoint circuits. Six is the
#     comfortable floor; fewer fails with "the directory has too few relays".
#   * Relays are probe-only (they relay but host no hidden service of their own),
#     so the rendezvous point is ALWAYS a relay and never the target service's
#     own node -- otherwise the service would try to build a circuit ending at
#     itself ("a circuit cannot end at this node").
#   * Relays bind a NON-privileged gateway port (no :443, so no root needed).
#
# USAGE
#   dev-cluster.sh up        # start everything, then wait (foreground; for systemd)
#   dev-cluster.sh start     # start everything in the background and return
#   dev-cluster.sh stop      # stop everything
#   dev-cluster.sh status    # show what is up and each node's AXON address
#   dev-cluster.sh test      # svcB -> svcA /expert/health over AXON (proves the overlay)
#
# ENV
#   RABBIIT_NODE_BIN   path to the dendritic-node binary          (default: ./dendritic-node)
#   DEV_DIR            data/root directory for the cluster      (default: ~/.rabbiit-dev)
#   NRELAY             number of relays                         (default: 6)
#   HOST               address the nodes bind/announce          (default: 127.0.0.1)
#   PROXY              svcB loopback AXON proxy                  (default: 127.0.0.1:4480)
#   HOPS               circuit length: 3 = anonymous (default), 2 = faster, NOT anonymous
set -u
BIN="${RABBIIT_NODE_BIN:-./dendritic-node}"
DEV_DIR="${DEV_DIR:-$HOME/.rabbiit-dev}"
NRELAY="${NRELAY:-6}"
HOST="${HOST:-127.0.0.1}"
PROXY="${PROXY:-127.0.0.1:4480}"
HOPS="${HOPS:-3}"
PIDS="$DEV_DIR/pids"

die(){ echo "dev-cluster: $*" >&2; exit 1; }
have_py(){ command -v python3 >/dev/null || die "python3 is required"; }

relaycfg(){ # $1 dir  $2 axonport  $3 gwport  $4 seedsJSON
  mkdir -p "$1"
  python3 - "$1/config.json" "$2" "$3" "$4" "$HOST" <<'PY'
import json,sys
out,port,gwport,seeds,host=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),json.loads(sys.argv[4]),sys.argv[5]
c={"data_dir":out.rsplit("/",1)[0],"run_mode":"probe-only","ui_listen":"",
   "s3_listen":f"127.0.0.1:{19000+port}",
   "gateway":{"enabled":False,"probe_enabled":True,"public_hostname":f"relay{port}.axon.local",
              "listen_port":gwport,"tls":{"mode":"reverse_proxy"},"probe_network":"dev-lan",
              "external_verification":{"enabled":False},"probe_urls":[]},
   # Bind all interfaces but ANNOUNCE the reachable address: external peers dial the
   # announced host, while same-host nodes can still reach the relay via loopback
   # (a cloud public IP often does not hairpin from inside the box).
   "axon":{"relay":True,
           "listen":["/ip4/0.0.0.0/tcp/%d"%port,"/ip4/0.0.0.0/udp/%d/quic-v1"%port],
           "announce":[f"{host}:{port}"],"allow_same_network":True,"proxy_listen":""}}
if seeds: c["axon"]["seeds"]=seeds
json.dump(c,open(out,"w"),indent=2)
PY
}
svccfg(){ # $1 dir  $2 seedsJSON  $3 proxy  $4 s3port
  mkdir -p "$1"
  python3 - "$1/config.json" "$2" "$3" "$4" "$HOPS" <<'PY'
import json,sys,secrets
out,seeds,proxy,s3,hops=sys.argv[1],json.loads(sys.argv[2]),sys.argv[3],int(sys.argv[4]),int(sys.argv[5])
# The storage role runs a loopback S3 gateway and requires credentials
# (access_key non-empty, secret_key >= 32 chars); generate per-node ones that
# never leave this host.
c={"data_dir":out.rsplit("/",1)[0],"run_mode":"storage","ui_listen":"",
   "s3_listen":f"127.0.0.1:{s3}",
   "access_key":"DEV"+secrets.token_hex(8),"secret_key":secrets.token_hex(24),
   "axon":{"relay":False,"allow_same_network":True,"hops":hops,"proxy_listen":proxy,"seeds":seeds}}
json.dump(c,open(out,"w"),indent=2)
PY
}
spawn(){ # $1 dir  $2 expertport  [$3 backend]
  RABBIIT_EXPERT_LISTEN="127.0.0.1:$2" RABBIIT_EXPERT_BACKEND="${3:-}" \
    "$BIN" -config "$1/config.json" >"$1/run.log" 2>&1 &
  echo "$!" >>"$PIDS"
}
addr_of(){ # $1 dir -> quic dial multiaddr
  for _ in $(seq 1 80); do grep -q 'can join through' "$1/run.log" 2>/dev/null && break; sleep 0.25; done
  grep 'quic-v1/p2p' "$1/run.log" | grep -oE "/ip4/[^ ]+" | head -1
}
axon_addr(){ grep -oE '[a-z2-7]{56}\.key\.axon' "$1/run.log" 2>/dev/null | head -1; }

do_stop(){
  [ -f "$PIDS" ] && while read -r p; do kill "$p" 2>/dev/null; done <"$PIDS"
  pkill -x dendritic-node 2>/dev/null
  rm -f "$PIDS"
  echo "dev-cluster: stopped"
}
do_start(){
  have_py
  [ -x "$BIN" ] || die "dendritic-node binary not found/executable at $BIN (set RABBIIT_NODE_BIN)"
  do_stop >/dev/null 2>&1; sleep 1
  mkdir -p "$DEV_DIR"; : >"$PIDS"
  echo "dev-cluster: $NRELAY relays + 2 service nodes under $DEV_DIR (host $HOST, hops=$HOPS)"

  # Pass 1: mint relay identities and learn their dial multiaddrs.
  SEEDS=()
  for i in $(seq 1 "$NRELAY"); do
    d="$DEV_DIR/r$i"; relaycfg "$d" "$((4000+i))" "$((8442+i))" '[]'
    spawn "$d" "$((4600+i))"
    a="$(addr_of "$d")"; [ -n "$a" ] || die "relay r$i did not come up (see $d/run.log)"
    SEEDS+=("$a")
  done
  do_stop >/dev/null 2>&1; sleep 1; : >"$PIDS"
  MESH="$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1:]))' "${SEEDS[@]}")"

  # Pass 2: start the relays (full-mesh seeds) and the two service nodes.
  for i in $(seq 1 "$NRELAY"); do
    d="$DEV_DIR/r$i"; relaycfg "$d" "$((4000+i))" "$((8442+i))" "$MESH"
    spawn "$d" "$((4600+i))"
  done
  svccfg "$DEV_DIR/svcA" "$MESH" ""      19201; spawn "$DEV_DIR/svcA" 4471 "${EXPERT_A:-}"
  svccfg "$DEV_DIR/svcB" "$MESH" "$PROXY" 19202; spawn "$DEV_DIR/svcB" 4472 "${EXPERT_B:-}"
  echo "dev-cluster: started $(wc -l <"$PIDS") processes; AXON proxy on http://$PROXY"
}
wait_published(){
  for _ in $(seq 1 240); do
    d=0; for s in svcA svcB; do grep -q 'expert: serving /expert for praxis at' "$DEV_DIR/$s/run.log" 2>/dev/null && d=$((d+1)); done
    [ "$d" -ge 2 ] && return 0; sleep 0.5
  done; return 1
}
do_status(){
  echo "processes: $(pgrep -c -x dendritic-node 2>/dev/null) alive"
  for s in svcA svcB; do printf "  %-5s %s\n" "$s" "$(axon_addr "$DEV_DIR/$s")"; done
}
do_test(){
  wait_published || { echo "dev-cluster: service nodes did not publish in time"; exit 1; }
  local A; A="$(axon_addr "$DEV_DIR/svcA")"
  [ -n "$A" ] || die "svcA has no AXON address yet"
  echo "dev-cluster: svcB -> svcA ($A) /expert/health over AXON:"
  curl -sS --max-time 60 -x "http://$PROXY" "http://$A/expert/health"; echo
}

case "${1:-up}" in
  start)  do_start ;;
  up)     do_start; echo "dev-cluster: waiting (Ctrl-C / systemd stop to exit)"; wait ;;
  stop)   do_stop ;;
  status) do_status ;;
  test)   do_test ;;
  *) echo "usage: $0 {up|start|stop|status|test}"; exit 2 ;;
esac
