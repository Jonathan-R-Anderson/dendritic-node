#!/usr/bin/env bash
# Install syndichan-node, its runtime dependencies, and a boot service.
#
# LINUX ONLY. macOS, the BSDs and WSL-without-systemd are refused at the top of
# the script rather than half-supported: every path below assumes systemd,
# /proc, useradd and GNU coreutils, and an installer that pretends otherwise
# leaves a machine in a state nobody chose.
#
# bash, not POSIX sh, for one reason that is worth the dependency: /dev/tcp.
# The single most important check in this file is a real SAM handshake against
# 127.0.0.1:7656, and bash can open a TCP socket without nc, socat or python --
# none of which are guaranteed on a fresh server. Arrays (for the plan) are the
# second reason. Bash 4+ is assumed; the bash-3.2 contortions this script used
# to carry existed only for stock macOS.
#
# The shape is DETECT -> REPORT -> ASK -> ACT, in that order and never
# interleaved. Nothing in DETECT writes to the machine, which is what makes
# --check honest: it is not a separate code path, it is the same pass with ACT
# cut off.
#
# CHECK/ACT PARITY is the property everything else rests on. Every row the plan
# prints as "install" corresponds to exactly one DO_* flag set during DETECT
# and consumed by exactly one function during ACT:
#
#   DO_INSTALL_I2PD / PKGS[]  -> "I2P router (SAM)"      -> install_packages
#   DO_CONFIGURE_I2PD         -> "I2P router (SAM)"      -> configure_i2pd
#   DO_ENABLE_ROUTER          -> "I2P router on boot"    -> start_router
#   DO_START_ROUTER           -> "I2P router (SAM)"      -> start_router
#   DO_ENABLE_DOCKER          -> "Docker Engine"         -> start_docker
#   DO_BOOTSTRAP_GO           -> "Go toolchain"          -> bootstrap_go
#   DO_BUILD_BINARY           -> "syndichan-node binary" -> build_binary
#   DO_CREATE_USER            -> "service account"       -> create_user_and_dirs
#   DO_ADD_DOCKER_GROUP       -> "docker group"          -> install_compute_dropin
#   INSTALL_SERVICE           -> "boot service"          -> install_unit et al
#
# If you add an action, add its row. A --check that under-promises is a lie the
# operator finds out about after the fact.

# Deliberately NOT `set -o pipefail`. Detection here is full of pipelines whose
# reader exits early on purpose -- `... | grep -q`, `... | grep -m1` -- which
# sends SIGPIPE to the writer, which pipefail then reports as a failed
# pipeline. That is not hypothetical: with pipefail on, the /proc/cpuinfo
# virtualisation check reported "CPU reports no vmx/svm" on a machine whose CPU
# has vmx, because grep -q found the flag and closed the pipe before the first
# grep had finished writing. A detection script that lies about hardware is
# worse than one that ignores a write error, so pipefail stays off and every
# command whose failure actually matters is checked on its own.
#
# -E so the ERR trap below is inherited by functions.
set -eEu

VERSION="2"
PROGRAM="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "$(uname -s)" != "Linux" ]; then
  echo "$PROGRAM: this installer supports Linux only (found $(uname -s))." >&2
  echo "Build the binary with 'go build ./cmd/syndichan-node' and run it by hand." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Abort reporting
#
# The failure this guards against: under `set -e`, a function whose last
# statement is a bare `return` after a failing `&&` returns 1 and kills the
# script with NO output at all. Every function below ends in an explicit
# `return 0`, but that is a convention, and conventions rot. This trap makes
# the structural guarantee: an unexpected abort always names a line.
# ---------------------------------------------------------------------------

ABORT_LINE=""
trap 'ABORT_LINE="$LINENO"' ERR

WORK=""
workdir() { # a private scratch directory, created on first use only
  if [ -z "$WORK" ]; then
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/syndichan-install.XXXXXX")"
  fi
  printf '%s' "$WORK"
}

on_exit() {
  local rc=$?
  [ -n "$WORK" ] && rm -rf -- "$WORK"
  if [ "$rc" -ne 0 ] && [ -n "$ABORT_LINE" ]; then
    printf 'error: %s aborted unexpectedly at line %s (exit %s).\n' \
      "$PROGRAM" "$ABORT_LINE" "$rc" >&2
    printf 'Nothing further was attempted. Re-run with --check to see the plan.\n' >&2
  fi
  return 0
}
trap on_exit EXIT

# ---------------------------------------------------------------------------
# Options
#
# Deliberately few. Everything the node itself can configure lives in its
# config file or on the management page; flags here exist only for decisions
# that must be made BEFORE the node first runs, or that a headless server
# cannot make any other way.
# ---------------------------------------------------------------------------

DRY_RUN=0            # --check / --dry-run: report only, change nothing
ASSUME_YES=0         # --yes: skip the consent prompt
INSTALL_SERVICE=1    # --no-service: do not create or enable a boot service
WANT_COMPUTE=0       # --with-compute: also prepare Docker for the compute role
BINARY_SRC=""        # --binary PATH, otherwise discovered or built
DATA_DIR="/var/lib/syndichan"
PAYOUT=""
CAPACITY_GIB=""
UI_LISTEN=""

NODE_USER="syndichan"
NODE_GROUP="syndichan"
PREFIX="/usr/local"
BIN_DEST="$PREFIX/bin/syndichan-node"
WAIT_HELPER="$PREFIX/lib/syndichan/wait-for-sam"
UNIT_PATH="/etc/systemd/system/syndichan-node.service"
UNIT_DROPIN="/etc/systemd/system/syndichan-node.service.d/10-compute.conf"

# Not tunable, on purpose. Java I2P delays its SAM client app by 120 seconds
# and a cold router still has tunnels to build after that, so any budget short
# enough to be worth shortening mostly measures how fast this script gives up
# on a router that was going to work.
SAM_WAIT_SECONDS=300

# Where a bootstrapped Go toolchain goes. Never anywhere else, and never over
# an existing one.
GO_ROOT_DEST="/usr/local/go"
GO_BIN_LINK="/usr/local/bin/go"
# 1.21 is the first release that reads the `go` line in go.mod and downloads
# the toolchain it names. go.mod here pins go 1.25.12, so anything from 1.21
# up can build this tree without us shipping a version policy of our own.
GO_MIN_MAJOR=1
GO_MIN_MINOR=21

usage() {
  cat <<'EOF'
syndichan-node installer (Linux)

The safe way to start, and the way to answer "what is wrong with my node?":

    ./scripts/install.sh --check

--check runs every detection, prints a table of what is present, what is
missing, what would be installed and what CANNOT be installed, and exits
without touching the machine. Run it first. Run it again later when something
misbehaves; it is the same detection code the installer itself uses.

To actually install:

    sudo ./scripts/install.sh                 # asks before changing anything
    sudo ./scripts/install.sh --yes           # same plan, without the questions

Options:
  --check, --dry-run     Report only. No packages, no files, no services.
  --yes, -y              Do not prompt for consent before installing.
  --no-service           Do not create/enable the boot service. For developers
                         who run ./syndichan-node by hand. Boot-start is the
                         DEFAULT; this is the opt-out.
  --with-compute         Also prepare Docker for the compute/DCS role.
  --binary PATH          Use this syndichan-node binary instead of discovering
                         or building one.
  --data-dir PATH        Node data directory (default: /var/lib/syndichan).
                         Must be at least two path components deep, outside
                         the system directories, and either non-existent,
                         empty, or already owned by the service account.
  --payout 0x...         Payout address to write into the config. Without one
                         the node works and earns nothing, and a headless
                         server has no other way to set it (the management
                         page binds loopback).
  --capacity-gib N       Disk to donate, in whole GiB (node default: 20).
                         Checked against actual free space, which the node
                         never does.
  --ui-listen ADDR       Management page address, or "off" for headless. A
                         port clash here is fatal to the whole node (the
                         listener calls log.Fatal), so this is the escape
                         hatch when 9090 is taken.
  -h, --help             This text.

Other roles: gateway-only and probe-only nodes are configured by setting
run_mode in config.json (see GATEWAY.md); they need no I2P router and this
installer does not try to set them up.

Exit codes: 0 success (or, with --check, every REQUIRED dependency present);
1 a required dependency is missing (--check) or the install failed; 2 bad
usage or an unsupported platform.
EOF
}

say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "${C_BLUE:-}${C_BOLD:-}" "${C_RESET:-}" "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "${C_YELLOW:-}" "${C_RESET:-}" "$*" >&2; }
die()  { ABORT_LINE=""; printf '%serror:%s %s\n' "${C_RED:-}" "${C_RESET:-}" "$*" >&2; exit 1; }

need_value() { # a flag whose argument was swallowed by the next flag is a
               # silent misconfiguration, so refuse it here
  case "${2:-}" in
    ""|-*) echo "$PROGRAM: $1 needs a value" >&2; exit 2 ;;
  esac
  return 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check|--dry-run) DRY_RUN=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --no-service) INSTALL_SERVICE=0 ;;
    --with-compute) WANT_COMPUTE=1 ;;
    --binary) need_value "$1" "${2:-}"; BINARY_SRC="$2"; shift ;;
    --data-dir) need_value "$1" "${2:-}"; DATA_DIR="$2"; shift ;;
    --payout) need_value "$1" "${2:-}"; PAYOUT="$2"; shift ;;
    --capacity-gib) need_value "$1" "${2:-}"; CAPACITY_GIB="$2"; shift ;;
    --ui-listen) need_value "$1" "${2:-}"; UI_LISTEN="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$PROGRAM: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

usage_error() { ABORT_LINE=""; echo "$PROGRAM: $*" >&2; exit 2; }

# --- data directory ---------------------------------------------------------
#
# This is the ONE path the installer takes ownership of (chown to the service
# account, chmod 0700). It is caller-supplied, so it is validated like an
# attack surface rather than like a preference. Four rules, each of which
# independently blocks the worst case:
#
#   1. absolute, no "..", and only characters that a systemd unit can express.
#   2. at least two components deep -- so it can never be a filesystem or mount
#      root such as /data or /mnt.
#   3. not under a system directory.
#   4. (checked later, in detect_data_dir) if it already exists it must be a
#      real directory that is either EMPTY or ALREADY OWNED by the service
#      account. That is the rule that makes "--data-dir /home/alice" or
#      "--data-dir /etc/ssl" impossible rather than merely discouraged.
#
# The chown is never recursive, so even a mistake that got past all four
# touches exactly one inode.
case "$DATA_DIR" in
  /*) ;;
  *) usage_error "--data-dir must be an absolute path" ;;
esac
case "$DATA_DIR" in
  *"/../"*|*"/.."|*"/") usage_error "--data-dir must be a plain absolute path with no '..' and no trailing slash" ;;
esac
# A systemd unit file cannot express these safely: % introduces a specifier,
# and quotes/backslashes/newlines break Exec parsing. A SPACE is fine and is
# quoted properly everywhere it is written.
case "$DATA_DIR" in
  *[!A-Za-z0-9._/+:@" "-]*)
    usage_error "--data-dir may contain only letters, digits, spaces and . _ - + : @ /" ;;
esac
if [ "$(dirname "$DATA_DIR")" = "/" ]; then
  usage_error "--data-dir must be at least two components deep (e.g. /srv/syndichan, not $DATA_DIR)"
fi
case "$DATA_DIR" in
  /usr|/usr/*|/etc|/etc/*|/bin|/bin/*|/sbin|/sbin/*|/lib|/lib/*|/lib64|/lib64/*|/boot|/boot/*|/dev|/dev/*|/proc|/proc/*|/sys|/sys/*|/run|/run/*|/root|/root/*)
    usage_error "refusing a data directory inside a system path: $DATA_DIR" ;;
esac

case "$CAPACITY_GIB" in
  "") ;;
  *[!0-9]*) usage_error "--capacity-gib must be a whole number of GiB" ;;
  *) [ "$CAPACITY_GIB" -gt 0 ] || usage_error "--capacity-gib must be positive" ;;
esac

# Mirrors config.NormalizePayoutAddress. Duplicated only so a typo is caught in
# the first second rather than after a five-minute install; the node remains
# authoritative and will reject anything this misses.
if [ -n "$PAYOUT" ]; then
  case "$PAYOUT" in
    0x[0-9a-fA-F]*) ;;
    *) usage_error "--payout must start with 0x" ;;
  esac
  case "${PAYOUT#0x}" in
    *[!0-9a-fA-F]*) usage_error "--payout is not hexadecimal" ;;
  esac
  [ "${#PAYOUT}" -eq 42 ] || usage_error "--payout must be 42 characters including 0x"
fi

CONFIG_FILE="$DATA_DIR/config.json"

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

# ---------------------------------------------------------------------------
# The plan
#
# Status vocabulary, chosen so the table reads without a legend:
#   ok      present and working
#   fix     missing, and this script will install/configure it
#   manual  missing, and the operator must do it (the command is printed)
#   cannot  missing and IMPOSSIBLE to install here (hardware/firmware)
#   skip    not needed for the options selected
# ---------------------------------------------------------------------------

PLAN_STATUS=(); PLAN_NAME=(); PLAN_FOR=(); PLAN_DETAIL=()
REQUIRED_MISSING=0
BLOCKED=0

plan() { # plan STATUS NAME FOR DETAIL
  PLAN_STATUS+=("$1"); PLAN_NAME+=("$2"); PLAN_FOR+=("$3"); PLAN_DETAIL+=("$4")
  return 0
}

# blocker -- a condition that stops the install outright.
#
# Recorded as a plan row rather than raised as an immediate error, because
# --check exists to show the operator the WHOLE picture. Dying halfway through
# detection would hand them a truncated table and one sentence. ACT refuses to
# start while any of these stand.
blocker() { # blocker NAME FOR DETAIL
  BLOCKED=1
  REQUIRED_MISSING=1
  plan cannot "$1" "$2" "$3"
  return 0
}

PKGS=()
pkg_add() {
  local p
  for p in ${PKGS[@]+"${PKGS[@]}"}; do
    [ "$p" = "$1" ] && return 0
  done
  PKGS+=("$1")
  return 0
}

DO_INSTALL_I2PD=0
DO_CONFIGURE_I2PD=0
DO_ENABLE_ROUTER=0
DO_START_ROUTER=0
DO_ENABLE_DOCKER=0
DO_BOOTSTRAP_GO=0
DO_BUILD_BINARY=0
DO_CREATE_USER=0
DO_ADD_DOCKER_GROUP=0
ROUTER_KIND=""       # i2pd | java | none
ROUTER_UNIT=""       # systemd unit that owns the router, if any
I2PD_CONF=""
DOCKER_UNIT=""
GO_CMD=""            # the toolchain build_binary will use
BINARY_RESOLVED=""

# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

ARCH_RAW="$(uname -m)"
# go.dev publishes linux archives for exactly these names. An architecture that
# is not in this table STOPS the Go bootstrap -- it never picks a near miss,
# because a toolchain for the wrong ISA fails in a way that looks like a
# corrupt download.
case "$ARCH_RAW" in
  x86_64|amd64)   GOARCH="amd64" ;;
  aarch64|arm64)  GOARCH="arm64" ;;
  armv6l|armv7l)  GOARCH="armv6l" ;;   # Go ships armv6l; it runs on armv7 too
  i386|i686)      GOARCH="386" ;;
  *)              GOARCH="" ;;
esac

HAVE_SYSTEMD=0
[ -d /run/systemd/system ] && HAVE_SYSTEMD=1

IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1

have() { command -v "$1" >/dev/null 2>&1; }

PKG_MGR=""
if   have apt-get; then PKG_MGR="apt"
elif have dnf;     then PKG_MGR="dnf"
elif have pacman;  then PKG_MGR="pacman"
elif have zypper;  then PKG_MGR="zypper"
elif have apk;     then PKG_MGR="apk"
elif have yum;     then PKG_MGR="yum"
fi

# Package names differ per distro. Anything not in this table is reported as a
# manual step with the command spelled out, rather than guessed at -- guessing
# a package name installs SOMETHING, and the operator finds out later that it
# was not what they needed.
pkg_name_for() { # pkg_name_for LOGICAL -> distro package, or "" if unknown here
  case "$PKG_MGR:$1" in
    apt:i2pd|dnf:i2pd|yum:i2pd|pacman:i2pd|zypper:i2pd|apk:i2pd) echo "i2pd" ;;
    apt:ca-certificates|dnf:ca-certificates|yum:ca-certificates|pacman:ca-certificates|zypper:ca-certificates|apk:ca-certificates) echo "ca-certificates" ;;
    apt:docker) echo "docker.io" ;;
    dnf:docker|yum:docker) echo "moby-engine" ;;
    pacman:docker|zypper:docker|apk:docker) echo "docker" ;;
    *) echo "" ;;
  esac
  return 0
}

install_cmd_for() { # the exact command line used to install "$@"
  case "$PKG_MGR" in
    apt)    echo "apt-get install -y $*" ;;
    dnf)    echo "dnf install -y $*" ;;
    yum)    echo "yum install -y $*" ;;
    pacman) echo "pacman -S --needed --noconfirm $*" ;;
    zypper) echo "zypper --non-interactive install $*" ;;
    apk)    echo "apk add --no-cache $*" ;;
    *)      echo "" ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

# tcp_open HOST PORT -- true if something accepts a connection.
#
# The braces around exec are load-bearing. `exec 3<>/dev/tcp/... 2>/dev/null`
# still lets bash print "connect: Connection refused" to the terminal, because
# the redirection applies to the command and the message comes from the shell
# performing the redirection. Grouping moves the message inside the redirect.
tcp_open() {
  if { exec 3<>"/dev/tcp/$1/$2"; } 2>/dev/null; then
    exec 3>&-
    return 0
  fi
  return 1
}

# sam_probe -- the ONLY correct readiness test for the I2P transport.
#
# 0 = SAM answered RESULT=OK, 1 = nothing listening, 2 = connected but silent,
# 3 = something that is not SAM owns the port.
#
# This is byte-for-byte what internal/i2p/sam.go connectSAM does (HELLO VERSION
# MIN=3.1 MAX=3.3, reply must start "HELLO REPLY" and carry RESULT=OK), so a
# pass here guarantees the node's own handshake will pass. A bare TCP connect
# does not: the port can be open while the bridge is still initialising.
#
# WHY NOT THE CONSOLE PORTS: the obvious-looking check is "is the router up?",
# via 7657 (Java console) or 7070 (i2pd webconsole). Both bind IMMEDIATELY at
# router start. Java I2P ships the SAM client app with clientApp.N.delay=120,
# so SAM opens roughly TWO MINUTES after the console does. An installer that
# checks a console port reports success, systemd starts the node, p2p.Open gets
# ECONNREFUSED, and main.go calls logger.Fatal -- there is no startup retry in
# the node. The console tells you nothing about the bridge; ask the bridge.
#
# The address is the literal 127.0.0.1, never "localhost": on a machine whose
# resolver prefers ::1, "localhost" can reach a console listening on [::1]
# while missing a bridge bound to 127.0.0.1.
sam_probe() {
  local line=""
  if ! { exec 3<>"/dev/tcp/127.0.0.1/7656"; } 2>/dev/null; then
    return 1
  fi
  if ! printf 'HELLO VERSION MIN=3.1 MAX=3.3\n' >&3 2>/dev/null; then
    exec 3>&-; return 2
  fi
  if ! IFS= read -r -t 10 line <&3; then
    exec 3>&-; return 2
  fi
  exec 3>&-
  case "$line" in
    "HELLO REPLY"*RESULT=OK*) return 0 ;;
    *) return 3 ;;
  esac
}

# wait_for_sam SECONDS -- poll until the bridge answers, or give up.
#
# "Fail fast" is the wrong instinct here: the thing being waited for is known
# to be slow, and the cost of declaring failure early is an operator who
# reinstalls a router that was working.
#
# The one case that DOES fail fast is a reply that is not a SAM reply: if
# something answers 127.0.0.1:7656 and does not speak SAM, waiting cannot fix
# it, and continuing to wait would hide the real problem (a port collision).
wait_for_sam() {
  local budget="$1" waited=0 rc=0
  while :; do
    rc=0; sam_probe || rc=$?
    case "$rc" in
      0) return 0 ;;
      3) warn "127.0.0.1:7656 answered, but not with a SAM greeting -- something other than an I2P router owns that port"
         return 3 ;;
    esac
    if [ "$waited" -ge "$budget" ]; then
      return 1
    fi
    if [ "$waited" -gt 0 ] && [ $((waited % 30)) -eq 0 ]; then
      note "still waiting for the SAM bridge (${waited}s of ${budget}s) -- normal for a Java router"
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

free_mib() { # free_mib PATH -> MiB free on the filesystem holding the nearest
             # existing ancestor of PATH, or "" if df cannot say
  local d="$1"
  while [ ! -d "$d" ] && [ "$d" != "/" ]; do d="$(dirname "$d")"; done
  df -Pk -- "$d" 2>/dev/null | awk 'NR==2 {print int($4/1024)}'
  return 0
}

unit_exists() { # unit_exists NAME -- known to this systemd, enabled or not
  [ "$HAVE_SYSTEMD" = "1" ] || return 1
  have systemctl || return 1
  systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1"
}

sha_of() { sha256sum | awk '{print $1}'; }

MARKER_PREFIX="# managed-by: syndichan install.sh v$VERSION sha256="

# ---------------------------------------------------------------------------
# DETECT
# ---------------------------------------------------------------------------

detect_platform() {
  local label; label="Linux/$ARCH_RAW"
  if [ -n "$PKG_MGR" ]; then
    plan ok "platform" "all" "$label, package manager: $PKG_MGR"
  else
    plan manual "platform" "all" "$label, NO known package manager -- commands will be printed, not run"
  fi
  if [ "$HAVE_SYSTEMD" = "0" ] && [ "$INSTALL_SERVICE" = "1" ]; then
    REQUIRED_MISSING=1
    plan manual "systemd" "boot service" "not running here (no /run/systemd/system); re-run with --no-service and start the node yourself"
  fi
  return 0
}

detect_ca_certs() {
  local f
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [ -s "$f" ]; then
      plan ok "CA trust store" "heartbeat, gateway" "$f"
      return 0
    fi
  done
  # Nastier than it looks. The presence heartbeat is a real clearnet HTTPS POST
  # to syndichan.org (Proxy is deliberately nil so it does not go through I2P).
  # With no root certs, every peer-to-peer thing works perfectly and the node is
  # simply invisible to the site -- a split brain with no error anywhere the
  # operator is looking.
  REQUIRED_MISSING=1
  local p; p="$(pkg_name_for ca-certificates)"
  if [ -n "$p" ]; then
    pkg_add "$p"
    plan fix "CA trust store" "heartbeat, gateway" "no CA bundle found; will install $p"
  else
    plan manual "CA trust store" "heartbeat, gateway" "no CA bundle found; install your distro's ca-certificates package"
  fi
  return 0
}

detect_router_install() {
  # Which router, if any, is on this machine, and which unit owns it. The
  # shipped packaging/systemd/syndichan-node.service hardcodes
  # Requires=i2pd.service, which fails the node outright on a machine running
  # the Java router as i2p.service -- "Unit i2pd.service not found", before the
  # node ever tries SAM. The generated unit names the router actually found.
  if have i2pd || [ -f /etc/i2pd/i2pd.conf ]; then
    ROUTER_KIND="i2pd"
  elif have i2prouter || [ -f /usr/share/i2p/clients.config ] || [ -d /var/lib/i2p ]; then
    ROUTER_KIND="java"
  else
    ROUTER_KIND="none"
  fi
  local u
  for u in i2pd.service i2p.service; do
    if unit_exists "$u"; then
      ROUTER_UNIT="$u"
      [ "$u" = "i2pd.service" ] && ROUTER_KIND="i2pd"
      [ "$u" = "i2p.service" ] && [ "$ROUTER_KIND" = "none" ] && ROUTER_KIND="java"
      break
    fi
  done
  [ "$ROUTER_KIND" = "i2pd" ] && [ -f /etc/i2pd/i2pd.conf ] && I2PD_CONF="/etc/i2pd/i2pd.conf"
  return 0
}

detect_i2p() {
  local rc=0
  sam_probe || rc=$?
  detect_router_install

  if [ "$rc" = "0" ]; then
    # A live bridge answers the question completely. Do not install a router,
    # do not edit a router config, do not restart anything: only one process
    # can hold 7656, and a second router loses the bind and reports it in a log
    # nobody is reading. This is the property the whole I2P section exists to
    # protect -- an operator's working router is never touched.
    plan ok "I2P router (SAM)" "storage" "SAM v3 answered RESULT=OK on 127.0.0.1:7656 (${ROUTER_KIND:-unknown} router)"
    detect_router_boot
    return 0
  fi

  REQUIRED_MISSING=1
  if [ "$rc" = "3" ]; then
    plan manual "I2P router (SAM)" "storage" "127.0.0.1:7656 is held by something that does not speak SAM -- free that port first"
    return 0
  fi

  case "$ROUTER_KIND" in
    i2pd)
      DO_CONFIGURE_I2PD=1
      DO_START_ROUTER=1
      if [ -n "$I2PD_CONF" ]; then
        plan fix "I2P router (SAM)" "storage" "i2pd is installed but SAM is not answering; will assert [sam]/[httpproxy] in $I2PD_CONF (backed up, mode and owner preserved) and restart ${ROUTER_UNIT:-i2pd}"
      else
        DO_CONFIGURE_I2PD=0
        plan manual "I2P router (SAM)" "storage" "i2pd is installed but /etc/i2pd/i2pd.conf is missing; set [sam] enabled = true, address = 127.0.0.1, port = 7656 in your i2pd config"
      fi
      ;;
    java)
      # Deliberately NOT edited. Java I2P's clients.config is rewritten by the
      # router itself on shutdown, the SAM entry's index differs between the
      # monolithic file and the clients.config.d fragments, and an entry with
      # no startOnLoad line at all is silently unfixable by sed -- so the old
      # code could stop somebody's router, change nothing, restart it, and then
      # wait five minutes for a bridge that was never going to appear.
      # Reporting the exact two-click fix is both shorter and honest.
      plan manual "I2P router (SAM)" "storage" "Java I2P found but SAM is not answering; enable it at http://127.0.0.1:7657/configclients -> 'SAM application bridge' -> Start + 'Run at Startup', then re-run"
      detect_router_boot
      ;;
    *)
      local p; p="$(pkg_name_for i2pd)"
      if [ -n "$p" ]; then
        DO_INSTALL_I2PD=1
        DO_CONFIGURE_I2PD=1
        DO_ENABLE_ROUTER=1
        DO_START_ROUTER=1
        pkg_add "$p"
        ROUTER_KIND="i2pd"
        [ -z "$ROUTER_UNIT" ] && ROUTER_UNIT="i2pd.service"
        I2PD_CONF="/etc/i2pd/i2pd.conf"
        plan fix "I2P router (SAM)" "storage" "no router found; will install $p, enable its SAM bridge in /etc/i2pd/i2pd.conf, and enable+start $ROUTER_UNIT"
        if [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
          plan manual "i2pd repository" "storage" "i2pd is not in Fedora/RHEL's official repos; run 'dnf copr enable supervillain/i2pd' first"
        fi
      else
        plan manual "I2P router (SAM)" "storage" "no router found and no known package name here; install i2pd with SAM on 127.0.0.1:7656"
      fi
      ;;
  esac
  return 0
}

detect_router_boot() {
  # Without this the node starts after a reboot into nothing: SAM refused,
  # logger.Fatal, and a unit that looks broken when the router is the thing
  # that never came back.
  [ -n "$ROUTER_UNIT" ] || return 0
  if systemctl is-enabled "$ROUTER_UNIT" >/dev/null 2>&1; then
    plan ok "I2P router on boot" "storage" "$ROUTER_UNIT is enabled"
  else
    DO_ENABLE_ROUTER=1
    plan fix "I2P router on boot" "storage" "will run 'systemctl enable $ROUTER_UNIT' -- otherwise the node reboots into nothing"
  fi
  return 0
}

detect_i2p_proxy() {
  # Same daemon as SAM, but a SEPARATE port and a separate config switch. An
  # i2pd with SAM on and httpproxy off passes every 7656 check and still leaves
  # the node half-blind: the bootstrap document and every .i2p fetch go through
  # this proxy.
  if tcp_open 127.0.0.1 4444; then
    plan ok "I2P HTTP proxy" "storage" "127.0.0.1:4444 accepting connections"
  elif [ "$DO_CONFIGURE_I2PD" = "1" ]; then
    # Only claimed when this script actually owns the config it would change.
    plan fix "I2P HTTP proxy" "storage" "127.0.0.1:4444 not listening; [httpproxy] will be set in $I2PD_CONF alongside SAM"
  else
    plan manual "I2P HTTP proxy" "storage" "127.0.0.1:4444 not listening; enable your router's HTTP proxy on loopback (Java: http://127.0.0.1:7657/i2ptunnelmgr)"
  fi
  return 0
}

# --- the binary, and the toolchain that produces it -------------------------

go_base_version() { # go_base_version CMD -> "1.22.2", or nothing
  # Run from / with GOTOOLCHAIN=local so this reports the toolchain that is
  # actually INSTALLED. Inside the module directory, `go version` under the
  # default GOTOOLCHAIN=auto reports the toolchain go.mod asked for, which is
  # not the question being asked here.
  ( cd / && GOTOOLCHAIN=local "$1" version 2>/dev/null ) |
    sed -n 's/^go version go\([0-9][0-9.]*\).*/\1/p'
  return 0
}

go_new_enough() { # go_new_enough "1.22.2"
  local v="$1" major minor
  major="${v%%.*}"; v="${v#*.}"; minor="${v%%.*}"
  case "$major" in ""|*[!0-9]*) return 1 ;; esac
  case "$minor" in ""|*[!0-9]*) return 1 ;; esac
  [ "$major" -gt "$GO_MIN_MAJOR" ] && return 0
  [ "$major" -eq "$GO_MIN_MAJOR" ] && [ "$minor" -ge "$GO_MIN_MINOR" ] && return 0
  return 1
}

detect_binary() {
  local candidate
  if [ -n "$BINARY_SRC" ]; then
    [ -f "$BINARY_SRC" ] && [ -x "$BINARY_SRC" ] || die "--binary $BINARY_SRC is not an executable file"
    BINARY_RESOLVED="$BINARY_SRC"
    plan ok "syndichan-node binary" "all" "$BINARY_RESOLVED (given with --binary)"
    plan skip "Go toolchain" "building" "not needed; --binary was given"
    return 0
  fi
  for candidate in "$REPO_ROOT/syndichan-node" "$REPO_ROOT/dist/syndichan-node-linux-$GOARCH"; do
    if [ -x "$candidate" ]; then
      BINARY_RESOLVED="$candidate"
      plan ok "syndichan-node binary" "all" "$BINARY_RESOLVED"
      plan skip "Go toolchain" "building" "not needed; a built binary is already here"
      return 0
    fi
  done
  if [ ! -f "$REPO_ROOT/go.mod" ]; then
    REQUIRED_MISSING=1
    plan manual "syndichan-node binary" "all" "no binary here and no source tree ($REPO_ROOT/go.mod is missing); build it elsewhere and pass --binary PATH"
    return 0
  fi
  detect_go || return 0
  DO_BUILD_BINARY=1
  plan fix "syndichan-node binary" "all" "will run 'go build ./cmd/syndichan-node' in $REPO_ROOT (as ${SUDO_USER:-the invoking user}, never root)"
  return 0
}

# detect_go -- decide where the compiler comes from. Returns non-zero when
# there is no way to get one, having already recorded the reason.
detect_go() {
  local cmd="" ver=""
  if have go; then
    cmd="$(command -v go)"
  elif [ -x "$GO_ROOT_DEST/bin/go" ]; then
    cmd="$GO_ROOT_DEST/bin/go"
  fi
  if [ -n "$cmd" ]; then
    ver="$(go_base_version "$cmd")"
    if [ -n "$ver" ] && go_new_enough "$ver"; then
      GO_CMD="$cmd"
      # The build always passes GOTOOLCHAIN=auto explicitly, so a `go env -w
      # GOTOOLCHAIN=local` on this machine cannot break it. That download needs
      # network, which is why it is stated here rather than discovered.
      plan ok "Go toolchain" "building" "$cmd (go$ver); it will fetch the go$(sed -n 's/^go \([0-9.]*\)$/\1/p' "$REPO_ROOT/go.mod" | head -1) toolchain go.mod pins, over the network, if not already cached"
      return 0
    fi
    REQUIRED_MISSING=1
    plan manual "Go toolchain" "building" "$cmd is go${ver:-?}, older than $GO_MIN_MAJOR.$GO_MIN_MINOR and unable to fetch the pinned toolchain; upgrade it, or pass --binary PATH"
    plan manual "syndichan-node binary" "all" "cannot be built with the Go on this machine"
    return 1
  fi

  # Nothing usable. Bootstrap from go.dev -- the OFFICIAL source, with the
  # SHA-256 from the same signed-TLS index checked before anything is unpacked.
  # A distro package is deliberately not used here: half the supported distros
  # ship a Go too old for the pinned toolchain, and the point of this path is
  # to be distro-agnostic.
  local blocked=""
  [ -n "$GOARCH" ] || blocked="go.dev publishes no linux toolchain for '$ARCH_RAW'"
  if [ -z "$blocked" ] && ! have curl && ! have wget; then
    blocked="neither curl nor wget is installed, so nothing can be downloaded"
  fi
  if [ -z "$blocked" ] && ! have sha256sum; then
    blocked="sha256sum is missing, and an unverified toolchain will not be installed"
  fi
  if [ -z "$blocked" ] && ! have tar; then
    blocked="tar is missing"
  fi
  if [ -z "$blocked" ] && [ -e "$GO_ROOT_DEST" ]; then
    blocked="$GO_ROOT_DEST already exists and this installer will not write over somebody else's Go"
  fi
  if [ -n "$blocked" ]; then
    REQUIRED_MISSING=1
    plan manual "Go toolchain" "building" "no usable Go: $blocked. Install Go 1.21+ yourself, or build elsewhere and pass --binary PATH"
    plan manual "syndichan-node binary" "all" "no binary and no way to build one here"
    return 1
  fi
  DO_BOOTSTRAP_GO=1
  GO_CMD="$GO_ROOT_DEST/bin/go"
  local linking=""
  [ -e "$GO_BIN_LINK" ] || linking=", and symlink $GO_BIN_LINK"
  plan fix "Go toolchain" "building" "no Go here; will read https://go.dev/dl/?mode=json, download the newest stable go*.linux-$GOARCH.tar.gz over HTTPS, VERIFY its SHA-256 against that index, unpack to $GO_ROOT_DEST$linking"
  return 0
}

# --- service account, data directory, unit ----------------------------------

detect_service_user() {
  if [ "$INSTALL_SERVICE" = "0" ]; then
    plan skip "boot service" "auto-start" "--no-service: nothing will be written under /etc/systemd"
    plan skip "service account" "boot service" "--no-service: the node runs as you"
    return 0
  fi
  if id "$NODE_USER" >/dev/null 2>&1; then
    local uid; uid="$(id -u "$NODE_USER")"
    if [ "$uid" -ge 1000 ]; then
      # An ordinary login account with this name is somebody's, and the data
      # directory is about to be chowned to whatever this name resolves to.
      blocker "service account" "boot service" \
        "an ORDINARY user account named '$NODE_USER' already exists (uid $uid). This installer will not take over a human account, and will not chown anything to it."
      return 0
    fi
    NODE_GROUP="$(id -gn "$NODE_USER" 2>/dev/null || echo "$NODE_USER")"
    plan ok "service account" "boot service" "$NODE_USER exists (uid $uid, group $NODE_GROUP)"
  else
    DO_CREATE_USER=1
    plan fix "service account" "boot service" "will create system user $NODE_USER (no shell, no login, home $DATA_DIR)"
  fi

  [ "$HAVE_SYSTEMD" = "1" ] || return 0
  if [ ! -f "$UNIT_PATH" ]; then
    plan fix "boot service" "auto-start" "will write, enable and start $UNIT_PATH (runs as $NODE_USER, waits for SAM via $WAIT_HELPER, restarts on failure)"
  else
    local recorded body
    recorded="$(sed -n "s|^${MARKER_PREFIX}||p" "$UNIT_PATH" | head -1)"
    body="$(grep -v "^${MARKER_PREFIX}" "$UNIT_PATH" | sha_of)"
    if [ -n "$recorded" ] && [ "$recorded" = "$body" ]; then
      plan fix "boot service" "auto-start" "$UNIT_PATH was written by this installer; it will be refreshed if it has changed, then enabled and restarted"
    else
      plan manual "boot service" "auto-start" "$UNIT_PATH exists and was NOT written by this installer; it will be left alone (but still enabled and restarted)"
    fi
  fi
  plan fix "SAM readiness helper" "boot service" "will install $WAIT_HELPER, used as the unit's ExecStartPre"
  return 0
}

detect_data_dir() {
  # Rule 4 of the data-directory contract (see the option parsing above): an
  # existing directory is only adopted if it is empty or already ours. This is
  # what makes the chown safe rather than merely guarded.
  if [ -L "$DATA_DIR" ]; then
    blocker "data directory" "storage" \
      "$DATA_DIR is a SYMLINK; refusing to chown through it. Point --data-dir at a real directory."
  elif [ -e "$DATA_DIR" ] && [ ! -d "$DATA_DIR" ]; then
    blocker "data directory" "storage" "$DATA_DIR exists and is not a directory"
  elif [ -d "$DATA_DIR" ]; then
    local owner; owner="$(stat -c '%U' "$DATA_DIR" 2>/dev/null || echo "?")"
    if [ "$owner" != "$NODE_USER" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
      blocker "data directory" "storage" \
        "$DATA_DIR already exists, is NOT EMPTY, and is owned by '$owner' rather than '$NODE_USER'. Refusing to take ownership of it; pass an empty or new --data-dir."
    elif [ "$INSTALL_SERVICE" = "1" ]; then
      plan ok "data directory" "storage" "$DATA_DIR exists (owner $owner, $([ "$owner" = "$NODE_USER" ] && echo "already ours" || echo "empty")); will be chowned to $NODE_USER and chmod 0700 -- the leaf only, never recursively"
    fi
  elif [ "$INSTALL_SERVICE" = "1" ]; then
    plan fix "data directory" "storage" "will create $DATA_DIR owned by $NODE_USER, mode 0700"
  fi

  # capacity_bytes defaults to 20 GiB and NOTHING in the node compares it to
  # the disk.
  local avail want
  avail="$(free_mib "$DATA_DIR")"
  want="$(( ${CAPACITY_GIB:-20} * 1024 ))"
  if [ -n "$avail" ]; then
    if [ "$avail" -lt "$want" ]; then
      plan manual "free disk" "storage" "$((avail / 1024)) GiB free where $DATA_DIR will live, but the node would donate $((want / 1024)) GiB; pass --capacity-gib N"
    else
      plan ok "free disk" "storage" "$((avail / 1024)) GiB free for a $((want / 1024)) GiB donation"
    fi
  fi
  return 0
}

detect_state_conflicts() {
  if [ "$INSTALL_SERVICE" = "0" ]; then
    plan skip "configuration" "all" "--no-service: the node creates its own on first run (~/.config/Syndichan/storage-node)"
  elif [ -f "$CONFIG_FILE" ]; then
    plan ok "configuration" "all" "$CONFIG_FILE exists; only the flags you passed will be applied to it"
  else
    plan fix "configuration" "all" "will be created BY THE NODE, running as $NODE_USER, at $CONFIG_FILE"
  fi
  # Two instances on one data_dir collide on the bbolt flock in
  # <data_dir>/storage/metadata.db.
  if have pgrep && pgrep -f '[s]yndichan-node' >/dev/null 2>&1; then
    plan manual "running node" "all" "a syndichan-node process is already running; make sure it is not using $DATA_DIR"
  fi
  # The node's listeners are fatal on a bind clash: serve() calls
  # logger.Fatalf, so a taken port takes down the whole node, not just the page.
  local port
  for port in 9000 9090; do
    case "$port:$UI_LISTEN" in 9090:off|9090:none|9090:OFF|9090:None) continue ;; esac
    if tcp_open 127.0.0.1 "$port"; then
      if [ "$port" = "9090" ]; then
        plan manual "port 9090" "management page" "already in use; pass --ui-listen 127.0.0.1:PORT or --ui-listen off, or the node will exit at startup"
      else
        plan manual "port 9000" "S3 endpoint" "already in use; change s3_listen in $CONFIG_FILE before starting"
      fi
    fi
  done
  # Clock skew silently invalidates gateway registrations and probe results
  # (they carry 60-300s validity windows) and breaks clearnet TLS. Nothing in
  # the rejection message says "time".
  if have timedatectl; then
    if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)" = "yes" ]; then
      plan ok "clock" "heartbeat, gateway" "NTP synchronised"
    else
      plan manual "clock" "heartbeat, gateway" "not NTP-synchronised; enable systemd-timesyncd or chrony"
    fi
  fi
  return 0
}

# --- compute (opt-in) -------------------------------------------------------

DOCKER_OK=0
detect_docker() {
  if [ "$WANT_COMPUTE" = "0" ]; then
    plan skip "Docker Engine" "compute, DCS" "not requested (--with-compute)"
    return 0
  fi
  # The node CANNOT be trusted to detect this, which is why the installer must.
  # internal/dcs/runtime.go NewDockerClient only checks that the endpoint string
  # starts with "unix://" -- it never touches the socket. The DCS path pings
  # afterwards and disables itself cleanly; the COMPUTE path never pings, so a
  # machine with no daemon stands up the compute endpoints, answers "admitted"
  # to jobs, and then fails every one of them at container creation.
  local sock="/var/run/docker.sock"
  if unit_exists docker.service; then DOCKER_UNIT="docker.service"; fi

  if [ -S "$sock" ] && { { have curl && curl -s -o /dev/null --max-time 5 --unix-socket "$sock" http://localhost/_ping; } ||
                         { have docker && docker info >/dev/null 2>&1; }; }; then
    DOCKER_OK=1
    plan ok "Docker Engine" "compute" "$sock answered"
    detect_docker_group
    return 0
  fi

  REQUIRED_MISSING=1
  if [ ! -S "$sock" ]; then
    local p; p="$(pkg_name_for docker)"
    if [ -n "$p" ]; then
      pkg_add "$p"
      DO_ENABLE_DOCKER=1
      plan fix "Docker Engine" "compute" "no $sock; will install $p and run 'systemctl enable --now docker'"
    else
      plan manual "Docker Engine" "compute" "no $sock and no known package name here; install docker and start the daemon"
    fi
  elif [ -n "$DOCKER_UNIT" ]; then
    DO_ENABLE_DOCKER=1
    plan fix "Docker Engine" "compute" "$sock exists but did not answer; will run 'systemctl enable --now $DOCKER_UNIT'"
  else
    plan manual "Docker Engine" "compute" "$sock exists but did not answer /_ping -- start the daemon, or this user cannot open the socket"
  fi
  detect_docker_group
  return 0
}

detect_docker_group() {
  [ "$WANT_COMPUTE" = "1" ] || return 0
  [ "$INSTALL_SERVICE" = "1" ] || return 0
  # Announced as its own row because it is not a small thing: the docker group
  # is root-equivalent by design.
  if getent group docker >/dev/null 2>&1 &&
     id -nG "$NODE_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    plan ok "docker group" "compute" "$NODE_USER is already in the docker group"
    return 0
  fi
  DO_ADD_DOCKER_GROUP=1
  plan fix "docker group" "compute" "will add $NODE_USER to the docker group (ROOT-EQUIVALENT) and write $UNIT_DROPIN, which turns off PrivateDevices and MemoryDenyWriteExecute"
  return 0
}

detect_catalogue_images() {
  [ "$WANT_COMPUTE" = "1" ] || return 0
  # There is NO ImagePull anywhere in the Go tree and registry.local is not a
  # real registry, so these tags only exist if they were built on THIS machine.
  # Absent, every dispatched job dies "No such image" -- after the submitter has
  # already been told the job was admitted.
  if [ "$DOCKER_OK" = "0" ]; then
    plan manual "catalogue images" "compute" "cannot be checked without a working Docker daemon; re-run --check afterwards"
    return 0
  fi
  local missing="" lang
  for lang in python go c embed; do
    docker image inspect "registry.local/compute-$lang:latest" >/dev/null 2>&1 || missing="$missing $lang"
  done
  if [ -z "$missing" ]; then
    plan ok "catalogue images" "compute" "registry.local/compute-{python,go,c,embed}:latest present"
    return 0
  fi
  # Deliberately not offered as an action: compute-images/build.sh also runs
  # `k3s ctr images import`, which fails on any machine without k3s -- after the
  # docker build already succeeded, so the failure looks like the build failed
  # when it did not.
  if [ -d "$REPO_ROOT/../compute-images" ]; then
    plan manual "catalogue images" "compute" "missing:$missing -- build with: for l in$missing; do docker build -t registry.local/compute-\$l:latest $(cd "$REPO_ROOT/.." && pwd)/compute-images/\$l; done"
  else
    plan manual "catalogue images" "compute" "missing:$missing -- and compute-images/ is not next to this checkout; fetch it from the maniwani repo and docker build each one"
  fi
  return 0
}

detect_kvm() {
  # DETECTION ONLY, ALWAYS. Nothing in this section can be installed: the CPU
  # either exposes virtualisation or it does not, and on a VPS without nested
  # virtualisation no package on earth changes that. Say so plainly instead of
  # sending the operator to install a hypervisor on a machine that cannot run
  # one.
  [ "$WANT_COMPUTE" = "1" ] || return 0
  # Matched against the flags LINE, not the whole file: "vmx" and "svm" are
  # short enough to appear inside a CPU model name, and a substring search over
  # /proc/cpuinfo would claim virtualisation on the strength of marketing text.
  #
  # This pipeline is the reason `set -o pipefail` is off at the top of the file:
  # grep -q closes the pipe on its first match, the upstream grep dies of
  # SIGPIPE, and with pipefail on the whole test inverted and reported "no vmx"
  # on a CPU that has it.
  if ! grep -E '^(flags|Features)[[:space:]]*:' /proc/cpuinfo 2>/dev/null |
       grep -qE '(^|[[:space:]])(vmx|svm)([[:space:]]|$)'; then
    plan cannot "/dev/kvm (microVM)" "arbitrary-code compute" "CPU reports no vmx/svm -- CANNOT be installed; enable virtualisation in firmware, or this host offers no nested virt"
  elif [ ! -e /dev/kvm ]; then
    plan cannot "/dev/kvm (microVM)" "arbitrary-code compute" "CPU is capable but /dev/kvm is absent -- load kvm_intel/kvm_amd, or the hypervisor does not pass virt through. Not a package"
  elif { exec 4<>/dev/kvm; } 2>/dev/null; then
    # OPENED, not stat'ed: mode bits and group membership are two independent
    # ways to be wrong about the same question, and a POSIX ACL can grant access
    # that neither mentions. This is what internal/compute/microvm_linux.go
    # does, so it gives the same answer the node will.
    exec 4>&-
    plan ok "/dev/kvm (microVM)" "arbitrary-code compute" "openable read-write by $(id -un)"
  else
    plan manual "/dev/kvm (microVM)" "arbitrary-code compute" "present but not openable by $(id -un); usually: usermod -aG kvm $NODE_USER"
  fi
  if have firecracker; then
    plan ok "firecracker" "arbitrary-code compute" "$(command -v firecracker)"
  else
    plan manual "firecracker" "arbitrary-code compute" "optional; not packaged by any distro -- put the release binary from github.com/firecracker-microvm/firecracker in /usr/local/bin"
  fi
  # Never fetched automatically, and that is a policy decision rather than an
  # oversight: a node that fetched and booted a kernel somebody else chose would
  # have handed over the machine in the act of protecting it.
  plan manual "guest kernel + rootfs" "arbitrary-code compute" "operator-supplied on purpose; set compute.microvm_kernel and compute.microvm_rootfs in $CONFIG_FILE. This installer will never download a kernel"
  return 0
}

# ---------------------------------------------------------------------------
# REPORT
# ---------------------------------------------------------------------------

print_plan() {
  local i status label
  printf '\n%sDependency report%s  (compute=%s, boot service=%s, data dir=%s)\n\n' \
    "$C_BOLD" "$C_RESET" \
    "$([ "$WANT_COMPUTE" = 1 ] && echo yes || echo no)" \
    "$([ "$INSTALL_SERVICE" = 1 ] && echo yes || echo no)" \
    "$DATA_DIR"
  printf '  %-8s %-22s %-24s %s\n' "STATUS" "DEPENDENCY" "NEEDED FOR" "DETAIL"
  printf '  %-8s %-22s %-24s %s\n' "------" "----------" "----------" "------"
  i=0
  while [ "$i" -lt "${#PLAN_STATUS[@]}" ]; do
    status="${PLAN_STATUS[$i]}"
    case "$status" in
      ok)     label="${C_GREEN}ok${C_RESET}     " ;;
      fix)    label="${C_YELLOW}install${C_RESET}" ;;
      manual) label="${C_YELLOW}manual${C_RESET} " ;;
      cannot) label="${C_RED}cannot${C_RESET} " ;;
      skip)   label="${C_DIM}skip${C_RESET}   " ;;
      *)      label="$status" ;;
    esac
    printf '  %b %-22s %-24s %s\n' "$label" "${PLAN_NAME[$i]}" "${PLAN_FOR[$i]}" "${PLAN_DETAIL[$i]}"
    i=$((i + 1))
  done
  printf '\n'
  if [ "${#PKGS[@]}" -gt 0 ]; then
    local cmd; cmd="$(install_cmd_for ${PKGS[@]+"${PKGS[@]}"})"
    if [ -n "$cmd" ]; then
      printf '%sPackages to install:%s %s\n  sudo %s\n\n' "$C_BOLD" "$C_RESET" "${PKGS[*]}" "$cmd"
    else
      printf '%sNo known package manager here.%s Install these with whatever your system\nuses, then re-run:\n  %s\n\n' \
        "$C_BOLD" "$C_RESET" "${PKGS[*]}"
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# ACT
#
# Everything below runs as root (checked before the consent prompt) and every
# function is a no-op unless the matching DO_* flag was set during DETECT.
# ---------------------------------------------------------------------------

run() { # run a command as root, echoing it first so nothing is a surprise
  printf '    %s+%s %s\n' "$C_DIM" "$C_RESET" "$*"
  "$@"
}

# run_as_node -- run a command as the service account, never as root.
#
# runuser is preferred over `sudo -u`: it is part of util-linux (present
# wherever systemd is) and does not depend on a sudoers policy that may not
# permit user-switching. HOME is always set because config.Default() calls
# os.UserConfigDir() unconditionally, even when -config names an exact path, so
# a system account with no HOME makes the node exit before it reads the file it
# was pointed at.
run_as_node() {
  if have runuser; then
    run runuser -u "$NODE_USER" -- env HOME="$DATA_DIR" "$@"
  elif have setpriv && have getent; then
    run setpriv --reuid "$NODE_USER" --regid "$NODE_GROUP" --clear-groups \
      env HOME="$DATA_DIR" "$@"
  else
    run sudo -u "$NODE_USER" env HOME="$DATA_DIR" "$@"
  fi
}

confirm() {
  [ "$ASSUME_YES" = "1" ] && return 0
  local answer=""
  printf '%s%s%s [y/N] ' "$C_BOLD" "$1" "$C_RESET"
  IFS= read -r answer || answer=""
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

install_packages() {
  [ "${#PKGS[@]}" -gt 0 ] || return 0
  local cmd; cmd="$(install_cmd_for ${PKGS[@]+"${PKGS[@]}"})"
  if [ -z "$cmd" ]; then
    warn "no package manager here; install these yourself and re-run: ${PKGS[*]}"
    return 0
  fi
  step "Installing packages: ${PKGS[*]}"
  if [ "$PKG_MGR" = "apt" ]; then
    run apt-get update
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y ${PKGS[@]+"${PKGS[@]}"}
  else
    # shellcheck disable=SC2086  # cmd is built by install_cmd_for, not user input
    run $cmd
  fi
  return 0
}

# i2pd_set_key SECTION KEY VALUE FILE
#
# i2pd has no conf.d for its main config, so the settings have to go INTO
# i2pd.conf. This rewrites one key inside one section, uncommenting it if the
# shipped file has it commented out (which it does for the whole [sam] block),
# and appending the section if it is absent entirely. Writing only when the
# content actually changes is what makes a second run a no-op instead of a
# growing pile of duplicate keys.
#
# The awk is verified byte-identical on a second pass. Do not rewrite it
# casually.
#
# The repo's packaging/systemd/i2pd-syndichan.default is NOT used, on purpose:
# upstream's systemd unit has no EnvironmentFile and hardcodes its ExecStart,
# so $DAEMON_OPTS from /etc/default/i2pd is read only by the sysvinit script.
# Dropping that file on a systemd box applies none of its flags, silently.
#
# Returns 0 if the file changed, 1 if it was already correct.
i2pd_set_key() {
  local section="$1" key="$2" value="$3" file="$4" tmp mode uid gid
  tmp="$(workdir)/i2pd.conf.new"
  awk -v sect="$section" -v key="$key" -v val="$value" '
    BEGIN { cur = ""; done = 0 }
    /^[[:space:]]*\[/ {
      if (cur == sect && !done) { print key " = " val; done = 1 }
      s = $0; sub(/^[[:space:]]*\[/, "", s); sub(/\].*$/, "", s)
      cur = s
      print; next
    }
    {
      if (cur == sect && !done && $0 ~ ("^[[:space:]]*#*[[:space:]]*" key "[[:space:]]*=")) {
        print key " = " val; done = 1; next
      }
      print
    }
    END {
      if (!done) {
        if (cur != sect) print "[" sect "]"
        print key " = " val
      }
    }
  ' "$file" >"$tmp"
  if cmp -s "$tmp" "$file"; then
    return 1
  fi
  # Mode and ownership are carried over from the file being replaced. The old
  # code used `install -m 0644`, which quietly WIDENED a config an operator had
  # deliberately locked down, and handed it to root:root besides.
  mode="$(stat -c '%a' "$file")"
  uid="$(stat -c '%u' "$file")"
  gid="$(stat -c '%g' "$file")"
  run install -m "$mode" -o "$uid" -g "$gid" "$tmp" "$file"
  return 0
}

configure_i2pd() {
  [ "$DO_CONFIGURE_I2PD" = "1" ] || return 0
  # After a fresh package install the config exists even though DETECT could not
  # see it.
  [ -n "$I2PD_CONF" ] || I2PD_CONF="/etc/i2pd/i2pd.conf"
  if [ ! -f "$I2PD_CONF" ]; then
    warn "$I2PD_CONF is not there after installation; enable SAM by hand: [sam] enabled = true, address = 127.0.0.1, port = 7656"
    return 0
  fi
  step "Configuring i2pd: $I2PD_CONF"
  [ -f "$I2PD_CONF.syndichan.bak" ] || run cp -p "$I2PD_CONF" "$I2PD_CONF.syndichan.bak"
  local changed=0
  # SAM is enabled by default on i2pd >= 2.28, so most of these are assertions
  # rather than edits. Assert anyway: the one failure mode is a pre-existing
  # config where somebody uncommented enabled = false, and that is invisible
  # from the outside until the node dies at startup.
  i2pd_set_key sam enabled true "$I2PD_CONF" && changed=1
  i2pd_set_key sam address 127.0.0.1 "$I2PD_CONF" && changed=1
  i2pd_set_key sam port 7656 "$I2PD_CONF" && changed=1
  i2pd_set_key httpproxy enabled true "$I2PD_CONF" && changed=1
  i2pd_set_key httpproxy address 127.0.0.1 "$I2PD_CONF" && changed=1
  i2pd_set_key httpproxy port 4444 "$I2PD_CONF" && changed=1
  # i2pd's stock outproxy is the placeholder http://false.i2p, so clearnet
  # fetches through the I2P proxy fail on a default install even though SAM is
  # perfectly healthy. Only replaced when it is still that placeholder.
  if grep -qE '^[[:space:]]*outproxy[[:space:]]*=[[:space:]]*http' "$I2PD_CONF" &&
     ! grep -qE '^[[:space:]]*outproxy[[:space:]]*=.*false\.i2p' "$I2PD_CONF"; then
    note "keeping the outproxy already configured in $I2PD_CONF"
  else
    i2pd_set_key httpproxy outproxy http://exit.stormycloud.i2p "$I2PD_CONF" && changed=1
  fi
  [ "$changed" = "0" ] && note "already configured; nothing changed"
  return 0
}

start_router() {
  [ -n "$ROUTER_UNIT" ] || return 0
  if [ "$DO_ENABLE_ROUTER" = "1" ]; then
    step "Enabling $ROUTER_UNIT on boot"
    run systemctl enable "$ROUTER_UNIT" || warn "could not enable $ROUTER_UNIT"
  fi
  [ "$DO_START_ROUTER" = "1" ] || return 0
  # `restart` only when this script actually changed the router's config.
  # Restarting somebody's healthy router drops every tunnel it has built, and
  # "SAM is off" is not a reason to do that to them.
  if [ "$DO_CONFIGURE_I2PD" = "1" ]; then
    step "Restarting $ROUTER_UNIT (its configuration changed)"
    run systemctl restart "$ROUTER_UNIT" || warn "could not restart $ROUTER_UNIT"
  else
    step "Starting $ROUTER_UNIT"
    run systemctl start "$ROUTER_UNIT" || warn "could not start $ROUTER_UNIT"
  fi
  return 0
}

start_docker() {
  [ "$DO_ENABLE_DOCKER" = "1" ] || return 0
  local unit="${DOCKER_UNIT:-docker.service}"
  step "Enabling and starting $unit"
  run systemctl enable --now "$unit" || warn "could not start $unit; check 'systemctl status $unit'"
  return 0
}

# --- Go bootstrap -----------------------------------------------------------

fetch_to() { # fetch_to URL OUTFILE -- HTTPS only, certificates always verified
  # curl/wget are invoked without any flag that weakens TLS. If you are ever
  # tempted to add -k or --no-check-certificate here: the whole point of this
  # function is that a root-run installer is downloading a compiler.
  if have curl; then
    run curl -fsSL --proto '=https' --tlsv1.2 --max-time 900 --retry 2 -o "$2" "$1"
  elif have wget; then
    run wget -q -O "$2" "$1"
  else
    return 127
  fi
}

bootstrap_go() {
  [ "$DO_BOOTSTRAP_GO" = "1" ] || return 0
  local work index entry tarball sha url staging actual need_mib

  # ~250 MB compressed and ~1 GB unpacked; both need somewhere to live, and a
  # tarball that runs out of disk halfway through hashes to something that
  # looks exactly like tampering.
  work="$(workdir)"
  for need_mib in "$work:1500" "/usr/local:1500"; do
    local where="${need_mib%%:*}" want="${need_mib##*:}" avail
    avail="$(free_mib "$where")"
    if [ -n "$avail" ] && [ "$avail" -lt "$want" ]; then
      die "only ${avail} MiB free on the filesystem holding $where; the Go toolchain needs about ${want} MiB. Free some space, or build elsewhere and pass --binary PATH."
    fi
  done

  step "Fetching the Go release index from https://go.dev/dl/?mode=json"
  index="$work/go-dl.json"
  fetch_to 'https://go.dev/dl/?mode=json' "$index" ||
    die "could not download the Go release index. This machine needs outbound HTTPS to go.dev, or build elsewhere and pass --binary PATH."
  [ -s "$index" ] || die "the Go release index came back empty"

  # The index is a JSON array of releases, newest stable first, each with a
  # "files" array. Every file object is flat, so stripping whitespace and
  # splitting on '{' puts exactly one file per line and the FIRST match is the
  # newest stable build for this architecture. `grep -m1` closes the pipe early
  # -- harmless only because pipefail is off (see the note at the top).
  entry="$(tr -d ' \n\t' <"$index" | tr '{' '\n' |
    grep -m1 "\"filename\":\"go[0-9][0-9.]*\.linux-$GOARCH\.tar\.gz\",\"os\":\"linux\",\"arch\":\"$GOARCH\",.*\"kind\":\"archive\"")" || true
  [ -n "$entry" ] || die "no linux-$GOARCH archive in the Go release index. Install Go yourself, or pass --binary PATH."

  tarball="$(printf '%s' "$entry" | sed -n 's/.*"filename":"\([^"]*\)".*/\1/p')"
  sha="$(printf '%s' "$entry" | sed -n 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p')"
  # Nothing from the network is used before it is checked. The filename becomes
  # part of a URL and a path; the digest is the only thing standing between a
  # compromised mirror and root on this machine.
  case "$tarball" in
    go[0-9]*".linux-$GOARCH.tar.gz") ;;
    *) die "the Go index offered an unexpected filename: '$tarball'. Refusing to download it." ;;
  esac
  case "$sha" in
    *[!0-9a-f]*|"") die "the Go index carried no usable SHA-256 for $tarball. Refusing to install an unverified toolchain." ;;
  esac
  [ "${#sha}" -eq 64 ] || die "malformed SHA-256 for $tarball"

  url="https://go.dev/dl/$tarball"
  step "Downloading $tarball"
  note "expected SHA-256: $sha"
  fetch_to "$url" "$work/$tarball" || die "download failed: $url"

  step "Verifying SHA-256"
  actual="$(sha256sum "$work/$tarball" | awk '{print $1}')"
  if [ "$actual" != "$sha" ]; then
    rm -f -- "$work/$tarball"
    die "SHA-256 MISMATCH for $tarball
    expected $sha  (from https://go.dev/dl/?mode=json)
    actual   $actual
The download was discarded and nothing was installed. Do not retry blindly:
this is either a corrupted transfer or a tampered mirror."
  fi
  note "verified: $actual"

  # Unpacked into a staging directory on the same filesystem and moved into
  # place, so a failure never leaves a half-populated /usr/local/go that a later
  # run would then refuse to touch.
  [ -e "$GO_ROOT_DEST" ] && die "$GO_ROOT_DEST appeared while this was running; refusing to overwrite it"
  staging="/usr/local/.syndichan-go-unpack.$$"
  run rm -rf -- "$staging"
  run mkdir -p -- "$staging"
  step "Unpacking to $GO_ROOT_DEST"
  # The official linux tarballs are statically linked (verified against
  # go1.25.12.linux-amd64: `file bin/go` reports "statically linked"), so they
  # run on musl/Alpine as well as glibc. The node itself is built with
  # CGO_ENABLED=0, so no C toolchain is needed either.
  run tar -C "$staging" -xzf "$work/$tarball"
  [ -x "$staging/go/bin/go" ] || { run rm -rf -- "$staging"; die "the Go archive did not contain go/bin/go"; }
  run mv -- "$staging/go" "$GO_ROOT_DEST"
  run rmdir -- "$staging"

  # Only if the name is free. An operator's own Go is never shadowed: detect_go
  # would have used it, and this link is skipped if anything already holds it.
  if [ ! -e "$GO_BIN_LINK" ]; then
    run ln -s "$GO_ROOT_DEST/bin/go" "$GO_BIN_LINK"
    note "$GO_BIN_LINK -> $GO_ROOT_DEST/bin/go (scripts/update-from-github.sh needs go on PATH)"
  else
    note "$GO_BIN_LINK already exists; left alone. Add $GO_ROOT_DEST/bin to PATH yourself."
  fi
  GO_CMD="$GO_ROOT_DEST/bin/go"
  note "installed $("$GO_CMD" version)"
  return 0
}

build_binary() {
  [ "$DO_BUILD_BINARY" = "1" ] || return 0
  [ -n "$GO_CMD" ] || die "internal error: asked to build with no Go toolchain"
  # The build below reaches another user's shell through `sh -c`, so the path is
  # single-quoted. A checkout path containing a single quote would escape that;
  # refuse rather than mis-execute.
  case "$REPO_ROOT" in
    *"'"*) die "the checkout path contains a single quote and cannot be built from safely: $REPO_ROOT" ;;
  esac
  step "Building syndichan-node from $REPO_ROOT"
  # GOTOOLCHAIN=auto is passed explicitly so a `go env -w GOTOOLCHAIN=local` on
  # this machine cannot break the build: go.mod pins go 1.25.12, and any Go from
  # 1.21 up fetches exactly that on demand.
  local build="cd '$REPO_ROOT' && CGO_ENABLED=0 GOTOOLCHAIN=auto '$GO_CMD' build -trimpath -ldflags='-s -w' -o '$REPO_ROOT/syndichan-node' ./cmd/syndichan-node"
  # Built as the human who invoked the script, never as root. A root-owned
  # GOCACHE and root-owned objects inside somebody's checkout is a mess that
  # outlives the install and shows up later as a build that fails for the
  # account owning the source.
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ] && have runuser; then
    run runuser -u "$SUDO_USER" -- sh -c "$build"
  else
    warn "building as root; the build cache and output will be root-owned"
    run sh -c "$build"
  fi
  BINARY_RESOLVED="$REPO_ROOT/syndichan-node"
  return 0
}

create_user_and_dirs() {
  [ "$INSTALL_SERVICE" = "1" ] || return 0
  if [ "$DO_CREATE_USER" = "1" ]; then
    step "Creating system user $NODE_USER"
    if have useradd; then
      run useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$NODE_USER"
    elif have adduser; then
      run adduser --system --home "$DATA_DIR" --no-create-home --disabled-password "$NODE_USER"
    else
      die "no useradd/adduser here; create the $NODE_USER system account yourself and re-run"
    fi
    NODE_GROUP="$(id -gn "$NODE_USER" 2>/dev/null || echo "$NODE_USER")"
  fi

  # Re-checked here, immediately before the only chown this script performs,
  # because DETECT ran minutes ago and the plan the operator agreed to said
  # "empty, or already ours".
  if [ -d "$DATA_DIR" ] && [ ! -L "$DATA_DIR" ]; then
    local owner; owner="$(stat -c '%U' "$DATA_DIR")"
    if [ "$owner" != "$NODE_USER" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
      die "$DATA_DIR is not empty and is owned by '$owner'; refusing to chown it"
    fi
  elif [ -e "$DATA_DIR" ]; then
    die "$DATA_DIR is not a plain directory; refusing to chown it"
  fi

  step "Preparing $DATA_DIR"
  run mkdir -p -- "$(dirname "$DATA_DIR")"
  # install -d applies mode and ownership to the leaf only. Never chown -R:
  # even a mistake that got past every guard above touches one inode.
  run install -d -m 0700 -o "$NODE_USER" -g "$NODE_GROUP" -- "$DATA_DIR"
  return 0
}

install_binary() {
  [ -n "$BINARY_RESOLVED" ] || return 0
  step "Installing $BIN_DEST"
  if [ "$HAVE_SYSTEMD" = "1" ] && systemctl is-active --quiet syndichan-node.service 2>/dev/null; then
    # Replacing a running binary in place gives ETXTBSY. The enable/start at the
    # end brings it back; the plan row for "boot service" says so.
    run systemctl stop syndichan-node.service || true
  fi
  run install -d -m 0755 "$PREFIX/bin"
  run install -m 0755 "$BINARY_RESOLVED" "$BIN_DEST"
  return 0
}

create_config() {
  [ "$INSTALL_SERVICE" = "1" ] || return 0
  # Minted BY THE NODE, AS THE SERVICE USER. LoadOrCreate writes config.json
  # mode 0600 owned by whoever runs it, sets data_dir to the config file's own
  # directory, and generates the S3 credentials -- so a root-generated config is
  # a file the service cannot read, holding keys nobody asked for.
  #
  # -show-config rather than -config-path: both create the file and exit without
  # binding a listener, but applyHeadlessFlags checks printPath FIRST and
  # returns before -payout/-capacity-gib/-ui-listen are applied, so -config-path
  # cannot be used to save settings.
  local args=()
  [ -n "$PAYOUT" ] && args+=(-payout "$PAYOUT")
  [ -n "$CAPACITY_GIB" ] && args+=(-capacity-gib "$CAPACITY_GIB")
  [ -n "$UI_LISTEN" ] && args+=(-ui-listen "$UI_LISTEN")
  step "Creating/updating $CONFIG_FILE as $NODE_USER"
  run_as_node "$BIN_DEST" -config "$CONFIG_FILE" ${args[@]+"${args[@]}"} -show-config >/dev/null ||
    warn "the node refused the configuration; run it by hand to see why:
    runuser -u $NODE_USER -- env HOME='$DATA_DIR' $BIN_DEST -config '$CONFIG_FILE' -show-config"
  return 0
}

install_wait_helper() {
  [ "$INSTALL_SERVICE" = "1" ] || return 0
  step "Installing $WAIT_HELPER"
  local tmp; tmp="$(workdir)/wait-for-sam"
  cat >"$tmp" <<'HELPER'
#!/usr/bin/env bash
set -u
# Wait for the local I2P SAM bridge, then exit 0.
#
# Installed by syndichan-node's installer and used as the service's
# ExecStartPre. It exists because the node has NO startup retry: p2p.Open ->
# i2p.Open -> connectSAM fails, main.go calls logger.Fatal, and the process is
# gone. systemd's After= only orders against the ROUTER UNIT, which is up long
# before its SAM bridge is (Java I2P delays the SAM client app by 120 seconds
# while the console answers immediately).
#
# Probes SAM itself -- never the console on 7657/7070, which proves nothing --
# with the same HELLO exchange internal/i2p/sam.go performs.
#
# Safe to run by hand: `/usr/local/lib/syndichan/wait-for-sam 30` is the
# quickest answer to "is my router actually ready?".
budget="${1:-300}"
waited=0
while :; do
  line=""
  if { exec 3<>/dev/tcp/127.0.0.1/7656; } 2>/dev/null; then
    if printf 'HELLO VERSION MIN=3.1 MAX=3.3\n' >&3 2>/dev/null && IFS= read -r -t 10 line <&3; then
      exec 3>&-
      case "$line" in
        "HELLO REPLY"*RESULT=OK*)
          echo "syndichan: I2P SAM bridge ready after ${waited}s"
          exit 0 ;;
        *)
          # Something owns 7656 and does not speak SAM. Waiting cannot fix a
          # port collision, and pretending otherwise hides it.
          echo "syndichan: 127.0.0.1:7656 is not a SAM bridge: ${line}" >&2
          exit 1 ;;
      esac
    fi
    exec 3>&-
  fi
  if [ "$waited" -ge "$budget" ]; then
    echo "syndichan: I2P SAM bridge did not answer within ${budget}s" >&2
    exit 1
  fi
  sleep 2
  waited=$((waited + 2))
done
HELPER
  run install -d -m 0755 "$PREFIX/lib/syndichan"
  run install -m 0755 "$tmp" "$WAIT_HELPER"
  return 0
}

# generate_unit -- the unit body, without the marker line.
#
# EVERY interpolated path is quoted. systemd honours double quotes in Exec
# lines, Environment= and ReadWritePaths=, and a data directory containing a
# space silently truncated all three before this was fixed. (Characters systemd
# cannot express at all -- % and quotes and backslashes -- are refused during
# option parsing instead.)
generate_unit() {
  local wants="network-online.target"
  [ -n "$ROUTER_UNIT" ] && wants="$wants $ROUTER_UNIT"
  cat <<EOF
[Unit]
Description=Syndichan encrypted volunteer storage and edge node
Documentation=https://github.com/Jonathan-R-Anderson/syndichan/tree/main/storage-client
Wants=$wants
After=$wants
# Wants=, not Requires=. The shipped packaging/systemd/syndichan-node.service
# uses Requires=i2pd.service, which fails the node outright on a machine whose
# router unit is named i2p.service (Java I2P) -- and takes the node down with
# the router whenever the router restarts. Ordering plus the readiness wait
# below does the same job without the shared fate.
#
# Generous rate limit: a cold router can take longer than the node's 75s SAM
# command timeout to build its first tunnels, and the right answer to that is to
# keep retrying, not to give up after five tries in ten seconds.
StartLimitIntervalSec=600
StartLimitBurst=20

[Service]
Type=simple
User=$NODE_USER
Group=$NODE_GROUP
# config.Default() calls os.UserConfigDir() unconditionally, so a missing HOME
# makes the node exit before it reads the -config file it was handed.
Environment="HOME=$DATA_DIR"
# The node has no startup retry. This is what stops systemd racing the router.
ExecStartPre=$WAIT_HELPER $SAM_WAIT_SECONDS
# No posture flags. The node registers exactly six: -config, -payout,
# -capacity-gib, -ui-listen, -show-config, -config-path. Run mode and data
# directory live in the config file; passing -data-dir (as the shipped unit
# once did) exits 2 with "flag provided but not defined".
ExecStart=$BIN_DEST -config "$CONFIG_FILE"
Restart=on-failure
RestartSec=15s
# Longer than systemd's 90s default, because the ExecStartPre wait above can
# legitimately take ~120s on a Java router, and a start job killed mid-wait
# marks the unit failed for a router that was about to work.
TimeoutStartSec=$((SAM_WAIT_SECONDS + 120))
TimeoutStopSec=75s
LimitNOFILE=65535

# Only low-port binding, and only for the gateway role. The process is not root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths="$DATA_DIR"

[Install]
WantedBy=multi-user.target
EOF
  return 0
}

generate_compute_dropin() {
  # SupplementaryGroups= naming a group that does not exist makes systemd REFUSE
  # TO START the unit ("failed to determine supplementary groups"), so the list
  # is built from the groups this machine actually has.
  local groups="" g
  for g in docker kvm; do
    getent group "$g" >/dev/null 2>&1 && groups="$groups $g"
  done
  groups="${groups# }"
  cat <<EOF
# Compute/DCS relaxations for syndichan-node.
#
# Written because the hardened unit silently disables the very features being
# turned on: PrivateDevices=true gives the service a private /dev with no
# /dev/kvm (so microVM isolation can never be advertised), and the service
# user's docker group is only useful if systemd actually applies it.
#
# HARDENING GIVEN UP HERE, out loud:
#   - PrivateDevices: the service can now see the real /dev.
#   - MemoryDenyWriteExecute: firecracker children need W^X relaxed.
#   - the docker group is root-equivalent by design. A node that lends compute
#     is trusting the container runtime with the machine; that is the deal.
[Service]
PrivateDevices=false
DeviceAllow=/dev/kvm rw
MemoryDenyWriteExecute=false
${groups:+SupplementaryGroups=$groups}
# ProtectSystem=strict leaves /run read-only. Connecting to a socket is not a
# filesystem write, so this should be unnecessary -- it is here because
# "should" is not how an operator wants to find out.
ReadWritePaths=/run/docker.sock
EOF
  return 0
}

install_unit() {
  [ "$INSTALL_SERVICE" = "1" ] || { note "skipping the boot service (--no-service)"; return 0; }
  if [ "$HAVE_SYSTEMD" = "0" ]; then
    warn "no systemd here. Start the node with:"
    say "    runuser -u $NODE_USER -- env HOME='$DATA_DIR' $BIN_DEST -config '$CONFIG_FILE'"
    return 0
  fi
  local body hash tmp recorded existing
  body="$(generate_unit)"
  hash="$(printf '%s\n' "$body" | sha_of)"

  if [ -f "$UNIT_PATH" ]; then
    # Idempotency with a conscience. The marker records the hash of the unit
    # body we last wrote. If the file on disk still hashes to what we recorded,
    # this script wrote it and may replace it. If it does not, somebody edited
    # it -- possibly to fix something -- and overwriting that silently is how an
    # installer destroys a working machine.
    recorded="$(sed -n "s|^${MARKER_PREFIX}||p" "$UNIT_PATH" | head -1)"
    existing="$(grep -v "^${MARKER_PREFIX}" "$UNIT_PATH" | sha_of)"
    if [ -z "$recorded" ] || [ "$recorded" != "$existing" ]; then
      # Written to /run, not the scratch directory, so it outlives this process
      # for the operator to diff -- and disappears at the next reboot rather
      # than accumulating.
      tmp="/run/syndichan-node.service.proposed"
      printf '%s\n' "$body" >"$tmp"
      warn "$UNIT_PATH was written or edited by somebody else; NOT overwriting it."
      note "the unit this installer would write has been left at: $tmp"
      note "compare with: diff -u '$UNIT_PATH' '$tmp'"
      # Their unit is kept, but it is still enabled and started: the operator
      # asked for a node that comes back after a reboot, and refusing to
      # overwrite their file is not a reason to leave it disabled.
      enable_unit
      return 0
    fi
    if [ "$existing" = "$hash" ]; then
      note "$UNIT_PATH is already current"
      install_compute_dropin
      enable_unit
      return 0
    fi
  fi

  step "Writing $UNIT_PATH"
  tmp="$(workdir)/syndichan-node.service"
  { printf '%s%s\n' "$MARKER_PREFIX" "$hash"; printf '%s\n' "$body"; } >"$tmp"
  run install -m 0644 "$tmp" "$UNIT_PATH"
  run systemctl daemon-reload
  install_compute_dropin
  enable_unit
  return 0
}

install_compute_dropin() {
  [ "$WANT_COMPUTE" = "1" ] || return 0
  [ "$HAVE_SYSTEMD" = "1" ] || return 0
  local tmp; tmp="$(workdir)/10-compute.conf"
  generate_compute_dropin >"$tmp"
  if [ ! -f "$UNIT_DROPIN" ] || ! cmp -s "$tmp" "$UNIT_DROPIN"; then
    step "Writing $UNIT_DROPIN (relaxes hardening for compute -- read the comments in it)"
    run install -d -m 0755 "$(dirname "$UNIT_DROPIN")"
    run install -m 0644 "$tmp" "$UNIT_DROPIN"
  fi
  # Group membership is what actually opens the docker socket; the drop-in only
  # makes systemd apply it.
  if [ "$DO_ADD_DOCKER_GROUP" = "1" ] && getent group docker >/dev/null 2>&1; then
    step "Adding $NODE_USER to the docker group (root-equivalent)"
    run usermod -aG docker "$NODE_USER" || warn "could not add $NODE_USER to the docker group"
  fi
  run systemctl daemon-reload
  return 0
}

enable_unit() {
  step "Enabling syndichan-node on boot"
  run systemctl enable syndichan-node.service
  run systemctl restart syndichan-node.service ||
    warn "the service did not start; see: journalctl -u syndichan-node -n 50"
  return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

printf '%ssyndichan-node installer%s\n' "$C_BOLD" "$C_RESET"
if [ "$DRY_RUN" = "1" ]; then
  printf '%s--check: detecting only. Nothing on this machine will be changed.%s\n' "$C_DIM" "$C_RESET"
fi

# Order matters in exactly one place: detect_service_user renders the unit to
# compare it against the installed one, and the unit names the router that
# detect_i2p found.
detect_platform
detect_ca_certs
detect_i2p
detect_i2p_proxy
detect_binary
detect_service_user
detect_data_dir
detect_state_conflicts
detect_docker
detect_catalogue_images
detect_kvm

print_plan

if [ "$DRY_RUN" = "1" ]; then
  if [ "$BLOCKED" = "1" ]; then
    say "Blocked: see the 'cannot' row(s) above. The install would refuse to run as configured."
    exit 1
  fi
  if [ "$REQUIRED_MISSING" = "1" ]; then
    say "Some REQUIRED dependencies are missing. Re-run without --check to install them."
    exit 1
  fi
  say "Everything required is present. Re-run without --check to install the node and its service."
  exit 0
fi

if [ "$BLOCKED" = "1" ]; then
  die "refusing to install: see the 'cannot' row(s) above. Nothing was changed."
fi

if [ "$IS_ROOT" = "0" ]; then
  die "this installer must run as root. Re-run with sudo, or use --check to see the full plan without any privilege."
fi

# Consent is asked once, for the whole plan, AFTER the plan has been printed and
# BEFORE anything is touched. Installing software on somebody's machine without
# asking is not acceptable merely because the thing doing it is called an
# installer -- and that covers creating a user, editing a router's config and
# writing a systemd unit, not only `apt-get install`.
if ! confirm "Proceed with the plan above?"; then
  say "Nothing was changed."
  exit 0
fi

install_packages
configure_i2pd
start_router      # started early, so the router builds tunnels while Go compiles
start_docker
bootstrap_go
build_binary
create_user_and_dirs
install_binary
create_config
install_wait_helper

step "Waiting for the I2P SAM bridge on 127.0.0.1:7656 (up to ${SAM_WAIT_SECONDS}s)"
sam_rc=0; wait_for_sam "$SAM_WAIT_SECONDS" || sam_rc=$?
case "$sam_rc" in
  0) note "SAM bridge ready" ;;
  3) warn "not starting the node against a port that is not SAM" ;;
  *) warn "the SAM bridge did not answer in ${SAM_WAIT_SECONDS}s."
     note "the service is installed with a readiness wait and will start on its own once the router is ready."
     note "check the router: ${ROUTER_UNIT:-your I2P router}, and http://127.0.0.1:7657 or :7070" ;;
esac

install_unit

printf '\n%sDone.%s\n' "$C_BOLD" "$C_RESET"
if [ "$INSTALL_SERVICE" = "1" ] && [ "$HAVE_SYSTEMD" = "1" ]; then
  say "  systemctl status syndichan-node       # is it up"
  say "  journalctl -u syndichan-node -f       # what is it doing"
fi
case "$UI_LISTEN" in
  off|none|OFF|None) say "  (management page disabled; edit $CONFIG_FILE to configure this node)" ;;
  "")                say "  http://127.0.0.1:9090                 # management page (loopback only)" ;;
  *)                 say "  http://$UI_LISTEN/                    # management page" ;;
esac
say "  $0 --check                            # re-run the detection at any time"
if [ -z "$PAYOUT" ]; then
  say ""
  say "No payout address is set: this node will work and earn nothing. Set one on the"
  say "management page, or re-run with --payout 0x..."
fi
