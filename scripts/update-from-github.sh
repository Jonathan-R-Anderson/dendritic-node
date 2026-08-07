#!/usr/bin/env bash
set -euo pipefail

# Build and activate the latest trusted GitHub branch, rolling back the binary
# automatically unless the public gateway becomes ready after restart.
#
# This script is deliberately usable outside a checkout. The installation owns
# a bare mirror under $SYNDICHAN_INSTALL_DIR, exports the selected commit into a
# fresh temporary directory, and never executes a mutable working tree.

INSTALL_DIR="${SYNDICHAN_INSTALL_DIR:-}"
GIT_URL="${SYNDICHAN_GIT_URL:-https://github.com/Jonathan-R-Anderson/syndichan-node.git}"
GIT_BRANCH="${SYNDICHAN_GIT_BRANCH:-main}"
SERVICE="${SYNDICHAN_SERVICE:-syndichan-node.service}"
HEALTH_URL="${SYNDICHAN_UPDATE_HEALTH_URL:-}"
HEALTH_ATTEMPTS="${SYNDICHAN_UPDATE_HEALTH_ATTEMPTS:-36}"
HEALTH_INTERVAL="${SYNDICHAN_UPDATE_HEALTH_INTERVAL:-5}"

case "$INSTALL_DIR" in
  /*) ;;
  *) echo "SYNDICHAN_INSTALL_DIR must be an absolute path" >&2; exit 2 ;;
esac
case "$INSTALL_DIR" in
  /|/home|/root|/usr|/var) echo "refusing unsafe installation directory: $INSTALL_DIR" >&2; exit 2 ;;
esac
case "$HEALTH_URL" in
  https://*/readyz) ;;
  *) echo "SYNDICHAN_UPDATE_HEALTH_URL must be an https://.../readyz URL" >&2; exit 2 ;;
esac
case "$HEALTH_ATTEMPTS:$HEALTH_INTERVAL" in
  *[!0-9:]*|:*|*:) echo "health attempts and interval must be positive integers" >&2; exit 2 ;;
esac
if [ "$HEALTH_ATTEMPTS" -lt 1 ] || [ "$HEALTH_INTERVAL" -lt 1 ]; then
  echo "health attempts and interval must be positive integers" >&2
  exit 2
fi

BIN_DIR="$INSTALL_DIR/bin"
DATA_DIR="$INSTALL_DIR/data"
CONFIG_FILE="$INSTALL_DIR/config/config.json"
MIRROR="$INSTALL_DIR/source.git"
PROGRAM="$BIN_DIR/syndichan-node"
PREVIOUS="$BIN_DIR/syndichan-node.previous"
DEPLOYED_SHA="$INSTALL_DIR/deployed.sha"
STATUS_FILE="$INSTALL_DIR/update-status"
LOCK_FILE="$INSTALL_DIR/update.lock"

mkdir -p "$BIN_DIR" "$DATA_DIR" "$INSTALL_DIR/config"
chmod 0700 "$INSTALL_DIR" "$DATA_DIR" "$INSTALL_DIR/config"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "another Syndichan update is already running"
  exit 0
fi

tmp="$(mktemp -d "$INSTALL_DIR/.update.XXXXXXXX")"
cleanup() {
  rm -rf -- "$tmp"
}
trap cleanup EXIT INT TERM

status() {
  local state="$1"
  local detail="$2"
  umask 077
  {
    printf 'state=%s\n' "$state"
    printf 'time=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'detail=%s\n' "$detail"
  } >"$STATUS_FILE.tmp"
  mv -f "$STATUS_FILE.tmp" "$STATUS_FILE"
}

rollback() {
  local reason="$1"
  status rollback "$reason"
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  if [ -f "$PREVIOUS" ]; then
    install -m 0755 "$PREVIOUS" "$PROGRAM.rollback"
    mv -f "$PROGRAM.rollback" "$PROGRAM"
  fi
  systemctl start "$SERVICE" >/dev/null 2>&1 || true
  for _attempt in $(seq 1 "$HEALTH_ATTEMPTS"); do
    if curl --fail --silent --show-error --max-time 10 "$HEALTH_URL" >/dev/null; then
      status rolled_back "$reason; previous binary restored and healthy"
      return 0
    fi
    sleep "$HEALTH_INTERVAL"
  done
  status rollback_failed "$reason; previous binary did not become healthy"
  return 1
}

status checking "fetching $GIT_BRANCH from GitHub"
if [ ! -d "$MIRROR" ]; then
  git init --bare "$MIRROR" >/dev/null
  git -C "$MIRROR" remote add origin "$GIT_URL"
else
  git -C "$MIRROR" remote set-url origin "$GIT_URL"
fi
git -C "$MIRROR" fetch --quiet --prune origin \
  "+refs/heads/$GIT_BRANCH:refs/remotes/origin/$GIT_BRANCH"
candidate_sha="$(git -C "$MIRROR" rev-parse "refs/remotes/origin/$GIT_BRANCH")"
deployed_sha=""
if [ -f "$DEPLOYED_SHA" ]; then
  deployed_sha="$(tr -d '[:space:]' <"$DEPLOYED_SHA")"
fi
if [ "$candidate_sha" = "$deployed_sha" ] && [ -x "$PROGRAM" ]; then
  status current "$candidate_sha"
  echo "Syndichan is already current at ${candidate_sha:0:12}"
  exit 0
fi

mkdir -p "$tmp/source"
git -C "$MIRROR" archive "$candidate_sha" | tar -x -C "$tmp/source"
if [ ! -f "$tmp/source/go.mod" ] || [ ! -d "$tmp/source/cmd/syndichan-node" ]; then
  status rejected "$candidate_sha does not contain the storage-client source tree"
  exit 1
fi

status testing "running tests for ${candidate_sha:0:12}"
(
  cd "$tmp/source"
  timeout 15m go test ./...
  CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w" \
    -o "$tmp/syndichan-node" ./cmd/syndichan-node
)
chmod 0755 "$tmp/syndichan-node"

# Loading the real configuration catches schema or validation incompatibility
# without binding a listener or touching the durable identity/store.
#
# -show-config, not -gateway-status: that flag has never existed on this binary.
# It exited 2 with "flag provided but not defined", and under `set -euo pipefail`
# that aborted EVERY update run at this line -- so no update ever reached the
# install step. -show-config is the flag that does what the comment above
# describes: ConfigPath -> LoadOrCreate -> ValidateForRole, print, exit. There is
# no -data-dir either; the data directory comes from the config file.
"$tmp/syndichan-node" -show-config -config "$CONFIG_FILE" >/dev/null
if [ -f "$tmp/source/scripts/update-from-github.sh" ]; then
  bash -n "$tmp/source/scripts/update-from-github.sh"
fi

status activating "installing ${candidate_sha:0:12}"
if [ -x "$PROGRAM" ]; then
  install -m 0755 "$PROGRAM" "$PREVIOUS"
fi
install -m 0755 "$tmp/syndichan-node" "$PROGRAM.next"
mv -f "$PROGRAM.next" "$PROGRAM"

if ! systemctl restart "$SERVICE"; then
  rollback "systemd could not restart candidate ${candidate_sha:0:12}"
  exit 1
fi

healthy=0
for _attempt in $(seq 1 "$HEALTH_ATTEMPTS"); do
  if curl --fail --silent --show-error --max-time 10 "$HEALTH_URL" >/dev/null; then
    healthy=1
    break
  fi
  sleep "$HEALTH_INTERVAL"
done
if [ "$healthy" != "1" ]; then
  rollback "candidate ${candidate_sha:0:12} failed public readiness"
  exit 1
fi

printf '%s\n' "$candidate_sha" >"$DEPLOYED_SHA.tmp"
mv -f "$DEPLOYED_SHA.tmp" "$DEPLOYED_SHA"

# Let a successful release update the updater for the next timer run. Replacing
# the pathname is safe while this process continues from its already-open inode.
if [ -f "$tmp/source/scripts/update-from-github.sh" ]; then
  install -m 0755 "$tmp/source/scripts/update-from-github.sh" "$BIN_DIR/update-from-github.next"
  mv -f "$BIN_DIR/update-from-github.next" "$BIN_DIR/update-from-github"
fi
status healthy "$candidate_sha"
echo "Updated Syndichan to ${candidate_sha:0:12}; public readiness passed"
