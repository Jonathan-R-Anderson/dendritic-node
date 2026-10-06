#!/bin/sh
set -eu
umask 077
mkdir -p /var/lib/axon-dns/keys
if [ ! -s /var/lib/axon-dns/rndc.key ]; then
    rndc-confgen -a -A hmac-sha256 -c /var/lib/axon-dns/rndc.key
fi
# Provision validated unsigned zones before the server starts. No chain writes occur.
axon-dns publish -config /etc/axon-dns/publisher.json -no-reload
named-checkconf -z /etc/axon-dns/named.conf
named -g -c /etc/axon-dns/named.conf -n 2 &
named_pid=$!
publisher_pid=
cleanup() {
    kill "$named_pid" 2>/dev/null || true
    if [ -n "$publisher_pid" ]; then kill "$publisher_pid" 2>/dev/null || true; fi
    wait 2>/dev/null || true
}
trap 'cleanup; exit 0' INT TERM
trap cleanup EXIT
attempt=0
until rndc -s 127.0.0.1 -p 9953 -k /var/lib/axon-dns/rndc.key status >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ] || ! kill -0 "$named_pid" 2>/dev/null; then exit 1; fi
    sleep 1
done
axon-dns publish -config /etc/axon-dns/publisher.json -watch &
publisher_pid=$!
while kill -0 "$named_pid" 2>/dev/null && kill -0 "$publisher_pid" 2>/dev/null; do sleep 1; done
exit 1
