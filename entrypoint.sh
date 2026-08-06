#!/bin/sh
set -eu

umask 077
cd /app

if [ ! -x ./whois-app ]; then
    echo "fatal: /app/whois-app is not executable" >&2
    exit 1
fi
if [ ! -r ./assets.sha256 ] || ! sha256sum -c ./assets.sha256 >/dev/null; then
    echo "fatal: packaged assets failed integrity verification" >&2
    exit 1
fi
if [ ! -d ./data ] || [ ! -w ./data ]; then
    echo "fatal: /app/data must be a writable volume owned by uid 100 (gid 101)" >&2
    exit 1
fi

exec ./whois-app
