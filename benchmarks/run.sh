#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
umask 077
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
sha256sum --check --strict SHA256SUMS
chmod u+x bin/caddy bin/stock-caddy bin/appsec-bench bin/appsec-microbench engine/crowdsec engine/cscli
exec ./bin/appsec-bench --bundle "$PWD" "$@"
