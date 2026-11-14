#!/bin/sh
# Run only the extracted candidate and disposable acceptance fixture processes.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"
chmod 700 ./caddy ./pool.test ./pool-origin
case "${1:-}" in
  origin)
    test "$#" -eq 3 || { echo 'Usage: run-pool-acceptance.sh origin PRIVATE_IP NODE_ID'; exit 2; }
    test ! -f origin.pid || { echo 'This workspace already has an origin.pid; use a new extraction directory.'; exit 1; }
    nohup ./pool-origin -bind "$2" -node "$3" -duration 30m >origin.log 2>&1 </dev/null &
    pid=$!
    printf '%s\n' "$pid" >origin.pid
    sleep 1
    kill -0 "$pid" 2>/dev/null || { cat origin.log; exit 1; }
    printf 'Disposable origin PID=%s; expires in 30 minutes. Workspace=%s\n' "$pid" "$root"
    cat origin.log
    ;;
  gateway)
    shift
    test "$#" -ge 2 || { echo 'Usage: run-pool-acceptance.sh gateway PRIVATE_IP PRIVATE_IP [...]'; exit 2; }
    v1= v2=
    for host do
      v1="${v1:+$v1,}$host:52991"
      v2="${v2:+$v2,}$host:52992"
    done
    export TRUEOPS_POOL_CADDY="$root/caddy"
    export TRUEOPS_POOL_V1_TARGETS="$v1" TRUEOPS_POOL_V2_TARGETS="$v2"
    export TRUEOPS_APPSEC_TEST_LOCAL=1
    ./pool.test -test.v -test.run '^TestCandidatePool' -test.count=1 >report.log 2>&1 || {
      cat report.log
      exit 1
    }
    grep -E 'external fixtures:|candidate=|pool_changes=|round=|external origin=|^--- |^PASS|^FAIL' report.log
    printf 'Full report: %s/report.log\n' "$root"
    ;;
  local)
    export TRUEOPS_POOL_CADDY="$root/caddy"
    ./pool.test -test.v -test.run '^TestCandidatePool' -test.count=1
    ;;
  *)
    echo 'Usage: run-pool-acceptance.sh origin PRIVATE_IP NODE_ID | gateway PRIVATE_IP PRIVATE_IP [...] | local'
    exit 2
    ;;
esac
