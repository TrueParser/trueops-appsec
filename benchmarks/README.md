# Isolated AppSec comparison

Build/package on Windows with `powershell -File benchmarks/package.ps1`.
The output directory is new and immutable; the command refuses to overwrite it.
The archive contains Windows-built Linux amd64 Caddy candidates, a runner and
microbenchmark executable, pinned official CrowdSec v1.8.2 binaries, verified
Hub/CRS assets, manifests, checksums and dependency licenses. No Go is needed on
the Ubuntu 24.04 amd64 VPS. Do not run engine installers or systemctl commands.

After downloading and verifying the archive's SHA-256, extract into a new private
temporary directory. Run `sh ./run.sh --quick --mode synthetic` for an explicitly
synthetic smoke, then `sh ./run.sh --duration 5s --warmup 1s --repeats 9` for real
engine comparisons. Nine rounds rotate every candidate through every position.
The runner creates another private temporary results directory, prints its path,
and retains logs, isolated configurations, raw JSONL and machine information.

Stock baseline, bundle absent/disabled, WAF-only, Bot-only and combined candidates
use the same content handlers. The external topology is client → bridge → stock
Caddy; the bridge reuses the same AppSec Handler, transport and limits. The
in-process topology is client → bundled Caddy AppSec → original handler. This
controls enforcement implementation while measuring the additional proxy hop.

The real engine uses private SQLite/LAPI credentials and unused loopback ports.
Its WAF profiles combine pinned Hub defaults, CRS, schema and native rate-limit
examples; its Bot and combined profiles share only this test site's private
challenge secret. No existing engine, Caddy service, site, firewall, database or
tunnel is touched. The first private LAPI profile stops firewall decisions.
Setup fails rather than silently dropping an unsupported rule or profile.

Body/method/Host/URI checks and native denial probes precede timing. Challenges
that replace origin responses cause preflight failures, never successful origin
throughput. Browser JavaScript, submission, verified-cookie, cross-site firewall,
HTTP/2/TLS, streaming/upgrades, native arm64 and sustained pressure/recovery
acceptance remain separate pending gates. Synthetic challenges cannot pass them.
All failures remain in JSONL; an incomplete comparison exits nonzero.

The pinned Bot profile challenges each request until the browser supplies a
valid native cookie. Accordingly, real Bot/combined measurements are explicitly
labelled `first-challenge`, not successful application throughput. Native worker
assets and rejection of malformed submissions are checked before measurement;
that HTTP verification does not prove JavaScript execution or cookie issuance.
The balanced profile rejects detected automation, so a headless browser is not
an assumed way to obtain a valid cookie or bypass this remaining acceptance gate.

Throughput and approximate p50/p95/p99 use a bounded histogram with <=1% bucket
resolution. CPU deltas and end-of-window RSS are sampled from each owned Linux
process; RSS is neither peak memory nor retained Go heap. The load generator,
origin and candidates share the VPS, which can limit capacity; results disclose
that placement. An authorized separate generator is preferable for capacity
acceptance. No benchmark listener is exposed publicly by this bundle.

For allocation measurements, run the same verified microbenchmark executable:
`./bin/appsec-microbench -test.v -test.run '^$' -test.bench BenchmarkDisabledPath -test.benchmem`.
These are module microbenchmarks, not real engine capacity measurements.

Keep the complete archive, `manifest.json`, `environment.json`, JSONL and logs.
Publish only the exact accepted `bin/caddy` bytes; do not rebuild after measuring
and assume acceptance transfers. The manifest records a dirty source snapshot
when packaging uncommitted work. This bundle does not tag, commit or release.

WSL may host the verified archives using the Windows-built `artifact-server` and
a separate temporary Cloudflare Quick Tunnel pointing at that listener. Keep the
Controller's existing tunnel and services running. Verify the HTTPS download's
hash before sharing it. WSL is not a benchmark or development environment.
