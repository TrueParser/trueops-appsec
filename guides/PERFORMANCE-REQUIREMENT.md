# TrueOps AppSec Performance Requirements

**Status:** Normative acceptance requirements.
**Scope:** The in-process Caddy AppSec module and its request, transport and lifecycle overhead.

Apply these requirements alongside the [product invariants](product-invariants.md).
[Engineering invariants](engineering-invariants.md) govern implementation decisions;
[build/release invariants](releasing.md#build-and-release-invariants) govern
dependency pins, repository ownership and release artifacts.

## 1. Performance contract

Performance is a primary acceptance requirement alongside correctness and
security. Minimize module-added allocations, body copies and connection overhead,
and verify the complete request path against matching upstream Caddy.

The performance benefit is direct continuation inside Caddy after explicit native
allow, eliminating the extra application-proxy hop. Caddy and the external
CrowdSec exchange still perform network I/O. No malloc-free or syscall-free
architecture is required.

Caddy owns HTTP serving and content handling; CrowdSec owns detection. The
module's performance work concerns scoped integration, native protocol handling,
body preservation and enforcement. It does not authorize a local detection
engine or additional request-payload analysis.

## 2. Requirements by path

| Path | Requirement |
| --- | --- |
| Protection disabled | No inspection calls, body reads/capture, allow-cache lookup or challenge handling. Target zero module-added heap allocations and allocated bytes per request. |
| Excluded request | Minimal policy matching and no unnecessary body capture; preserve work required by any remaining enabled policy. |
| Protected request | Reuse connections; minimize allocations and body copies without weakening required inspection. |
| Request body | Bound buffering and retention; use buffer reuse only where benchmarks demonstrate benefit. |
| Allowed response | Continue directly to the original Caddy handler; avoid response buffering and unnecessary response-writer wrappers. |
| Configuration | Parse and prepare policies during configuration loading rather than on every request. |

Benchmark both the configured both-policies-off path and the bundle with the
module absent from the handler chain. Absence alone does not verify disabled
middleware behavior. Verify 0 added heap allocations/request and 0 added
allocated bytes/request against the matching stock Caddy handler chain, and
report the absolute baseline and bundle values as well as the delta.

This target concerns module overhead, not allocations performed by Caddy,
downstream handlers or network I/O. Do not claim it is achieved without evidence.
Keep body-free requests body-free and preserve efficient static-file, streaming
and upgrade behavior within the supported product contract.

## 3. Protocol work and data representations

Use the reviewed native AppSec request, decision and challenge protocol. Its wire
encoding/decoding is necessary; additional in-process serialization is not.
Pass typed Go values between module stages and reuse decoded protocol results.

- Avoid repeated byte/string conversion, full-buffer copies, body materialization
  and encoding/decoding of the same native response.
- Do not convert through generic JSON trees or redundant DTO layers merely to
  move data between stages. One conversion for a real ownership or protocol
  boundary is acceptable when needed.
- Preserve required status, body, headers, repeated cookies, CSP and challenge
  exchanges. An optimization must not collapse distinct native outcomes.
- Parse only what the integration protocol requires. Do not add language parsers,
  payload normalization or local detection work to avoid native inspection.

Choose a codec or client for the semantics used by this module, including
malformed-input behavior and repeated fields. Benchmark its actual integration
path rather than relying on an upstream parse-only or throughput claim.

## 4. Request bodies and buffer ownership

Understand each material copy between incoming body, inspection capture/replay,
native AppSec transport and the original Caddy handler. Preserve the complete
method, Host, URI/query, headers and body semantics required by the product.

- Read failures, interrupted input and invalid framing must not become
  successfully inspected or replayed partial bodies. Never silently inspect or
  forward a truncated prefix.
- Define oversize, compressed and streaming behavior from the supported protocol
  and measured resource needs. A prototype fixture size is not a product limit.
- Where protocol-required decoding occurs, bound both source and derived size,
  expansion, depth and work. Source-byte limits alone do not bound amplification.
- Do not preallocate directly from an untrusted claimed size. Avoid repeated
  growth or concatenation where a measured, bounded capacity hint suffices.
- Use readers or slices with clear ownership when they avoid material copies.
  Never mutate, reuse or pool a buffer while a handler, transport or goroutine
  still references it. Avoid retaining a large body through a small slice.

Do not add object or buffer pools by default. Pooling needs measured benefit,
bounded retained capacities and aggregate retention, safe sensitive-data
handling, and proof against cross-request contamination. Measure both allocation
rate and retained memory: fewer allocations must not hide persistent retention
of peak upload-sized buffers.

Zero-copy is not a separate acceptance goal. Do not add unsafe aliases, custom
arenas or complex lifetime machinery merely to avoid an insignificant copy.

## 5. Connections, concurrency and lifecycle

Reuse appropriately bounded Go/Caddy transports and connections through the
module lifecycle. Do not create a new client, connection, timer or worker per
request when existing facilities suffice. Propagate deadlines and cancellation.

Prefer Caddy's request concurrency over extra parallel stages. Additional
goroutines or queues require demonstrated need, bounded work/memory and clear
ownership. Do not introduce a generic worker framework for anticipated load.

- Keep request-local state local and prepared configuration immutable where
  practical. Measure contention before adding shared locks to the hot path.
- Bound any attacker-triggered backlog. Measure queue wait, active work,
  rejections and work retained after caller timeout where those mechanisms exist.
- Do not release a permit, buffer or memory reservation while ongoing work still
  uses it, even if the caller has timed out.
- Reload/shutdown must not leak goroutines or prematurely release resources used
  by active requests. Preserve Caddy's native graceful reload/shutdown behavior
  and configured shutdown limits.

Use syscall profiling when investigating connection or I/O overhead. Attribute
costs to the module, Caddy, AppSec transport and workload before changing the
architecture; necessary I/O is not a defect.

## 6. Policy isolation and security

Performance changes must preserve the [product contract](product-invariants.md),
including reviewed, pinned native AppSec profiles and bounded V1 policy scope.

Verify off, WAF-only, Bot-only and combined modes. A valid bot cookie must not
bypass WAF, and a bot exclusion must not disable a matching WAF policy.
Site-scoped outcomes must not automatically become gateway-wide firewall
decisions; Site A must not affect Site B through shared profiles, caches or
firewall enforcement.

Do not introduce an allow cache without measured need and defined authorization,
scope, identity, profile and lifetime semantics. Configuration preparation must
not cache a request's allow decision or permit public headers to weaken policy.

Never improve benchmark results by skipping inspection, truncating required
input, reusing an unauthorized allow, discarding a denial or treating a challenge,
read error, malformed response or infrastructure failure as native allow.
Preserve the explicitly defined timeout/failure behavior.

## 7. Diagnostics and error paths

Keep routine metrics lightweight, structured and bounded. Avoid expensive
formatting when a log level is disabled, high-cardinality attacker-controlled
labels and serialization of full protocol objects for routine logging.
Diagnostics remain opt-in and bounded; exclude bodies, credentials and challenge
secrets. Use compact reasons and metadata for attacker-triggered errors.

Exercise malformed native responses, repeated/oversized metadata, incomplete
bodies, engine timeouts/disconnects and supported encoding failures. Error
handling must not amplify attacker-controlled work through repeated scans,
growing string construction or unbounded retries. Any unavoidable superlinear
work must have a justified bound on its controlling input.

## 8. Dependencies and optimization

Assess existing Go client facilities and the
[implementation references](implementation-references.md) before adding another
implementation. Evaluate required protocol semantics, copies, allocations,
cancellation, concurrency safety, malformed-input behavior, dependency weight,
licensing and supported-target behavior.

A material dependency or performance refactor needs a measured bottleneck,
baseline, integration cost, result and correctness/security verification.
Keep the evidence proportional; trivial non-hot-path changes do not need a
separate benchmark exercise.

Do not introduce custom allocation machinery, unsafe memory tricks,
architecture-specific assembly or a replacement networking stack upfront.
Such changes require demonstrated necessity, evidence that a simpler change
cannot resolve the cost, explicit maintainer approval, security/lifecycle review
and supported-target validation. Unsafe hot-path changes also require focused
fuzzing. SIMD or zero-copy claims require evidence that the actual target build
exercises the claimed path; dependency capability alone is insufficient.

## 9. Benchmark controls and workloads

Use microbenchmarks to locate body capture/replay, protocol encoding/decoding or
header/cookie costs. Use the complete in-process handler path and real
client-to-Caddy-to-AppSec-to-original-handler traffic for acceptance.
Microbenchmarks do not establish end-to-end capacity.

Compare these controls with matching Caddy versions, toolchains, build flags,
hardware, content, inspection configuration and connection behavior:

1. Upstream Caddy without custom modules.
2. The bundle with the module absent from the request chain.
3. Configured both-policies-off middleware.
4. Body/protocol overhead control, clearly labelled synthetic and unprotected.
5. Real WAF-only, Bot-only and combined inspection.
6. First challenge, valid-cookie traffic and excluded paths.

An external-proxy comparison may illustrate a removed hop but cannot be the only
reference. Compare equivalent protection work. Synthetic inspection must not be
advertised as real WAF/Bot Detection capacity.

The [VPS benchmark bundle](../benchmarks/README.md) includes the required external
bridge comparison against the same in-process enforcement and native profiles.
Build on Windows, use WSL only to host immutable downloads, and measure on the
isolated VPS. Preserve existing services/sites/firewall/tunnels and release the
same accepted binary bytes; a rebuild does not inherit the measurements.

Cover application GETs, small/large POSTs, representative uploads and static
files; concurrency 1 and representative concurrent load; HTTP/1.1, HTTP/2,
relevant TLS and supported streaming/upgrades. Claim handler support only after
the corresponding integration path passes. Do not claim WebSocket-frame or
unbounded-stream inspection without proof.

Include representative benign, malicious, malformed and mixed traffic,
sustained resource pressure and recovery afterwards. Measure legitimate traffic
during pressure. Continue observing until latency, outstanding work and retained
memory recover; do not stop measurement when attack/upload traffic ends.

## 10. Metrics, baselines and regression acceptance

Record throughput, errors, CPU, p50/p95/p99 latency, added heap allocations/request,
allocated bytes/request and memory. Include active-request peaks, retained idle
memory after upload bursts, and outstanding work after timeouts. Distinguish
sampled RSS, allocation peaks and Go heap retention.

Use repeated runs, balanced ordering and adequate warmup. Report baseline
variation, load-generator placement and shared-host effects. Separate module
overhead from external-engine cost; neither silently absorbs the other.

The disabled path must meet the zero-added-allocation target and remain
materially equivalent to upstream within measured baseline variation.
Establish numeric regression budgets from stable controlled measurements before
enforcing percentage thresholds. Noise alone is not a regression; unexplained
material regression is not acceptable.

Profile the measured workload when a material cost remains. Use Go CPU/heap/
allocation profiles and native platform tools; isolate serialization or syscall
costs when evidence points there. Optimization must improve the relevant whole
path while preserving correctness and security.

## 11. Reproducibility and native target evidence

Record source commit, distribution/upstream/module versions, exact binary
checksum, Go toolchain, build flags, CGO/CPU target settings, OS/hardware,
engine/profile configuration, workload revision, commands, duration, concurrency,
input sizes, protocol/TLS and connection-reuse settings.

Benchmark optimized release-equivalent, portable builds. Label local CPU-specific
results; do not treat them as evidence for incompatible deployment hardware.
Normal development/builds run on Windows. Exercise Windows-built artifacts on
native Linux amd64 and arm64 targets for their acceptance. Cross-builds and short
CI smoke runs do not establish native runtime or performance acceptance.

Retain raw measurements as CI/test artifacts outside the task ledger. Preserve
baseline definitions needed for future comparison. Artifact publication and
exact-binary identity follow [build/release invariants](releasing.md#build-and-release-invariants).

## 12. Acceptance checklist

For a material request-path or performance change:

- [ ] Verify required native protocol behavior and relevant correctness tests.
- [ ] Account for material copies, allocations, retained buffers and ownership.
- [ ] Verify configured disabled middleware has zero added heap allocations/bytes.
- [ ] Compare upstream, inactive bundle, synthetic controls and real protection.
- [ ] Verify all four policy modes and cross-site/firewall isolation.
- [ ] Measure benign/hostile/error paths, concurrency and post-pressure recovery.
- [ ] Preserve graceful lifecycle behavior and resource ownership after timeout.
- [ ] Record required metrics, reproducible inputs and stable regression budgets.
- [ ] Verify claimed improvements on the actual integration and supported targets.
- [ ] Report unexercised engine/browser/native paths as pending; skipped or
      synthetic tests do not prove their acceptance.
