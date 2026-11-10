# TrueOps AppSec Product Invariants

**Status:** Locked product contract.

These invariants define functional and performance acceptance. Detailed
measurement requirements are in [performance-requirement.md](performance-requirement.md);
repository ownership, upstream dependency pins and release artifact integrity
belong to the separate [build/release invariants](releasing.md#build-and-release-invariants).

## Performance acceptance

- Performance is a primary acceptance requirement. Target zero module-added
  heap allocations on the disabled path. Minimize protected-path allocations,
  body copies and connection overhead.
- Verify against matching upstream Caddy using throughput, tail latency, CPU,
  allocations and retained memory. Optimizations must preserve correctness and
  security; custom allocators or networking machinery require demonstrated
  necessity. No malloc-free or syscall-free architecture is required.

## Native Caddy behavior and request continuation

- Preserve native CLI, configuration validation, admin API, TLS and content
  handling. Do not introduce SSH management, another proxy hop, internal HTTP
  re-entry, a configuration database or another management application dependency.
- Protection is opt-in per virtual host/path. With both policies off, perform
  no inspection calls, body capture, allow-cache lookup or challenge handling.
- For protected requests, continue directly to the original Caddy handler only
  after explicit native allow. Preserve method, Host, URI/query, headers and
  complete-body semantics. Unprotected scopes retain the ordinary Caddy path.
- Preserve streaming and upgrades outside inspected scopes. Claim support for
  file serving, reverse proxy, FastCGI, uploads or upgrades only after the
  corresponding integration path has actually passed.
- Shared transports, buffers and background work follow Caddy's lifecycle.
  Reload and shutdown must release owned resources without leaking goroutines
  or prematurely releasing resources used by active requests; preserve Caddy's
  native graceful reload/shutdown behavior and configured shutdown limits.

## AppSec policy, identity and secrets

- Keep WAF-only, Bot-only and combined policies independent. A valid bot cookie
  must not bypass WAF; a bot exclusion must not disable a matching WAF policy.
- Site-scoped WAF or Bot Detection outcomes must not automatically create
  gateway-wide firewall decisions. A detection on Site A must not affect Site B
  through shared profiles, caches or firewall enforcement. Verify all four
  combinations: off, WAF-only, Bot-only and combined.
- Bind each scope to its reviewed native AppSec profile. Use Caddy's trusted
  client identity. Public request headers must not select a weaker profile or
  forge client identity. Preserve host/path and concurrent-request isolation.
- Implement the complete native CrowdSec challenge protocol, including envelope
  decoding, browser status/body/headers/CSP, repeated cookies, assets and
  submission exchanges. Challenge HTTP 200 or 307 is not permission to invoke
  the application handler. Errors and malformed responses are not native allow.
- Specify and test timeout/failure behavior before stable release. Never add an
  implicit allow fallback, unauthorized cached allow or retry of uncertain
  side effects to improve availability or benchmark results.
- Treat request/configuration/environment inputs as untrusted at their actual
  boundaries. Keep engine/admin/provider credentials and challenge secrets out
  of logs, errors, fixtures, screenshots, source control and release assets.
  Do not weaken TLS verification or native trust and authorization checks.

## V1 policy scope

- Use reviewed, pinned native AppSec profiles, including native CRS, API schema
  validation, Bot Detection and engine-side rate limiting where configured.
  Detection, policy hooks and counters remain in CrowdSec; the Caddy module
  integrates and enforces native outcomes. Do not introduce an arbitrary rule
  editor, new rule language, local detector or competing policy/rate-limit engine.
- Pin profile rules and supporting assets, preserve site isolation and verify
  each enabled feature against the selected engine. Request inspection does not
  imply response-body inspection or application credential verification.

## Bodies, resources and dependencies

- Read failures, interrupted bodies and invalid framing must not become
  successfully inspected or replayed partial bodies. Never silently inspect or
  forward a truncated prefix.
- Derive limits from protocol requirements and measured resource needs. Define
  and test oversize, compressed and streaming behavior. Prototype fixture sizes
  are not product defaults. Do not claim WebSocket-frame or unbounded-stream
  inspection without evidence.
- Reuse bounded transports/connections; propagate deadlines and cancellation.
  Bound attacker-triggered work and retained memory with documented rationale.
  Caller timeout does not release resources still used by ongoing work.
- The external AppSec engine is a dependency only when protection is enabled.
  Do not bundle/manage that engine, firewall services or host packages. Do not
  add unrelated listeners, databases, analytics pipelines or detection engines.
