# TrueOps AppSec Implementation

## Objective and scope

- [ ] Implement a small native Caddy AppSec module with independent WAF and Bot
  Detection, complete-body handling and direct original-handler continuation.
- [ ] Use the existing layout: `cmd/caddy/`, `modules/appsec/`,
  `tests/integration/` and `benchmarks/`; keep responsibilities cohesive.
- [ ] Preserve the [product invariants](guides/product-invariants.md),
  [engineering invariants](guides/engineering-invariants.md) and
  [performance requirements](guides/performance-requirement.md).
- [ ] Integrate reviewed, pinned native WAF/Bot capabilities, including CRS,
  API schema validation and engine-side rate limiting. Keep detection and policy
  execution in CrowdSec; add no rule editor, local policy engine, gateway-wide
  firewall decisions, management service, extra content proxy or Caddy fork.
- [ ] Hand over tested code; commits, pushes, tags and releases remain with the
  maintainer. Preserve existing work and do not modify live infrastructure.

## 1. Read-only audit

- [x] Boundary: Existing repository/contracts and the exact upstream revisions
  needed for the module; no implementation changes during this audit.
- [x] Review the [implementation references](guides/implementation-references.md)
  and official challenge specification for native API methods, remediation,
  challenge exchanges and request-body behavior; assess existing Go client reuse.
- [x] Settle reviewed Go/Caddy/client/profile pins, module identifier,
  configuration syntax, scope/client identity, supported body/streaming behavior,
  justified resource limits and timeout/failure semantics before implementation.
- [x] Evidence: Identify revision-specific source/tests supporting the chosen
  contracts and any verified gaps; resolve behavior/security uncertainties.
- [x] Completion: Required public contracts and integration choices are settled
  without importing another proxy's architecture.
- [x] Slice complete.

### Audit notes — 2026-11-10

This is a source/protocol audit, not runtime acceptance. The maintainer expanded
the audit to native WAF capabilities; reference projects supply evidence, not
our architecture. Implementation, real-engine/browser tests and performance
acceptance remain in the existing pending slices below.

**Reviewed pins and reuse**

| Component | Exact revision and decision |
| --- | --- |
| Go | [go1.27.3](https://go.dev/dl/?mode=json), selected toolchain; the installed Windows toolchain is currently go1.27.0 and was not changed. |
| Caddy | [v2.11.9 / `0d98caea58f794f88e709b1bef2880996a471bca`](https://github.com/caddyserver/caddy/tree/0d98caea58f794f88e709b1bef2880996a471bca). Its `go.mod` requires Go 1.26.0. Consume the upstream module and standard imports, without copying its source into this repository. |
| CrowdSec | [v1.8.2 / `3d369d64eb3e9ba770ed39aedc83ffd3170aef4c`](https://github.com/crowdsecurity/crowdsec/tree/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c), external acceptance-engine baseline. It requires Go 1.27.1 and pins CrowdSec's Coraza fork `v3.8.0-crowdsec.20261001`; neither engine nor Coraza becomes a module dependency here. |
| Hub | [`04bf592e846e05bda8851d7665141fb69e6e08d3`](https://github.com/crowdsecurity/hub/tree/04bf592e846e05bda8851d7665141fb69e6e08d3). Pin configuration, resolved rule lists and supporting data; a collection name or wildcard alone is insufficient. |
| OWASP CRS | [v4.30.0 / `e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`](https://github.com/coreruleset/coreruleset/tree/e03a4f6dabc7a30ebd8c52c97d28a154f590a48f). Selected external rules archive: `coreruleset-4.30.0-minimal.zip`, SHA-256 `27ae3ce7a785472c42426270798ff1415cfd5dd5b8d4cea7fc2bebeed9334418`; downloaded checksum matches the GitHub release asset digest. Native engine loading/attack acceptance is still required. |
| Nginx / Lua | Nginx [v1.2.3 / `067541cdfff4b650182d819e92c04a207aa2fbb5`](https://github.com/crowdsecurity/cs-nginx-bouncer/blob/067541cdfff4b650182d819e92c04a207aa2fbb5/Makefile#L6) delegates protocol implementation to Lua [v1.0.19 / `ec94d512927cf70be865686e4eb928d128189633`](https://github.com/crowdsecurity/lua-cs-bouncer/tree/ec94d512927cf70be865686e4eb928d128189633). Reference only. |
| Traefik | [v1.8.1 / `f9c85b1472d618e9188a025c9b2308d0b27e5321`](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/tree/f9c85b1472d618e9188a025c9b2308d0b27e5321). Reference only. |
| Caddy reference | [v0.15.0 / `4a6ce1d3094dbfd270fecf2a91aaab81663d0cb4`](https://github.com/hslatman/caddy-crowdsec-bouncer/tree/4a6ce1d3094dbfd270fecf2a91aaab81663d0cb4). Lifecycle/handler reference only. |
| Envoy | [v0.8.4 / `f21c149179e2d00fde3b111a4f3de52d618a4106`](https://github.com/kdwils/envoy-proxy-crowdsec-bouncer/tree/f21c149179e2d00fde3b111a4f3de52d618a4106). Protocol reference only; no external authorization service. |
| Go bouncer client | [`fa0aa7f8456e8fe74bf2787be8496f968c4d3f50`](https://github.com/crowdsecurity/go-cs-bouncer/blob/fa0aa7f8456e8fe74bf2787be8496f968c4d3f50/doc.go). Its live/stream clients retrieve LAPI decisions, not AppSec challenge exchanges. Do not import it for this integration; reuse Go `net/http`, Caddy lifecycle/configuration and trusted-client facilities. |

Windows `go mod download -json github.com/caddyserver/caddy/v2@v2.11.9`
verified the selected origin commit and returned module sum
`h1:bhZtcRKQOq0fuLvEgCdPYvUxXyGn9kzjG4lh2332DTE=` and go.mod sum
`h1:jctG0eTy0tC4ST/Q7GIPKIfxox7mhSCtcwlwF82HLVM=`. No project
`go.mod`/`go.sum` was created during this audit.

**Caddy integration and public configuration**

- Go module: `github.com/TrueParser/trueops-appsec`; Caddy module:
  `http.handlers.trueops_appsec`; JSON handler/Caddyfile directive:
  `trueops_appsec`. This avoids the reference module's `http.handlers.appsec` ID.
- Use `caddyhttp.MiddlewareHandler`, `Provision`, `Validate` and `Cleanup`;
  the thin launcher calls `caddycmd.Main()` and imports standard Caddy modules.
  Protection precedes rewrites/content handlers inside an explicitly ordered
  native `route`. Native host/path matchers own scope and exclusions.
- Handler fields, with identical Caddyfile subdirective names: `waf` and `bot`
  (booleans; Caddyfile `on`/`off`, both default off), `endpoint` (HTTP(S) URL),
  `api_key`, `timeout` (positive duration), `max_body_bytes`,
  `max_response_bytes` and `max_in_flight` (positive integers), plus optional
  `ca_file` for a private CA. JSON durations follow Caddy's duration encoding.
  Enabled protection requires the endpoint, credential and explicit budgets;
  no guessed capacity/timeout defaults. Native Caddyfile environment expansion
  can supply the credential, for example `api_key {$APPSEC_API_KEY}`.
- Each handler's endpoint is bound in trusted deployment configuration to the
  matching WAF-only, Bot-only or combined native profile. Both off immediately
  calls `next.ServeHTTP(w, r)` without security work. Combined protection uses
  one native inspection exchange, not two independent engines or another proxy.
  There is no request-controlled profile selector or runtime version/health gate.
- Resolve identity from Caddy's `ClientIPVarKey`, which Caddy derives through
  its trusted-proxy configuration. Clone only the inspection request; overwrite
  integration metadata and remove hop-by-hop/Connection-nominated headers there.
  Preserve the original method, Host, escaped URI/query, headers and replayed
  complete body for direct continuation. Do not buffer allowed responses.
- On Bot-enabled hosts, configure a companion native host route for
  `/crowdsec-internal/challenge/*` before application/path exclusions, targeting
  the same host's challenge runtime. These requests terminate in the module;
  even an upstream allow for an unknown internal path must not reach the origin.
  Both-off handlers themselves retain their ordinary no-work behavior.

Evidence: Caddy's [middleware interface](https://github.com/caddyserver/caddy/blob/0d98caea58f794f88e709b1bef2880996a471bca/modules/caddyhttp/caddyhttp.go#L59),
[trusted-client preparation](https://github.com/caddyserver/caddy/blob/0d98caea58f794f88e709b1bef2880996a471bca/modules/caddyhttp/server.go#L1397)
and the reference's [registration/lifecycle](https://github.com/hslatman/caddy-crowdsec-bouncer/blob/4a6ce1d3094dbfd270fecf2a91aaab81663d0cb4/appsec/appsec.go#L35).

**Native protocol and failure contract**

- Follow the [base protocol](https://docs.crowdsec.net/docs/appsec/protocol/):
  inspection GET without a body, POST with a body, actual captured Content-Length,
  and owned `X-Crowdsec-Appsec-{Ip,Uri,Host,Verb,Api-Key,User-Agent,Http-Version}`
  metadata. Preserve browser cookies. Do not forward our engine credential to
  the application or log credentials, bodies or challenge secrets.
- Continue only on transport HTTP 200 with a valid explicit `action: allow`.
  HTTP 403 is remediation, even when its browser status is 200 or 307.
  Decode the bounded envelope once; do not follow engine redirects. Ban returns
  a terminal denial, preserving a valid native denial status such as rate-limit
  429. Unknown/captcha remediations without a configured supported renderer
  fail closed to 403; never invent a successful CAPTCHA or bot-cookie bypass.
- Relay native challenge body, replacement headers/CSP and separate Set-Cookie
  fields. Honour browser status, including 307; the specified absent/zero
  challenge-status default is 200. Handle assets, POST submissions and opaque
  success cookies; only the engine validates/mints them. Missing or invalid
  challenge payload fails closed to plain 403 without exposing its envelope.
- Timeout, connection/authentication/TLS errors, unexpected status and malformed
  allow responses terminate with 503; malformed/empty 403 responses terminate
  with 403. Neither invokes `next`. No fail-open switch, allow cache or
  application-level retry; submissions must not be replayed after uncertain I/O.
  Propagate cancellation and return before continuation if the caller is canceled.

Evidence: engine [request decoding](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/request.go#L398),
[challenge dispatch/cookies](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec.go#L1296),
[response encoding](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec.go#L2057),
the [official challenge contract](https://docs.crowdsec.net/docs/appsec/bot_detection/challenge_protocol/),
Lua [challenge relay](https://github.com/crowdsecurity/lua-cs-bouncer/blob/ec94d512927cf70be865686e4eb928d128189633/lib/plugins/crowdsec/challenge.lua#L13)
and Traefik's [header/cookie relay tests](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/f9c85b1472d618e9188a025c9b2308d0b27e5321/bouncer_test.go#L642).

**Expanded native features and profile selection**

| Feature | Integration decision and limits |
| --- | --- |
| Virtual patches and generic WAF rules | WAF profile derives from pinned Hub `appsec-default` (0.4), with resolved `base-config`, `vpatch-*`, `generic-*` and explicitly recorded out-of-band rules. Out-of-band matches cannot retrospectively block an allowed request. |
| OWASP CRS | Include request-phase SQLi, XSS, injection, traversal and other native CRS detections through an engine-side reviewed file-rule wrapper for the pinned official v4.30.0 archive. Load setup before ordered rules and retain associated data files. Do not silently use Hub's unversioned CRS data URLs: the downloaded initialization rules identify themselves as 4.0.0-rc1. No response-body/data-leakage inspection claim: the native AppSec exchange supplies requests only. |
| Bot Detection | Initial Bot profile uses pinned Hub `appsec-bot-challenge-scoring` (0.2) plus `appsec-bot-challenge-scoring-balanced` (0.2), threshold 75. Initial path exclusions use Caddy routes selecting WAF-only; do not implicitly install the full bot collection, its behavioral ban scenarios or mutable external good-bot data. Additional native detection/exemption components require their own reviewed asset manifest. Combined adds the same Bot components to the WAF profile. Cookie/exclusion handling must only exempt challenges, never WAF. |
| OpenAPI schema validation | Use native `on_load` schema loading and `pre_eval` validation/drop hooks. Application-specific schemas and their options are reviewed and checksummed deployment inputs, not a Caddy-side validator or authentication service. Credential presence checks do not verify credentials; unsupported OAuth/OIDC validation cannot be advertised as authentication. Custom body decoders are engine-process global, so their use requires compatible isolated engine configuration. |
| Rate limiting | Allow reviewed native in-band `RateLimit` hooks and preserve their ban/429 response. Counters belong to the external datasource, reset on engine restart/reload and are not a distributed quota. Use trusted IP identity initially (native IPv6 /64 behavior); do not use freely chosen request headers as trusted quota identities. Separate datasources isolate sites' budgets. No Caddy-side limiter or worker framework. |
| Native policy hooks | Reviewed engine-side exclusions, scoring and remediation hooks are permitted; no arbitrary rule editor, local detector or new rule language. A policy that calls `SkipProcessing`, disables body inspection or overrides a denial must not weaken the declared WAF contract. Traditional provider CAPTCHA requires its own renderer/provider integration; it is not supplied by the native PoW challenge protocol and is not claimed by this module. |

Hub profile SHA-256 values from its pinned index: `appsec-default`
`68e34ef8b7c8aaadca4233a7213f2fce706daf1b670fc1f544c03b0c8b2e7b87`;
scoring `e5445319b2f281ea5cd9f5420fb6f953fadbebf2a190bd1510d6bf827df16bc8`;
balanced `fa54cfda9b864b02fe148760b30d25167ed7771859d55d4169eb67201ac8ada4`.
Profile assembly/examples and resolved asset manifests are implementation work;
these choices do not claim that the assembled profiles have run successfully.

Evidence: pinned [WAF profile](https://github.com/crowdsecurity/hub/blob/04bf592e846e05bda8851d7665141fb69e6e08d3/appsec-configs/crowdsecurity/appsec-default.yaml),
[bot scoring](https://github.com/crowdsecurity/hub/blob/04bf592e846e05bda8851d7665141fb69e6e08d3/appsec-configs/crowdsecurity/appsec-bot-challenge-scoring.yaml),
[challenge-only exemption](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec.go#L1848),
[native file-rule loading](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec_rules_collection.go#L95),
[schema source/tests](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/api_validation/api_validation_test.go),
[rate-limit source](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/ratelimit.go#L232)
and [ban/429 tests](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/acquisition/modules/appsec/appsec_ratelimit_test.go#L115).

**Bodies, resource ownership and isolation**

- Capture finite bodies completely once, including chunked/unknown-length bodies,
  under the explicit byte budget; detect overflow with a bounded extra byte.
  Oversize is 413, broken framing/read errors 400, upload timeout 408. Never
  inspect/replay a prefix. Preserve JSON, form, multipart and raw bytes for the
  engine's native processors. Initially require identity Content-Encoding on
  protected bodies (415 otherwise); no unverified decompression path.
- Protected servers must configure a positive native Caddy `read_timeout` for
  the total upload, with suitable idle limits; a trickling client must not retain
  a capture slot indefinitely. Finite bodies must reach EOF within those bounds.
  Unbounded streaming/duplex uploads are outside full-body inspection; place those paths
  outside protection explicitly. Inspect upgrade handshakes only where acceptance
  proves them; do not inspect WebSocket frames or buffer allowed SSE/downloads.
  Unprotected streaming/upgrades keep Caddy's ordinary behavior.
- Bound request capture, native response envelopes and concurrent protected work
  with the explicit configuration budgets. Saturation returns 503 without an
  unbounded wait queue. Size the body budget no higher than the reviewed engine
  and Coraza body limits; require native oversize action `drop`, never `partial`
  or `allow`. Native Caddy timeouts own upload reads; the module timeout bounds
  the complete engine exchange. Actual capacity values and performance budgets
  must come from the acceptance workloads, not prototype constants.
- The engine currently accepts partial bodies after its own read timeout or
  unexpected EOF. The reviewed deployment must disable its separate
  `body_read_timeout` (`0`) and send a completely captured body with exact length;
  any failed/incomplete outbound transfer invalidates allow. Include a deliberately
  truncated/slow engine transfer in integration acceptance rather than trusting
  HTTP 200. Engine authentication/body defaults are not our product budgets.
- Reuse lifecycle-owned verified-TLS transports/connections with bounded idle
  retention; disable redirects and unnecessary transport compression. Close idle
  connections on cleanup without prematurely closing active requests. Retain
  buffers through transport completion and downstream use; no pooling before
  measurements justify bounded retention. No background inspection workers.
- Scope handlers/configuration and request state independently. Use distinct
  engine datasources for different sites/policies; share a challenge secret only
  within one site's intended Bot trust domain so cookies/assets/submissions work
  across that site's policy routes. Do not share challenge trust across sites or
  use global engine allowlists as Bot-only exclusions.
- No LAPI/blocklist/decision client is included. This alone cannot prevent the
  external engine from creating firewall bans: native WAF/Bot collections can
  emit IP-scoped alerts/scenarios. The deployment's LAPI profiles must short-circuit
  these site AppSec/Bot/rate-limit alerts with no decisions before global ban
  profiles, and shared firewall/log pipelines must not promote those detections.
  The simplest baseline is a dedicated AppSec LAPI with an initial matching
  profile having `filters: ["true"]`, `decisions: []`, `on_success: break`;
  a shared LAPI instead needs complete reviewed alert/scenario filters.
  Preserve alert/metric visibility and verify that Site A's denial never creates
  a shared decision affecting Site B. Do not modify live engine/firewall state.

Evidence: engine [partial-read behavior](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/request.go#L308),
[body limits](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/acquisition/modules/appsec/appsec_bodysize_test.go),
[Caddy upload deadlines](https://github.com/caddyserver/caddy/blob/0d98caea58f794f88e709b1bef2880996a471bca/modules/caddyhttp/server.go#L62),
[global engine allowlist bypass](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/acquisition/modules/appsec/appsec_runner.go#L455),
[default IP ban profile](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/config/profiles.yaml),
[decision-free profile evaluation](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/csprofiles/csprofiles.go#L97)
and [profile short-circuiting](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/apiserver/controllers/v1/alerts.go#L226).

**Verified reference gaps and acceptance handoff**

The Caddy reference's [AppSec client](https://github.com/hslatman/caddy-crowdsec-bouncer/blob/4a6ce1d3094dbfd270fecf2a91aaab81663d0cb4/internal/core/appsec.go#L92)
can inspect a prefix, skips some unreadable bodies, accepts some unexpected
statuses and models only action/status, without the complete challenge envelope.
Traefik also has prefix/unreadable-body and optional fail-open behavior; use its
challenge/CSP/cookie/connection tests as cases, not as our allow policy. Envoy's
[client](https://github.com/kdwils/envoy-proxy-crowdsec-bouncer/blob/f21c149179e2d00fde3b111a4f3de52d618a4106/waf/waf.go#L175)
flattens headers and forwards URL.Path rather than the complete query-bearing
request target; do not import those losses into Caddy. CRS's pinned
[Coraza overrides](https://github.com/coreruleset/coreruleset/blob/e03a4f6dabc7a30ebd8c52c97d28a154f590a48f/tests/regression/coraza-overrides.yaml)
also demonstrate engine differences, so a rule-set version is not evidence that
every detection works.

The next slices must prove all four policy modes, request/body fidelity, native
CRS/schema/rate-limit outcomes, complete challenge exchanges, WAF under valid
cookies/exclusions, cross-site/firewall isolation, lifecycle and bounded failure
paths. Compare against matching Caddy with zero added disabled-path allocations;
measure protected throughput, tail latency, CPU, allocations and retained memory.
No Caddy/engine/browser runtime, attack corpus, benchmark or native Linux target
was exercised in this read-only audit. Graft has no indexed code and Go MCP
reports no Go workspace in this checkout; no implementation scaffolding was
created to work around that.

## 2. Bootstrap and implement the module

- [x] Boundary: Root `go.mod`/`go.sum`, `cmd/caddy/` and `modules/appsec/`.
- [x] Initialize `github.com/TrueParser/trueops-appsec` with reviewed pins and a
  thin launcher retaining standard Caddy modules, CLI and configuration behavior.
- [x] Register the native module; prepare configuration/policies during loading
  and reuse Caddy lifecycle, trusted-client identity and suitable client facilities.
- [x] Implement host/path opt-in and independent off, WAF-only, Bot-only and
  combined behavior. The disabled path performs no security work or body reads.
- [x] Implement native inspection and complete body capture/replay with bounded
  ownership; preserve method, Host, URI/query and headers. Never accept or forward
  a silently truncated prefix after a read/framing failure.
- [x] Implement the complete native challenge exchange: envelopes, browser
  status/body/headers/CSP, repeated cookies, assets, submissions and valid-cookie
  behavior. Challenges, denials and errors must not become explicit native allow.
- [x] Continue directly to the original handler after allow; preserve WAF when
  Bot Detection permits/excludes a request and isolate sites across profiles,
  caches and enforcement. Integrate reviewed native CRS, schema-validation and
  engine-side rate-limit profiles without local detection/policy execution or
  gateway-wide firewall side effects.
- [x] Reuse transports/connections; propagate deadlines/cancellation and retain
  resources while in use. Preserve native graceful reload/shutdown and configured
  limits. Keep diagnostics bounded, opt-in and free of bodies or real secrets.
- [x] Evidence: Focused module tests cover each implemented behavior and failure
  path using self-contained fixtures with diagnostics enabled.
- [x] Completion: The configured module performs native inspection/remediation
  and direct continuation under the audited contract, with required checks green.
- [x] Slice complete.

## 3. Correctness and performance verification

- [ ] Boundary: Module tests, `tests/integration/` and `benchmarks/`.
- [ ] Verify all four policy combinations and cross-site/firewall isolation;
  prove allow invokes the original handler and deny/challenge/error does not.
  Cover native CRS attacks, API schema violations and rate-limit 429/isolation.
- [ ] Cover complete/empty/large bodies, read errors, invalid framing, configured
  size limits, supported compression/streaming/upgrades and claimed content
  handlers. Check reload, cancellation, timeout, concurrent ownership and recovery.
- [ ] Verify the full challenge/browser protocol against the reviewed real
  engine, including repeated cookies and WAF remaining active for valid bot cookies.
- [ ] Gate maintainer-local dependencies with `TRUEOPS_APPSEC_TEST_LOCAL=1`
  outside CI; skip before side effects by default and whenever `CI=true`.
  Keep unit tests and isolated fixtures enabled in normal GitHub test runs.
- [ ] Compare matching upstream Caddy, inactive bundle, configured disabled
  middleware, labelled synthetic overhead and real WAF/Bot/combined/challenge
  paths using the performance guide's workloads and reproducible inputs.
- [ ] Verify zero added heap allocations/bytes on the disabled path. Measure
  throughput, errors, CPU, p50/p95/p99, allocations and retained memory, including
  concurrent upload/hostile pressure and recovery; establish measured budgets.
- [ ] Exercise the exact Windows-built artifacts on native Linux amd64 and
  arm64 for required target behavior and performance; do not substitute cross-builds
  or CI smoke checks for native acceptance.
- [ ] Evidence: Identify exercised engine/browser/target paths and exact binary
  checksums; retain raw logs/measurements outside this ledger. Investigate failures
  from telemetry and rerun the affected checks after the smallest supported fix.
- [ ] Completion: Required correctness, isolation, real-integration and measured
  performance acceptance passes; unavailable checks remain pending, never passed.
- [ ] Slice complete.

## 4. Documentation and final handoff

- [ ] Boundary: `README.md`, relevant existing guides, `THIRD_PARTY_NOTICES` and
  final repository verification; no release publication work.
- [ ] Document actual configuration/examples, profile pins, policy combinations,
  body/resource limits, failure behavior, challenge routes and local-test setup.
  Keep product requirements in guides and contributor workflow in `AGENTS.md`.
- [ ] Update required dependency/license notices and operator guidance for the
  implemented module and existing build/release workflow inputs.
- [ ] Run formatting checks, the full `go test -v ./...` suite with applicable
  diagnostics, `go vet ./...` and `go build ./cmd/caddy` on Windows. Confirm changed
  source has no compiler/analyzer warnings and no new dependent-file diagnostics.
- [ ] Evidence: Review the focused final diff, preserve unrelated work, verify
  documentation links and report actual test/native/performance results.
- [ ] Completion: Every required implementation and acceptance item is verified;
  hand over green tested code with any genuine external blocker stated explicitly
  and its dependent checklist items left pending.
- [ ] Slice complete.
