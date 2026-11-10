# Independent bundled Caddy distribution

**Status:** Proposed. This document defines a new repository; it does not create or publish it.

**Recommended repository name:** `trueops-caddy`.

**Proposed local location:** `D:\Development\trueops-caddy`, as an independent Git repository.

**Hosting:** A new public GitHub repository under the maintainer's chosen account or organization. Public releases provide direct binary downloads without requiring a GitHub account.

## 1. Objective

Build and publish a standalone Caddy distribution containing upstream Caddy and selected compiled-in modules, with performance as the paramount engineering requirement alongside correctness and security.

Operators download a ready-to-run binary. They do not need Go, `xcaddy`, a source checkout or another management application on the deployment machine. The repository must build, test, release and operate independently.

The first custom module provides an efficient in-process CrowdSec AppSec integration. Other reviewed modules can be included in future releases without creating a fork, a runtime plugin installer or another distribution architecture.

## 2. Repository and upstream boundaries

- Create a new local repository from an empty directory and host that repository on GitHub.
- Do **not** fork, clone, vendor or copy the Caddy source tree into it.
- Consume `github.com/caddyserver/caddy/v2` through Go modules at an exact reviewed release. Normal Go module resolution is the supported upstream acquisition mechanism.
- Retain upstream standard modules and use a thin executable entry point calling Caddy's existing command entry point.
- Register custom modules through Caddy's supported module interfaces and normal Go imports. Never patch Caddy internals to make a module work.
- Commit `go.mod` and `go.sum`; pin the Go toolchain and every additional module version or immutable source revision. No floating branches or `@latest` in release builds.
- Keep distribution release versions separate from the upstream Caddy version. A new module revision produces a new distribution release even when Caddy itself is unchanged.
- Keep source, tests, configuration examples, release automation and documentation self-contained. No imports, file references, credentials or runtime callbacks into another application or repository.

Caddy documents both [custom builds](https://caddyserver.com/docs/build) and [module registration and lifecycle](https://caddyserver.com/docs/extending-caddy). Those supported extension points are the foundation of this distribution.

## 3. Initial scope and exclusions

### Included

- One standalone Caddy executable per published platform, containing standard Caddy and the reviewed custom module set.
- An in-process HTTP AppSec module with independent WAF and Bot Detection policies, configured through native Caddy configuration.
- Correct request-body handling and direct continuation to the original Caddy content handler after explicit allow.
- Performance comparisons, protocol tests and actual supported-platform acceptance.
- Windows development/build tooling and GitHub Actions verification, packaging and release publication.
- Versioned downloads, SHA-256 checksums, a build manifest, build provenance and required license notices.
- A documented, small process for adding another compiled-in module later.

### Excluded

- A Caddy fork, copied source tree or custom HTTP server replacing Caddy.
- A management UI, resource inventory, deployment agent, remote command channel or configuration database.
- A second application proxy or a public-to-private Caddy round trip for AppSec enforcement.
- Bundling or managing the CrowdSec engine, firewall services or host operating-system packages. A configured AppSec engine is needed only when that feature is enabled.
- A new detection engine, rule language, rule editor, arbitrary plugin marketplace or on-demand compilation on deployment hosts.
- An automatic host updater, package repository, container platform or unrelated service framework.

## 4. Minimal repository shape

```text
cmd/caddy/main.go              Thin Caddy launcher and explicit module imports
modules/appsec/               Custom Caddy module, configuration and focused tests
tests/integration/            Request/protocol/content-handler acceptance
benchmarks/                   Small comparative workload runner and fixtures
.github/workflows/ci.yml      Verification with explicit runner operating systems
.github/workflows/release.yml Tagged build, acceptance and release publication
go.mod
go.sum
README.md                     Build, configuration, download and verification guidance
LICENSE
THIRD_PARTY_NOTICES
```

Keep additional modules in cohesive packages under `modules/`, or import reviewed upstream module packages directly. Explicit imports and pinned Go modules define the bundle. Do not introduce a generic module registry, plugin loader or build orchestration framework.

The initial audit settles exported module identifiers and configuration fields before implementation. Avoid module-ID collisions with existing Caddy plugins. Prototype identifiers are not automatically stable public contracts.

## 5. Request path and module behavior

```text
Incoming request
  → Caddy virtual-host/path routing
  → configured in-process AppSec handler
      → native AppSec decision
          allow      → original Caddy content handler
          deny       → terminal denial
          challenge  → terminal protocol-correct browser response
```

The original content handler remains Caddy's `file_server`, `reverse_proxy`, FastCGI handler or another explicitly supported handler. Enabling protection must preserve its method, Host, URI/query, headers and body semantics. Support for a handler is earned through integration evidence.

Required behavior:

- Protection is opt-in per configured virtual host/path. Both policies off means no inspection calls, body capture, allow cache lookup or challenge handling on the ordinary content path.
- WAF-only, Bot-only and combined policies remain independent. A valid bot cookie does not bypass WAF inspection; a bot exclusion does not disable a matching WAF policy.
- Bind each configured scope to its reviewed native AppSec profile. Public request headers cannot select a weaker profile or forge the original client identity.
- Use Caddy's trusted-client identity and configuration lifecycle. Keep engine credentials out of request logs, responses, fixtures and release assets.
- Accept only an explicit native allow as permission to continue. Infrastructure errors, malformed responses and browser challenge statuses are not allow decisions.
- Implement the complete [CrowdSec challenge protocol](https://docs.crowdsec.net/docs/appsec/bot_detection/challenge_protocol/), including envelope decoding, browser status/body/headers/CSP, repeated cookies, assets and submission exchanges. HTTP 200 or 307 from a challenge does not invoke the application handler.
- Read failures, invalid framing and interrupted input must not become successfully inspected or replayed partial bodies. Never silently inspect or forward a truncated prefix.
- Define body/resource limits from the supported protocol and measured requirements. Do not turn a prototype fixture limit into a product default. Oversize, compressed and streaming behavior must be explicit and tested.
- Preserve streaming and upgrade behavior outside inspected scopes. Clearly define supported handshake/body inspection; do not claim inspection of WebSocket frames or unbounded streaming bodies without proof.
- Specify and test timeout/failure behavior before a stable release. Never obtain better benchmark results by weakening inspection, reusing an unauthorized allow decision or discarding native denials.
- Keep request-local data request-local. Shared transports and reusable buffers follow Caddy's lifecycle; reload and shutdown release owned resources without dropping active requests or leaking goroutines.

## 6. Performance contract — primary design driver

Choose the simplest correct implementation with the lowest measured request-path cost. A feature or abstraction must justify its latency, allocations and operational cost.

### Implementation requirements

- Continue directly to the next Caddy handler. No extra content proxy, internal HTTP re-entry or per-request management-service dependency.
- Keep body-free requests on a body-free path. Disabled modules do no request-specific security work.
- Minimize body copies and allocation churn. Reuse buffers where measurement supports it; bound retention and never return a buffer while a handler or transport still uses it.
- Reuse appropriately bounded local transports and connections. No new connection, client, timer or worker per request when existing facilities suffice.
- Preserve Caddy's efficient static-file and response-streaming paths. Avoid unnecessary response-writer wrappers or full-response buffering.
- Keep routine metrics lightweight and diagnostics opt-in and bounded. Never log request bodies or secrets to obtain performance evidence.
- Profile demonstrated costs before optimizing. Do not add speculative caches, goroutines, queues or custom transport machinery.

### Comparative measurements

Use identical Caddy source versions, toolchains, build flags, hardware, content, inspection configuration and connection behavior. Include:

1. Upstream Caddy without custom modules.
2. The bundled executable with custom modules absent from the request chain.
3. The custom handler's body/protocol overhead control, clearly labelled as a control rather than protected traffic.
4. Real WAF-only, Bot-only and combined inspection.
5. First challenge, valid-cookie traffic and excluded paths.

An external-proxy comparison can demonstrate the effect of removing proxy hops, but must not be the only reference. Do not compare different protection work and call the difference a module optimization.

Cover application GETs, small and large POSTs, representative uploads and static files. Measure concurrency 1 and representative concurrent loads, HTTP/1.1 and HTTP/2, relevant TLS behavior and supported upgrades/streaming. Use repeated runs with balanced ordering and adequate warmup.

Record throughput, p50/p95/p99 latency, errors, CPU, allocations and memory, including retained idle memory after upload bursts. Distinguish sampled RSS from allocation peaks and disclose shared-host/load-generator effects. Preserve raw measurements as CI/test artifacts, not implementation diaries.

Disabled-path behavior must be materially equivalent to the matching upstream control within measured baseline variation. Establish numeric regression budgets from stable measurements on controlled hardware before enforcing percentage thresholds. No unexplained material regression ships; synthetic inspection is never advertised as actual WAF/Bot Detection capacity. Cross-builds and short CI smoke runs do not establish target-platform performance.

## 7. Build and platform policy

- Perform normal development, dependency work, tests and builds on Windows.
- Build from the independent module with a pinned toolchain and reproducible inputs. A thin Go launcher is sufficient; `xcaddy` may be used as a pinned development tool when useful, but is not required on deployment hosts.
- Initial proposed release targets are Linux/amd64 and Windows/amd64, with actual native acceptance for each published target. Linux/arm64 and other platforms are subsequent explicit additions after native verification.
- Start from reviewed Caddy/Go pins. The existing prototype's Caddy 2.11.4 / Go 1.26.6 combination is an experimental reference, not a claim that it is the newest or production-selected release.
- Prefer `CGO_ENABLED=0` when all selected modules support it. A future module requiring CGO or a platform-specific runtime must receive an explicit support/build review before inclusion.
- Record module versions, source commit, toolchain, target and build flags in the release manifest. Preserve upstream version information and native `caddy version`, `caddy build-info` and `caddy list-modules` diagnostics.
- Verify equivalent behavior for the exact release binary. Do not rebuild a different binary after acceptance and publish it as if it were the tested artifact.

## 8. GitHub CI/CD

### Pull requests and main-branch verification

Use explicit OS runners. Windows jobs perform formatting, vet, focused/full repository tests and build both intended targets. Cross-compiled integration test executables and release candidates are then exercised on Ubuntu 24.04 for Linux-specific runtime behavior; no second Go development environment is required there. Windows runtime smoke checks run natively.

Checks cover module registration, CLI/configuration compatibility, body correctness, direct content-handler continuation, reload/shutdown, inactive-path purity, secret exclusion and protocol errors. Real AppSec/browser acceptance and controlled performance evidence remain required before declaring the corresponding feature production-ready.

PR jobs have read-only repository permissions and no release credentials. Pin third-party Actions to immutable revisions and keep untrusted PR code out of privileged publication jobs, following [GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

### Tagged release workflow

1. A maintainer creates a distribution tag such as `v0.1.0` from a reviewed commit. Branch pushes and PRs do not publish production releases.
2. CI resolves the committed pins, verifies the source, builds candidates and records checksums/build metadata.
3. Required native acceptance and performance gates validate those candidates. Missing target evidence or a failed gate leaves the release unpublished.
4. Package the accepted binaries with license notices and the manifest. Generate SHA-256 checksums and GitHub artifact attestations for the published assets.
5. Upload to a draft GitHub Release; publish it only after all required jobs succeed. Grant `contents: write` only to publication, and OIDC/attestation permissions only where needed for provenance.
6. Preserve published versioned assets. Corrections produce a new tag/release; do not silently overwrite binaries or move existing release tags.

Use [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases) for distribution. Expiring workflow artifacts are acceptance/build intermediates, not the supported public download channel. [Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) bind downloadable assets to their source and build workflow; checksum verification alone is not proof of publisher identity.

## 9. Release and download contract

Recommended assets for a distribution tag:

```text
trueops-caddy_v0.1.0_linux_amd64.tar.gz
trueops-caddy_v0.1.0_windows_amd64.zip
SHA256SUMS
manifest.json
```

Archives contain `caddy` or `caddy.exe`, the manifest and required notices. The manifest identifies the distribution tag, source commit, upstream Caddy version, complete reviewed module set, toolchain, build flags and platform. The separate `SHA256SUMS` file records the final archive digests.

Provide version-specific GitHub release URLs. A `latest` convenience link may exist, but installation examples and reproducible consumers use an exact release tag and asset. Do not make users retrieve build logs, source archives or temporary tunnels to obtain the executable.

The README explains downloading, checksum/provenance verification, inspecting included modules, validating configuration and running the binary using ordinary Caddy commands. No compile step or repository checkout is needed on the target.

Updates use a new published bundle to preserve the reviewed module set. Document that upstream module-changing commands are outside that controlled update path; do not introduce a competing updater.

## 10. Adding a future module

For each proposed addition:

1. Record its purpose, source revision, module identifiers, license, supported platforms and any runtime requirements.
2. Reuse a maintained upstream implementation when it satisfies the required contract; audit gaps instead of assuming feature support from its name.
3. Add the exact Go module pin and explicit import. Do not create a runtime loader or a separate build profile for every combination.
4. Test configuration/reload compatibility, module-ID and directive conflicts, disabled behavior, credentials and interaction with existing modules.
5. Repeat affected correctness and comparative performance checks, including the entire bundle's inactive-path baseline.
6. Publish a new distribution release with updated metadata and notices after review. Compiled-in availability never automatically activates the module.

## 11. Implementation sequence and acceptance

- [ ] **Independent repository audit/setup:** Select GitHub owner/visibility, create the empty local repository, establish upstream/toolchain pins and public module contracts, and publish the repository without importing a Caddy source tree. Confirm standalone clean-checkout operation.
- [ ] **Minimal bundled executable:** Implement the thin launcher and native module registration. Preserve standard CLI/API/content handlers and both upstream/distribution identity. Verify Windows and Linux artifacts.
- [ ] **AppSec correctness:** Implement the direct middleware path and real native decision/challenge protocol, independent policies, complete-body/error handling and scoped identity/credential contracts. Prove actual engine/browser behavior rather than synthetic responses alone.
- [ ] **Performance acceptance:** Profile the plugin, compare the controls and real protection modes, establish regression budgets and verify latency/throughput/CPU/memory on supported native targets. Remove unnecessary work before expanding features.
- [ ] **Release automation and operator documentation:** Implement verified tagged publication, downloadable archives, checksums, attestations, manifests, notices and standalone configuration/download guidance.
- [ ] **First release closeout:** Exercise a clean checkout and fresh binary download on each published platform; verify manifests/modules, protocol/native/browser evidence, inactive behavior and release failure handling. Publish only the accepted artifacts and retain concrete unresolved requirements as pending.

The result is a separately usable, performance-driven Caddy distribution with upstream-owned server behavior, explicit custom-module ownership and a verifiable GitHub binary release process.
