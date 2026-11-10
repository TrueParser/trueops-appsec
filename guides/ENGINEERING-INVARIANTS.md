# Engineering Invariants

**Scope:** All implementation, refactoring, debugging, code review, and AI-assisted development.

**Purpose:** Build software that works correctly without adding speculative restrictions, unnecessary complexity, or mechanisms that block valid operations.

These invariants apply to `trueops-caddy`, the standalone Go/Caddy distribution
defined in [proposals/bundled-caddy-binary.md](proposals/bundled-caddy-binary.md).
Use them alongside [PERFORMANCE-REQUIREMENT.md](PERFORMANCE-REQUIREMENT.md) and
[AGENTS.md](../AGENTS.md). The proposal is the scope reference; it does not mean
the proposed code, pins, platforms or release infrastructure already exist.

The distribution bundles reviewed modules through supported Caddy extension
points. It is independent of the TrueOps management application and TrueWAF
engine. Do not carry their databases, controller workflows, UI or detection
architecture into this repository. Performance is a primary engineering
requirement alongside correctness and security, with measured evidence required
for performance claims and release acceptance.

## 1. Core Rule

**Implement the simplest correct solution. A validation, restriction, dependency, or abstraction must earn its place by preventing a concrete defect or satisfying an explicit requirement.**

Do not add code merely because an undesirable scenario can be imagined. Identify the actual failure mode, the boundary responsible for preventing it, and why existing protections are insufficient.

A system must not become harder to operate because defensive checks were added without evidence that they improve correctness or safety.

## 2. Validation Invariants

1. **No speculative validations.** Add a restrictive check only for a documented contract, an actual security or data-integrity boundary, a proven defect, or a correctness condition intrinsic to the operation. An invented edge case is not sufficient justification.
2. **No duplicate authority.** Do not repeat validations across layers unless those layers enforce distinct trust boundaries or independently receive untrusted input. Reuse the existing authoritative decision.
3. **No redundant response gates.** When the native protocol's authenticated exchange, request scope and validated response establish correlation, do not invent an unrelated acceptance gate. This does not permit treating HTTP success alone as native allow or skipping required challenge validation.
4. **No cross-machine clock ordering.** Do not use wall-clock timestamps from separate machines to establish causal ordering, replay identity or acceptance of an otherwise correctly correlated exchange. Use the protocol's authoritative identity, sequence or revision where defined. When freshness is required, measure it from timestamps recorded by the authority evaluating freshness.
5. **No arbitrary clock-skew tolerances.** Do not compensate for an invalid cross-clock comparison by adding a guessed number of seconds. Fix the source of authority instead. Keep real temporal security constraints, such as certificate validity and signed-token expiration.
6. **No unnecessary freshness gates.** Require recent observations only when the operation genuinely depends on current conditions. Immutable facts, recorded completion, and historical evidence must not expire merely because time passed.
7. **No observation-as-authority by default.** Logs, metrics, traces, cached status and diagnostic readings must not become request or configuration blockers unless an explicit correctness or safety requirement makes them authoritative. Native AppSec decisions are protocol authority, not optional telemetry.
8. **No unrelated prerequisites.** Do not block a valid operation because an optional service, diagnostic, feature, unrelated component, or whole-system health check is unavailable. Validate only the operation's actual dependencies.
9. **No arbitrary capacity ceilings.** Do not impose invented limits on nodes, records, workers, connections, payloads, or concurrent operations. Use documented product limits and proven resource or safety constraints. Bounds that protect memory, time, or abuse must have a concrete rationale.
10. **No invented version restrictions.** Enforce explicit compatibility and pinned-artifact requirements where they exist. Do not demand exact equality when the accepted contract allows compatible versions.
11. **No syntactic perfectionism.** Accept semantically valid inputs under the defined contract. Do not add arbitrary case, formatting, ordering, normalization, or naming constraints without a correctness, interoperability, or security reason.
12. **No false consistency prerequisites.** Distinguish configured policy, active Caddy configuration, per-request native decisions and diagnostic observations. Temporary disagreement is not automatically corruption or grounds to reject an unrelated operation. Resolve it when the action actually depends on it.
13. **No blanket fail-closed policy for optional evidence.** Fail closed at real authorization, trust, integrity, and destructive-operation boundaries. Elsewhere, expose unknown or degraded observations honestly without unnecessarily disabling valid behavior.
14. **No unproven validation expansion during fixes.** A bug fix must remove or repair the failing condition; it must not grow into new checks, general policies, or changed unrelated behavior.

## 3. Architecture and Implementation Invariants

1. **Functional path first.** Implement and verify the actual required operation before investing in surrounding frameworks, generalized workflows, or speculative recovery machinery.
2. **Native authority stays native.** Caddy owns routing, TLS, CLI/configuration, content handling and server lifecycle. CrowdSec owns detection and native decisions/challenges. The custom module owns scoped integration and enforcement. Use supported interfaces rather than patching Caddy or building competing server, detection or lifecycle machinery.
3. **Reuse existing infrastructure.** Prefer Caddy's configuration, trusted-client identity, module lifecycle and observability facilities, plus suitable existing Go transports and libraries. Do not introduce a second implementation of the same responsibility.
4. **No abstraction without a current use.** Do not add interfaces, factories, plugins, generic controllers, adapters, compatibility layers, or extensibility points merely for possible future requirements.
5. **No unnecessary state machines.** Use the smallest state model that correctly represents the current operation and its real failure outcomes. Do not invent extra states, transitions, or coordination services.
6. **No speculative retries or fallbacks.** Do not add automatic retries, fallback providers, alternative execution modes, or background reconciliation without explicit semantics. Never blindly repeat an operation whose side effects may already have happened.
7. **No observability-driven control logic.** Instrumentation records and explains behavior; it does not silently determine business or operational authorization. Do not expand telemetry into a dependency for correctness unless expressly required.
8. **No speculative hardening projects.** Do not broaden a focused change into platform-wide redesign, generalized security work, or future-proofing unless the existing behavior demonstrably cannot meet the requirement.
9. **Preserve existing behavior.** A change must be local to the stated need, except for directly required dependent changes. Do not modify unrelated services, contracts, or workflows for uniformity alone.
10. **Avoid duplicated recovery frameworks.** Use existing Caddy lifecycle and native protocol mechanisms. Do not add an operation journal, command channel or reconciliation service without an explicit requirement. Observe uncertain side effects before deciding whether another native action is safe.

## 4. Rules for Adding a Restriction

Before implementing a new validation, blocking prerequisite, capacity limit, retry rule, or failure gate, answer all five questions:

1. **What exact invalid or unsafe behavior does it prevent?**
2. **Is the behavior forbidden by an explicit requirement, inherent correctness condition, trust boundary, or demonstrated defect?**
3. **Which component is authoritative for the decision, and is the condition already enforced there?**
4. **Can this check reject a legitimate operation because of clock skew, stale caches, optional evidence, temporary partial state, or unrelated failures?**
5. **Can the same requirement be met with a smaller local change?**

**Decision:** If the check has no concrete justification, do not add it. If a justified check blocks valid operations, correct the check or its authority rather than layering arbitrary exceptions and tolerances.

Do not require a separate design ceremony for routine checks: apply these questions while implementing or reviewing the change.

## 5. Required Safeguards Remain Mandatory

These invariants **do not** authorize weakening necessary protections. Preserve, where applicable:

- Authentication, authorization, least privilege, tenant isolation, and ownership boundaries.
- Input validation at untrusted boundaries; injection prevention and safe handling of paths, commands, and data.
- Cryptographic identity, certificate chain, hostname, and validity checks.
- Request/response integrity, concurrency control, idempotency where required and native exchange correlation.
- Data-loss prevention, explicit confirmation for destructive actions, and safe handling of uncertain side effects.
- Documented protocol constraints, native compatibility requirements, and real resource-exhaustion or abuse limits.
- Fresh native observations **when the documented operation actually requires them**, without inventing cluster/quorum dependencies for a standalone Caddy module.

**Safety is not optional. Speculative restrictions are not safety.**

## 6. Review and Implementation Contract

- **First assess correctness.** If the current plan satisfies the requirement, implement it without broadening the scope.
- **Report real blockers only.** Distinguish demonstrated defects from optional improvements, preferences, and hypothetical risks.
- **Prefer the smallest fix.** Remove an unjustified gate rather than adding bypass flags, retries, clock tolerances, or new subsystems around it.
- **Test working behavior and meaningful failure cases.** Do not invent tests whose only purpose is to preserve an unjustified restriction.
- **Preserve required safeguards.** When removing a redundant check, verify that the actual owning boundary still enforces the relevant security or correctness invariant.
- **Prove end-to-end behavior.** Unit tests of scaffolding do not substitute for real execution when the task's acceptance criterion is a working integration.
- **Keep implementation and evidence honest.** A planned, queued, mocked, or merely observed action is not proof that the requested functional outcome occurred.

## 7. Default Engineering Decision

> **If the simplest existing implementation already satisfies the contract, do not add another mechanism.**
>
> **If a valid operation fails because of a defensive check that has no necessary correctness or safety purpose, remove or correct that check.**
>
> **If a genuine safety requirement exists, enforce it at its authoritative boundary using the least restrictive correct mechanism.**

## 8. Bundled Caddy Contract

1. **Standalone and upstream-owned.** Consume an exact reviewed Caddy Go module
   pin and retain standard modules through a thin launcher. Do not fork, clone,
   vendor, copy or patch Caddy's source tree. No cross-repository imports,
   credentials or runtime callbacks into another management application.
2. **Explicit bundle composition.** Use reviewed pinned imports and supported
   Caddy module registration. Keep distribution and upstream versions distinct.
   Do not add a runtime plugin installer, generic registry, competing updater
   or deployment-host compilation requirement.
3. **Direct content path.** Continue to the original Caddy handler in-process
   after explicit native allow. No extra content proxy or HTTP re-entry.
   Preserve method, Host, URI/query, headers and complete-body semantics.
   Handler support requires actual integration evidence.
4. **Inactive means inactive.** Protection is opt-in by configured host/path.
   With WAF and Bot both off, ordinary content requests perform no inspection
   calls, body capture, allow-cache lookup or challenge handling. An unavailable
   AppSec engine cannot block an unprotected scope.
5. **Independent policies and trusted identity.** A valid bot cookie does not
   bypass WAF; a bot exclusion does not disable a matching WAF policy. Bind each
   scope to its reviewed native profile and Caddy's trusted-client identity.
   Public headers cannot weaken the profile or forge identity. Preserve scope
   isolation across hosts, paths and concurrent requests.
6. **Native decision integrity.** Errors, malformed responses and challenges are
   not allow. Implement the complete CrowdSec challenge protocol, including
   envelopes, browser status/body/headers/CSP, repeated cookies, assets and
   submissions. Challenge HTTP 200 or 307 must not invoke the application handler.
   Define and test timeout/failure behavior before stable release; no implicit
   allow, unauthorized cached decision or discarded denial for speed.
7. **Complete input and honest limits.** Read errors, interrupted bodies and
   invalid framing must not become successfully inspected or replayed partial
   bodies. Never silently truncate. Derive limits from protocol and measured
   needs; specify oversize, compressed and streaming behavior. Preserve upgrades
   and streaming outside inspected scopes. Do not claim WebSocket-frame or
   unbounded-body inspection without evidence.
8. **Bounded resources and lifecycle.** Keep request-local state local. Shared
   transports and buffers follow Caddy's lifecycle with clear ownership, bounded
   retention and cancellation. Timeout does not release capacity still in use.
   Reload/shutdown must not drop active requests or leak goroutines. Keep
   diagnostics opt-in and bounded; exclude bodies, credentials and challenge
   secrets. Do not add a new analysis engine or speculative pooling/cache layer.
9. **Measured whole-path performance.** Compare matching upstream, inactive
   bundle, labelled synthetic overhead and real WAF/Bot/combined/challenge
   paths. Record latency, throughput, errors, CPU, allocations and memory,
   including idle retention and recovery after bursts. Disabled behavior must
   match upstream within measured variation; derive numeric budgets from stable
   controlled baselines. No unexplained material regression ships.
10. **Real platform and release evidence.** Normal development and builds run
    on Windows. Run Windows-built artifacts natively on each published target;
    cross-compilation is not runtime or performance acceptance. Real engine and
    browser behavior cannot be replaced by mocks. Accept the exact binary that
    will be packaged and published with checksums, manifest, provenance and
    notices. Missing required evidence leaves acceptance/release pending.
    Preserve published assets and tags; corrections require a new release.
