# TrueOps AppSec Engineering Invariants

**Scope:** Implementation, refactoring, debugging and review of the standalone
Caddy distribution and its in-process CrowdSec AppSec module.

Implement the simplest correct solution for the current requirement. A
validation, dependency, restriction or abstraction must prevent a concrete
defect, enforce an actual trust/correctness boundary or satisfy an explicit
requirement. Do not make valid operations harder through speculative checks.

## 1. Native ownership and reuse

- Caddy owns routing, TLS, CLI/configuration, content handling, trusted-client
  identity and server/module lifecycle. Use its supported interfaces.
- CrowdSec owns detection and native decision/challenge behavior. The module
  owns scoped integration and enforcement; do not build a competing detector
  or policy engine.
- Reuse suitable Go transports, Caddy facilities and supported client functions.
  Consult the [implementation references](implementation-references.md) for
  CrowdSec API/protocol behavior and reuse opportunities.
- Keep changes local to the requested behavior. Do not add a management service,
  persistence layer, generic controller, worker framework, compatibility shim or
  runtime extension mechanism without a current, demonstrated requirement.
- Use the smallest state and ownership model that represents the operation and
  its real failures. Do not add speculative retries, fallback execution paths or
  background reconciliation. Never blindly repeat an exchange whose side
  effects may already have occurred.

## 2. Validation at the authoritative boundary

- Validate untrusted request/configuration inputs where they enter the relevant
  boundary. Reuse an existing authoritative check unless another layer accepts
  independently untrusted input or enforces a distinct boundary.
- Add limits and rejection rules only for documented protocol requirements,
  concrete resource/abuse constraints or demonstrated defects. Fixture sizes,
  guessed capacity ceilings and formatting preferences are not product rules.
  Accept semantically valid inputs under the actual contract.
- Use trusted Caddy scope/identity and validated native responses. Do not invent
  unrelated response gates, but do not confuse HTTP success with native allow.
- Logs, metrics and cached diagnostic status explain behavior; they do not
  authorize requests or become unrelated prerequisites. Native AppSec decisions
  remain protocol authority. An unavailable engine must not block an
  unprotected scope.
- Preserve native identity/expiry rules, TLS validation and locally measured
  timeouts. Do not invent cross-machine clock comparisons or arbitrary skew
  allowances as acceptance gates.
- Preserve supported compatibility and reviewed pins. Do not introduce exact
  version-equality checks where the documented protocol permits compatibility.
  Build pin requirements are owned by the build/release contract.

Before adding a restriction, establish the concrete defect it prevents, its
owning authority, whether it duplicates an existing check, and whether it can
reject valid traffic because of stale diagnostics or unrelated failures.
Choose the smallest justified check; repair an incorrect gate rather than
adding bypass flags, guessed tolerances or new subsystems around it.

## 3. Correctness and security remain mandatory

Preserve the [product invariants](product-invariants.md): direct continuation,
independent WAF/Bot policies, site/firewall isolation, complete bodies, native
challenge handling, bounded V1 policy scope and graceful lifecycle semantics.

- Performance or availability work must not bypass required inspection, scope,
  authentication/trust, native decisions or the defined timeout/failure policy.
- Keep real credentials and challenge secrets out of diagnostics, errors and
  fixtures. Do not log request bodies. Preserve input/path/command safety at
  relevant boundaries.
- Keep request-local state isolated. Shared buffers, transports and concurrent
  work need clear ownership, cancellation and justified bounds; caller timeout
  must not release resources still in use.
- Incomplete reads, malformed responses and uncertain side effects must not
  silently become successful inspection or safe permission to continue.
- Use native graceful reload/shutdown behavior and configured shutdown limits;
  do not impose an unlimited active-request survival guarantee.

These safeguards do not justify unrelated health gates, arbitrary resource
limits or a broad hardening project around a narrow change.

## 4. Evidence and verification

Establish observed behavior and reproduce a defect before fixing it. Make the
smallest change supported by that evidence, preserving unrelated behavior.
Report demonstrated blockers separately from optional improvements.

Test working behavior and meaningful failure cases. When removing a redundant
check, verify that the owning security/correctness boundary remains enforced.
Do not add tests solely to preserve an unjustified restriction.

Mocked responses and unit scaffolding do not prove real native AppSec, browser
or content-handler behavior. Exercise the integration required by the task;
report unavailable acceptance honestly. Planned, skipped or synthetic execution
does not establish the requested outcome.

Performance claims require measurements under
[performance-requirement.md](performance-requirement.md); they must preserve
correctness and security.

## 5. Contract ownership

- [Product invariants](product-invariants.md): functional behavior and primary
  performance acceptance.
- [Performance requirements](performance-requirement.md): request-path costs,
  resource bounds, benchmarks and regression evidence.
- [Build/release invariants](releasing.md#build-and-release-invariants):
  independent repository ownership, reviewed pins and verified artifacts.
- [AGENTS.md](../AGENTS.md): contributor workflow, platform rules and handoff.

Use these contracts directly rather than duplicating their detailed requirements
or importing assumptions from unrelated applications.
