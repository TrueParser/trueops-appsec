# AI Agent Guidelines

This file is the working contract for AI agents contributing to `trueops-caddy`.

The scope is the standalone Go/Caddy distribution defined in
[guides/proposals/bundled-caddy-binary.md](guides/proposals/bundled-caddy-binary.md).
It bundles upstream Caddy and reviewed compiled-in modules, initially an
in-process CrowdSec AppSec integration. It is independent of the TrueOps
management application and the TrueWAF engine. It has no management UI,
configuration database, deployment agent or runtime plugin installer.

The proposal defines intended behavior, not evidence of implementation or
authorization to implement every planned item. Inspect the current checkout;
do not assume the proposed source tree, Git repository, Go module, CI or release
assets already exist. This guidance update does not select dependency pins or
settle the public module identifiers and configuration fields reserved for audit.


## Development machine and target environments

- This distribution is developed in Visual Studio Code on Windows.
- Windows is the only development environment for the project unless the maintainer explicitly authorizes otherwise.
- All normal development work must be performed on Windows, including editing, Go tooling, dependency management, builds, unit tests, repository verification, static analysis, formatting, and local development workflows.
- Do not install or configure a second development toolchain in WSL or Linux for agent convenience.
- WSL may be available, but it is not a development environment and must not be treated as one.
- WSL is reserved only for explicitly authorized target-platform deployment testing.
- When WSL is used for target testing, deploy and execute binaries or artifacts produced by the Windows development environment. Do not use WSL to build the project, install Go tooling, run normal Go tests, manage dependencies, format code, perform repository-wide verification, or maintain a duplicate development setup.
- The purpose of WSL is only to validate deployment-target behavior that cannot be meaningfully verified on Windows, such as Linux process execution, shell behavior, filesystem permissions, service behavior, systemd-related packaging, or other Linux-specific runtime semantics.
- Do not move development work into WSL merely because a test, agent, or tool is easier to run there.
- Do not create duplicate Windows and Linux development environments.
- Any Linux or Ubuntu validation must be narrowly scoped to the deployment behavior being tested.
- If a Linux-specific test requires a binary, package, service unit, installer, or other artifact, produce that artifact from the normal Windows development workflow first, then deploy it to the Linux target for validation.
- Cross-compiling a Linux binary on Windows does not count as validating Linux runtime, packaging, systemd, shell, permission, or service behavior.
- Linux-specific behavior must be validated on the actual supported target platform, such as Ubuntu 24.04, when that behavior matters.
- **Remote VPS instructions must never assume Python is installed. Do not provide Python scripts or Python-dependent commands for execution on a remote VPS; use shell tools or the bundled Caddy binary available on the target instead.**
- Tests that cannot run on Windows because they require Linux-specific runtime behavior must be explicitly gated and reported as not run on Windows. They must not be described as passed unless executed on the required target platform.
- Any CI/CD workflow must explicitly declare its operating system.
- Use Windows runners for the main repository pipeline and normal project verification.
- Add narrowly scoped Ubuntu/Linux CI jobs only where the deployment contract requires real Linux validation.
- Do not introduce Docker, Kubernetes, a Linux development workstation, or any other duplicate development environment unless explicitly authorized by the maintainer.
## Compiler warnings and errors

Every changed source file must be free of compiler errors and analyzer warnings
before completion. Verify that the change introduces none in dependent files.

## Core Rules

Read and follow [guides/ENGINEERING-INVARIANTS.md](guides/ENGINEERING-INVARIANTS.md) for all implementation, refactoring, debugging, code review, and AI-assisted development.
Read and follow [guides/PERFORMANCE-REQUIREMENT.md](guides/PERFORMANCE-REQUIREMENT.md)
for dependency selection and performance-sensitive work. Performance is a primary
design requirement alongside correctness and security.

1. Read this file at the beginning of every session.
2. Read only the files and documentation relevant to the requested task.
3. Treat all existing uncommitted changes as user work. Do not discard,
   overwrite, reset, restore, clean, or revert them.
4. Do not implement work outside the user's request. Keep the diff focused.
5. Do not guess about behavior, security, data ownership, compatibility, or
   public contracts. If an uncertainty would change one of those, stop and ask.
6. Do not use phase names in production or test filenames.
7. Do not commit, push, or force-push unless explicitly requested.
8. Do not use destructive database, Docker, or Git commands without explicit
   authorization and a verified target.
9. Prefer the simplest production-grade change that fits the existing design.
   Do not add speculative abstractions, services, wrappers, or refactors.
   Use visible `apply_patch` edits for repository changes. Do not use Python
   scripts or other opaque bulk-rewrite scripts to edit source files; keep each
   change directly reviewable in the tool output.
10. Report verified facts only. Do not claim a test, backend, provider, or
    deployment path passed unless it was actually exercised.
11. Keep each source file at or below 2,000 lines. When a requested change
    would make a file exceed this limit, split the file into cohesive files
    along clear ownership boundaries as part of that change.

12. Preserve upstream Caddy behavior and supported extension points. Do not
    import assumptions or subsystems from the TrueOps application or TrueWAF.

## Maintainer infrastructure and destructive actions

Do not stop or reconfigure maintainer-managed Cloudflare tunnels or WSL instances
without permission. Deleting WSL, deleting a repository or resetting Git requires
double confirmation from the maintainer. Verify the exact target first.

No test-data deletion permission from another repository applies here. Do not
modify remote VPS data, live Caddy state or an operator's AppSec engine without
explicit authorization.

## Running Test during debugging - Non negotiable
During a narrow debugging cycle, run focused tests. Once the fix is confirmed,
run the full suite once before handoff; do not rerun it for every small attempt.

## Debugging

Debugging must be based on telemetry and observability. Before fixing a bug,
enable existing opt-in diagnostics or add bounded, flag-controlled observability
for the affected path. Capture deterministic evidence, reproduce the failure,
then make the smallest supported fix. Never change code based on a guessed cause.
Diagnostics must exclude request bodies, credentials and challenge secrets.

When a bug is identified, continue autonomously through deterministic root-cause evidence, reproduction, the smallest supported fix, and verification. Do not stop after diagnosis, after reporting an intermediate status, or ask the maintainer to tell you to continue. Stop work on that bug only after the fix is confirmed. If a genuine external blocker prevents completion, provide its exact evidence and finish any independent work that remains possible.
## File size limit

The 2,000-line source-file limit in Core Rules is authoritative. Split by clear
responsibility; do not bypass it through compressed formatting or unrelated helpers.
## Task Ledger and Change Planning

Every code change must have a task-ledger entry before implementation starts,
except a focused bug fix performed during an active debugging session; that fix
does not need a separate task-ledger entry.
Use the repository's active task ledger when one exists; otherwise create or
update the appropriate task-tracking document rather than beginning code
without a recorded scope. A small follow-up may use a concise follow-up ledger
entry, but it must still state the requested change, affected files, boundaries,
and verification.

Work that is large enough to cross multiple files, layers, contracts, or
verification paths must use a phase-style ledger with checklist slices. Keep
the full structure proportional to the work and include:

- Objective and concrete goals;
- in-scope work, non-goals, and safety boundaries;
- invariants that must remain true;
- affected contract locations and ownership boundaries;
- a read-only audit slice before implementation;
- separately scoped implementation slices;
- focused test-coverage and regression slices;
- required documentation/update slices; and
- final verification and completion criteria.

Each slice must identify its file/layer boundary, expected evidence, and
completion criteria. Leave future slices pending until they are actually
performed and verified. If implementation reveals that the work is broader
than the ledger, stop and update the ledger before continuing. A proposal,
issue, or discussion does not authorize implementation by itself; the active
ledger entry or explicit user request must authorize the change.

Treat `TASK.md` as a task ledger, not an implementation log. Do not add
implementation diaries, per-attempt debugging logs, or detailed test output to
it. After the planned ledger entry exists, update existing checklist status
only after the corresponding work is verified. Report routine verification
results in the final response and keep raw test logs outside the repository.
Store documentation only when its details are needed for future work, using
existing relevant documentation where possible. Do not create standalone
verification or evidence Markdown files for routine results unless requested.

Only maintainer-requested task items belong in `TASK.md`, with pending or
finished checkbox status. Do not append implementation explanations, execution
notes, test narratives, handoff essays or agent-generated scope additions to a
slice. Keep standing agent instructions in `AGENTS.md` and routine execution
results in the final response, outside the task ledger.

Do not add slices ad hoc. Add a slice only when the maintainer requests an
enhancement or extension. If authorized work unexpectedly expands beyond the
active slice, stop and ask the maintainer how to proceed before adding scope.

Use standard Markdown task checkboxes for trackable ledger items: `- [ ]` for
pending work and `- [x]` for completed work. Do not represent pending or
completed task items with plain hyphen bullets or prose-only status labels.
Within each slice, treat the boundary, work, evidence, completion, and status
entries as trackable task items and give each one its own checkbox. Mark an
entry `[x]` only after it has been performed and verified.

- When a correction is requested within a task slice, correct that existing
  slice rather than creating a follow-up slice.

## Questions during an active task

When the maintainer asks a question during an active task, answer it promptly
and continue the authorized task in the same turn. A question or clarification
does not pause or cancel the task, and answering it is not a reason to end the
turn. Stop only when the task is complete, the maintainer explicitly asks to
pause/stop/cancel, or a concrete external blocker prevents further progress.

## Slice Completion and Handoff

- Never hand off an implementation slice as complete while any required implementation, evidence, verification, acceptance, or ledger checklist item remains pending. “Implement this slice” means finish the full authorized slice and its required verification, not only write code or pass a subset of tests.
- Continue the authorized work through completion. If a concrete external blocker prevents full completion, identify the blocker and its evidence explicitly, keep the slice status pending, and do not describe or hand it off as complete. Do not replace a required acceptance item with an unapproved assumption or a weaker test.
- When a maintainer explicitly schedules a slice's final status change for a later phase, keep the slice's implementation and evidence accurately recorded while leaving its overall status pending until that stated closeout point.

## Repository Shape and Ownership

The intended repository shape from the proposal is a single Caddy distribution:

```text
cmd/caddy/main.go      Thin launcher and explicit module imports
modules/appsec/       AppSec module, configuration, lifecycle and focused tests
tests/integration/   Request, protocol and original-handler acceptance
benchmarks/          Comparative workload runner and fixtures
.github/workflows/   Windows verification/builds and native target acceptance
```

These paths are planned boundaries until implemented. The launcher calls
Caddy's existing command entry point; modules use Caddy's supported interfaces
and lifecycle. Caddy owns routing, content handling, TLS, configuration and
server lifecycle. CrowdSec owns detection and native decisions/challenges;
the custom module owns scoped integration and enforcement.

Consume upstream Caddy through an exact reviewed Go module pin. Do not fork,
clone, vendor, copy or patch its source tree. Retain standard modules. Keep all
source, fixtures, tools and docs independent of other application repositories.
Future modules use explicit imports and reviewed pins, not a generic registry,
runtime loader or deployment-host compilation.
<!-- Go MCP :start -->
## Go MCP and Graft — Go Semantics and Repository Context

Use Go MCP and Graft together for Go repository work. They provide different,
complementary views:

- Go MCP (`mcp__gopls__*`) is primary for Go package and symbol semantics:
  definitions, references, callers, interface implementations, exported API
  shape, and package relationships.
- Graft (`mcp__graft__*`) supplements that analysis with repository
  orientation, wiring, hotspots, and source spans. Use it to check broader
  context and blast radius; it does not replace Go MCP for Go symbol semantics.

Both servers are configured in the Codex TOML. Check the active tool catalog
for the `mcp__gopls__*` and `mcp__graft__*` tools before concluding a server is
unavailable; a narrow name or description search can miss them. If a server is
absent from the active tool catalog, inspect the Codex TOML and report the
specific startup/configuration failure. Do not change user-level Codex
configuration unless an actual defect is verified and the requested work
authorizes that change.

When the Go MCP server is available, it is the mandatory primary mechanism
for Go code navigation and semantic analysis. Use it first to locate package
and symbol definitions, references, callers, interface implementations,
exported API shape, and package relationships. Retain returned symbol
identifiers when the server provides them and reuse them for follow-up queries.
Use the same relevant package/symbol context in Graft when it can add repository
structure or wiring evidence. For Go symbol relationships, use Go MCP results
as authoritative and do not substitute Graft, grep, or broad text matching
when Go MCP can answer the question. Use grep only for genuinely textual
repository search such as configuration, templates, SQL, literals, or
unindexed files.

If Go MCP is unavailable or cannot answer the question, use the narrowest
fallback in this order:

1. `go doc`, `go list`, and `gopls` or equivalent Go tooling;
2. targeted reading of the exact source ranges identified by package layout,
   tests, or documentation;
3. narrowly scoped `rg` for configuration, templates, SQL, literals, or
   unindexed content.

Do not claim Go MCP analysis when it was not available. Use normal local file
tools for exact source reading and edits after the relevant location is known.
<!-- Go MCP :end -->
## Change-Safety Boundaries

### Native Caddy behavior and request continuation

- Preserve native CLI, configuration validation, admin API, TLS and content
  handling. Do not introduce SSH management, another proxy hop, internal HTTP
  re-entry, a configuration database or another management application dependency.
- Protection is opt-in per virtual host/path. With both policies off, perform
  no inspection calls, body capture, allow-cache lookup or challenge handling.
- Continue directly to the original Caddy handler only after explicit native
  allow. Preserve method, Host, URI/query, headers and complete-body semantics.
- Preserve streaming and upgrades outside inspected scopes. Claim support for
  file serving, reverse proxy, FastCGI, uploads or upgrades only after the
  corresponding integration path has actually passed.
- Shared transports, buffers and background work follow Caddy's lifecycle.
  Reload and shutdown must release owned resources without leaking goroutines
  or dropping active requests.

### AppSec policy, identity and secrets

- Keep WAF-only, Bot-only and combined policies independent. A valid bot cookie
  must not bypass WAF; a bot exclusion must not disable a matching WAF policy.
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

### Bodies, resources and dependencies

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

### Distribution and release integrity

- Commit exact reviewed dependency pins and checksums when the Go module is
  created. No floating branches or `@latest` in release builds. Keep the
  distribution version separate from upstream Caddy's version.
- Preserve `caddy version`, `caddy build-info` and `caddy list-modules` diagnostics.
  Record source commit, complete module set, toolchain, target and build flags.
- Initial proposed targets are Windows/amd64 and Linux/amd64; each published
  target requires native acceptance. Additional targets require explicit scope
  and native verification. Cross-compilation alone is insufficient.
- Accept and publish the exact same binary. Packages include required licenses,
  notices and manifests, with SHA-256 checksums and provenance attestations.
- Releases require maintainer-created version tags, successful acceptance and
  performance gates, and verified draft-release completion before publication.
  Missing evidence leaves the release unpublished. Do not move released tags or
  overwrite published assets; corrections require a new distribution release.
- Keep PR jobs read-only and release secrets away from untrusted code. Pin
  third-party Actions to immutable revisions and grant publication/OIDC rights
  only to jobs that need them. Do not publish without maintainer authorization.
- Operators download versioned ready-to-run binaries without Go, `xcaddy` or a
  checkout. Updates preserve the reviewed bundle; do not add a competing updater.

## Testing and Verification

Every test command run during agent work must have diagnostic logging visible
and available bounded tracing enabled for the code under test. Use this
repository's actual diagnostic controls; do not invent flags or copy unrelated
application trace variables. Run Go tests with `-v` and keep both
stdout and stderr available so emitted logs and trace evidence can be reviewed.
Do not disable or discard trace/log output to make a test run quieter. A test
that specifically verifies disabled-by-default behavior may explicitly set its
own trace setting off within that test, then restore it as part of test cleanup.

Once Go source and the module exist, the Windows verification contract is:

```text
gofmt -l ./cmd ./modules ./tests ./benchmarks   # existing Go directories only; no output
go test -v ./...
go vet ./...
go build ./cmd/caddy
```

Run focused package tests first when changing a narrow area, then run the
broader checks required by the risk of the change. Do not edit production code,
tests, or formatting after the required suite is green unless the user asks
for a new change.

Run tests sharing an engine, listener or other mutable fixture serially or use
isolated resources. Do not mutate an operator's live instance for tests. Tests
requiring real Caddy/AppSec/browser environments must declare their setup and
remain gated when unavailable; report skips honestly. Synthetic fixtures do not
prove real engine or browser acceptance. Preserve regression tests; do not weaken,
delete or rewrite assertions merely to make an implementation pass.

For a bug fix, reproduce the bug with a focused failing test when practical,
make the smallest production change, and rerun the original regression plus
the relevant package tests. Acceptance covers module registration, CLI/config
compatibility, complete bodies and errors, direct handler continuation, independent
policies, challenge/browser behavior, inactive-path purity, reload/shutdown and
secret exclusion. Compare the bundle against upstream controls as required by
the performance guide; do not substitute smoke tests for performance acceptance.

### Slice completion test
Before completing an implementation slice, run the full repository suite if it
has not already passed for the final code. Required native/integration/performance
acceptance remains pending until exercised. For documentation-only work, verify
scope, links and consistency; report code checks as not run when no Go module or
source exists rather than creating scaffolding merely to run them.

## Local Development and Build Rules

- Use the pinned Go toolchain declared by `go.mod` once established, coordinated
  with CI and release manifests. The proposal's prototype pins are experimental
  references, not selected production versions.
- Run `gofmt` on changed Go files. Do not use a formatter or generator that
  rewrites unrelated files.
- Do not run `go mod tidy`, upgrade dependencies, regenerate assets, or change
  generated/committed files unless the task requires it.
- Prefer `CGO_ENABLED=0` when all selected modules support it. A CGO or
  platform-specific runtime dependency requires an explicit support/build review.
- Benchmark optimized release-equivalent builds. Record flags and CPU assumptions;
  preserve portable target compatibility. Do not patch Caddy for benchmarking.
- Read relevant README guidance when present and the proposal before changing
  development, configuration, deployment or release workflows. Keep operator
  documentation standalone; container packaging is outside the current scope.

## Git and Context Safety

Commits and pushes belong to the maintainer. Provide a suggested commit message;
do not commit or push unless explicitly requested.

Before editing, use targeted status and diff checks:

```text
git status --short
git diff --stat
git diff -- <affected files>
```

Do not run an unrestricted repository diff by default. After context
compaction, re-check status and the targeted diff before continuing. Preserve
unrelated changes and stop if the requested change overlaps them in a way that
cannot be resolved safely.

If this directory has not yet been initialized as a Git repository, report that
fact and use explicit file baselines for review. Do not initialize Git, create a
remote or publish the repository merely to satisfy these checks.

Do not delete files, remove subsystems, alter public contracts, or introduce
compatibility shims without explicit approval when the requirement is unclear.
If a requested behavior conflicts with an existing security, data-integrity,
or native-protocol invariant, explain the conflict and ask for direction.

## Completion

The final response should state only verified facts:

- what changed and the affected files;
- checks run and their results;
- whether live Caddy, real AppSec/browser, performance and native target paths
  were actually exercised;
- any remaining open items or environment-gated checks;
- one Conventional Commit message suggestion. The message must use
  Conventional Commit format and must not include phase numbers, task ledger
  numbers, or similar tracking identifiers.

Never commit the change as part of the task unless the user explicitly asks.
<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->
