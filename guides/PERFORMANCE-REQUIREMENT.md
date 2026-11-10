# Bundled Caddy Performance Requirements

Status: Normative engineering requirements  
Scope: Library selection, data-path design, parsing, serialization, allocation, concurrency, benchmarking, and performance-sensitive implementation  
Primary language: Go

## 1. Purpose

This document defines the performance requirements for `trueops-caddy`, the
standalone distribution scoped in
[proposals/bundled-caddy-binary.md](proposals/bundled-caddy-binary.md). Apply it
alongside [ENGINEERING-INVARIANTS.md](ENGINEERING-INVARIANTS.md) and
[AGENTS.md](../AGENTS.md).

Performance is a primary design driver alongside correctness and security.
Caddy owns the HTTP server and content handlers; CrowdSec owns detection.
This repository owns compiled-in module integration and enforcement, initially
the direct in-process AppSec handler. It does not implement a new detection
engine, parser framework, management service or connector-to-engine gRPC layer.
Requirements concerning decoding or parsing apply only where the supported
protocol actually requires that work; they do not authorize new analysis stages.

It exists to prevent technically correct but unnecessarily expensive implementations, especially in hot request paths where repeated parsing, serialization, copying, allocation, abstraction, or unsuitable library choices can materially reduce throughput or increase latency and memory usage.

This document is intentionally generic. It does not mandate a specific JSON parser, allocator, SIMD library, executor, parser framework, serialization format, or optimization technique.

The governing rule is:

> Choose libraries and implementation strategies based on the actual data path, required semantics, measured cost, resource safety, and maintainability. Do not select a high-performance dependency and then implement the surrounding path in a way that defeats its performance characteristics.

Performance is part of correctness because attackers control request volume,
input size, encoding and other dimensions that consume CPU and memory in Caddy,
the module and the configured AppSec engine.

## 2. Core Performance Principles

1. Measure before optimizing.
2. Design hot paths before selecting libraries.
3. Minimize transformations of attacker-controlled data.
4. Avoid serialization inside the process unless a real boundary requires it.
5. Avoid unnecessary allocation and copying.
6. Preserve structured parser output instead of repeatedly converting representations.
7. Do not trade semantic correctness or security guarantees for benchmark numbers.
8. Do not introduce complexity whose performance benefit has not been demonstrated.
9. Optimize the whole data path, not an isolated function or library benchmark.
10. Every attacker-controlled operation must have both a semantic purpose and a bounded resource cost.

## 3. Performance Is a Data-Path Property

A fast individual library does not make the system fast.

Agents must evaluate the complete path:

```text
incoming request
    ↓
Caddy virtual-host/path routing
    ↓
configured in-process AppSec handler
    ↓
minimum necessary body capture / protocol encoding
    ↓
native AppSec inspection / challenge exchange
    ↓
validated native decision
    ↓
explicit allow → original Caddy content handler
deny / challenge / error → terminal protocol-correct response
```

Performance decisions must consider the cumulative cost of this path.

Continue directly to the next Caddy handler. Do not add a second content proxy,
internal HTTP re-entry or a per-request management-service dependency. The
AppSec inspection exchange is the required external boundary; content handling
remains in the original Caddy chain.

With both WAF and Bot policies off, the ordinary content path performs no
inspection calls, body capture, allow-cache lookup or challenge handling.
Keep body-free requests body-free. Preserve Caddy's efficient static-file,
response-streaming and supported upgrade paths; avoid unnecessary response-writer
wrappers and full-response buffering.

Do not optimize one stage while introducing larger costs immediately before or after it.

Example of an unacceptable optimization pattern:

```text
fast parser
    ↓
serialize parsed data to JSON
    ↓
deserialize JSON into another structure
    ↓
copy fields into a redundant internal model
    ↓
rebuild the protocol representation
```

A fast parser is irrelevant if the surrounding implementation repeatedly serializes, copies, or rebuilds its output.

## 4. Library Selection Requirements

Before adding or replacing a performance-sensitive dependency, agents must evaluate:

- semantic correctness for the required task;
- parsing or processing model;
- allocation behavior;
- copy behavior;
- streaming support where relevant;
- borrow/zero-copy capabilities where relevant;
- SIMD support if relevant;
- behavior on malformed input;
- attacker-controlled worst cases;
- memory growth characteristics;
- recursion/depth behavior;
- cancellation or bounded-work behavior;
- thread-safety requirements;
- compile-time and binary-size cost where material;
- dependency weight;
- maintenance activity;
- security history;
- license compatibility;
- benchmark evidence relevant to the actual Caddy/AppSec workload.

Do not select a library primarily because:

- it is popular;
- it advertises SIMD;
- a synthetic benchmark shows it is fastest;
- another project uses it;
- an AI model recommends it;
- it has a convenient API.

The library must fit the actual distribution workload and the reviewed native
AppSec protocol. Pin reviewed versions or immutable revisions; account for
supported targets, licensing and bundle-wide inactive-path cost. Do not patch
upstream Caddy or introduce another protocol merely to use a preferred library.

## 5. Library Benchmarking Must Match the Real Usage Model

Do not rely only on upstream headline benchmarks.

A library benchmark is relevant only when it resembles the actual integration.

For protocol parsing, evaluate which of these semantics the integration needs:

```text
parse only
parse + traversal
parse + source spans
parse + borrowed values
parse + owned values
parse + duplicate preservation
parse + provenance
parse + malformed-input handling
parse + repeated field extraction
```

A parser that wins parse-only benchmarks may lose badly when the required
protocol workflow forces additional allocations or conversions.

Agents must benchmark the intended integration path, not merely the library's ideal microbenchmark.

## 6. SIMD Is an Optimization, Not a Design Requirement

Do not add a SIMD-capable library unless the implementation actually benefits from its execution model.

If a SIMD parser is chosen:

- verify that the SIMD path is enabled in the actual target build;
- verify that the target CPU/platform supports the intended acceleration;
- verify that the integration does not immediately copy or reparse the result;
- verify that required semantics are preserved;
- benchmark the complete Caddy/module/AppSec path;
- verify fallback behavior on unsupported hardware.

Do not claim a SIMD optimization merely because a dependency contains SIMD code.

A dependency that can use SIMD but whose fast path is never exercised provides no performance benefit.

Do not add architecture-specific unsafe code merely to claim SIMD support.

## 7. Serialization Policy

### 7.1 Avoid serialization inside the process

Serialization is appropriate at real process, protocol, storage, or compatibility boundaries.

Inside the Caddy process, prefer passing typed Go structures directly.

Avoid:

```text
Go struct
    ↓
JSON
    ↓
Go struct
```

or:

```text
decoded native response
    ↓
JSON
    ↓
another generic response model
```

unless an explicit external contract requires that representation.

### 7.2 The native AppSec protocol is a real boundary

Use the reviewed native CrowdSec AppSec request, decision and challenge protocol.

Its required wire encoding and decoding are intentional. Preserve envelopes,
status, body, headers, CSP and repeated cookies as required by that contract.

Do not introduce additional JSON, MessagePack, CBOR, YAML, or other serialization layers around the same data unless a specific protocol requires them.

### 7.3 Do not serialize for convenience

Serialization must not be used merely to:

- deep-copy a structure;
- compare structures;
- pass data between modules;
- log debug state;
- convert between internal representations;
- cache intermediate results.

Prefer direct typed operations.

### 7.4 Avoid repeated serialization

For one inspection, a logical structure should not be repeatedly serialized and deserialized between stages.

If repeated serialization appears necessary, reassess the ownership or module boundary.

## 8. Copying and Allocation

### 8.1 Every large copy needs a reason

For attacker-controlled or potentially large values, avoid unnecessary:

- repeated `[]byte` / `string` conversions;
- `bytes.Clone` or equivalent full-buffer copies;
- repeated `io.ReadAll` or body replay materialization;
- `fmt.Sprintf` for values that could remain typed;
- buffer reconstruction;
- repeated concatenation.

Small copies are acceptable where they improve clarity and are not material.

Do not distort code merely to eliminate trivial copies.

### 8.2 Track copies across boundaries

When designing a hot path, identify where bytes are copied.

For example:

```text
incoming Caddy request body
    ↓ copy?
inspection body capture / replay storage
    ↓
native AppSec request encoding and transport
    ↓
native response decoding
    ↓ copy?
original Caddy handler reading the complete replayed body
```

Agents should be able to explain each material copy.

### 8.3 Avoid copy-by-architecture

Do not create internal APIs that require a full copy when a read-only view or
stream with a clear lifetime would suffice.

Use slices/readers with explicit ownership where appropriate. Never mutate,
reuse or return a buffer to a pool while a downstream handler, transport or
goroutine still references it. A small slice must not accidentally retain a
large request buffer beyond its intended lifetime.

Do not introduce complex lifetime machinery merely to avoid an insignificant copy.

### 8.4 Pre-allocation

Use capacity hints when sizes are known or safely bounded and measurement shows repeated growth is material.

Do not reserve attacker-controlled claimed sizes without validating them against limits.

## 9. Zero-Copy Guidance

Zero-copy is useful where it naturally fits the parser and ownership model.

It is not a mandatory goal.

Prefer zero-copy when:

- the parser or reader supports safe source-backed views;
- the source buffer lifetime naturally covers analysis;
- provenance benefits from source-backed spans;
- it avoids large repeated copies;
- implementation complexity remains reasonable.

Do not introduce:

- unsafe byte/string aliases;
- shared mutable slices with unclear ownership;
- buffers reused before consumers finish;
- custom memory-management infrastructure;

merely to claim zero-copy behavior.

The target is minimum necessary copying, not ideological zero-copy.

## 10. Intermediate Representations

Every intermediate representation costs CPU and memory.

Before adding one, answer:

1. What semantic information does it provide that the existing representation does not?
2. Why can the next stage not consume the existing representation directly?
3. What allocations or copies does it introduce?
4. How long does it live?
5. Can it retain references/spans instead of duplicating payload data?

Avoid chains such as:

```text
bytes
→ string
→ generic JSON tree
→ normalized map
→ response DTO
→ another response model
```

when fewer representations can preserve the same semantics.

## 11. Request Metadata and Representation Limits

The module must preserve required request/protocol semantics without duplicating
all request data. Do not introduce an Input Graph or detection representation
owned by another engine.

Where metadata or derived values are required, prefer:

- source references;
- spans;
- occurrence identifiers for repeated fields;
- compact protocol metadata;
- immutable shared views with clear buffer lifetimes where practical.

Avoid storing full duplicated payload strings at every processing stage.

Derived values should be materialized only when the transformation requires materialization.

Required representations must have justified resource limits for:

- field/header count and bytes;
- source-range metadata, when required;
- derived-value bytes;
- decoding depth;
- per-request metadata.

## 12. Parser Output Reuse

Once protocol decoding has produced the structure required for enforcement,
reuse it. Do not add language parsing that belongs to the AppSec engine.

Do not:

```text
decode native response
→ inspect
→ encode it again
→ decode the same response again
```

or:

```text
parse request URL
→ inspect routing metadata
→ rebuild URL text
→ reparse the same URL
```

unless separate interpretation contexts genuinely require separate parsing.

When multiple module stages need the same decoded structure, prefer sharing
the immutable result within the request.

Do not introduce cross-request parser caches unless measurement and correctness requirements explicitly justify them.

## 13. Avoid Duplicate Work

Within one inspection, avoid repeating deterministic work.

Examples:

- repeated URL parsing of the same node;
- repeated percent decoding of the same interpretation;
- repeated JSON extraction;
- repeated charset decoding;
- repeated protocol envelope decoding;
- repeated profile/identity derivation for the same trusted scope;
- repeated DNS lookup for the same engine destination when transport policy permits safe reuse.

Where deduplication is introduced, ensure:

- semantic context is identical;
- provenance remains correct;
- caching cannot cross trust boundaries;
- cache keys are bounded;
- cache growth is bounded.

Do not add a generalized caching layer before duplicate work is measured.

## 14. String Construction

Avoid repeated concatenation in hot loops.

Repeatedly rebuilding a growing string or byte slice for each part is an
unacceptable pattern for large input.

Prefer appropriate capacity-aware construction or direct structured traversal.

Do not build large diagnostic strings when a typed reason code plus compact semantic details is sufficient.

## 15. Logging Performance

Logging must not become a hidden hot-path cost.

Do not:

- format expensive log messages when the level is disabled;
- serialize large request structures for routine logs;
- log full decoded protocol objects in production;
- log raw request bodies;
- create high-cardinality log fields without need.

Security findings should emit compact structured metadata.

Verbose protocol diagnostics belong only in explicit, bounded debugging
workflows and must still exclude bodies, credentials and challenge secrets.

## 16. Telemetry Performance

Metrics must be cheap and bounded.

Do not make per-request metrics perform:

- heap-heavy formatting;
- serialization;
- large label construction;
- arbitrary attacker-controlled label generation.

Prefer fixed enums or stable identifiers.

## 17. I/O, CPU Work and Cancellation

Adding goroutines is not a performance optimization for CPU-bound work.

Use Go's context-aware I/O and existing Caddy facilities where work waits on:

- network I/O;
- native AppSec HTTP exchanges;
- DNS;
- timers;
- bounded coordination.

Keep CPU work proportional to supported protocol needs and bounded under
concurrent requests. Do not introduce a worker framework without measured need.

Reuse appropriately bounded transports and connections through Caddy's module
lifecycle. Do not create a new client, connection, timer or worker per request
when existing facilities suffice. Propagate request cancellation and deadlines;
measure connection reuse, queueing and actual work remaining after timeout.

## 18. Goroutine Spawning

Do not spawn a goroutine merely to avoid writing sequential code.

Goroutine creation has scheduling, allocation, synchronization and lifecycle cost.

Before spawning concurrent work, establish that:

- tasks are independent;
- concurrency can improve measured latency or throughput;
- aggregate CPU and memory remain bounded;
- cancellation/accounting behavior remains correct.

Prefer existing Caddy request concurrency over parallelizing each inspection
stage. Additional concurrency must preserve independent WAF/Bot enforcement,
decision ordering and request isolation.

## 19. Queues and Backpressure

Every queue carrying attacker-triggered work must be bounded.

Performance under overload must degrade predictably.

Do not optimize normal-load throughput by introducing an unbounded backlog.

Measure:

- queue wait time;
- queue depth;
- rejection rate;
- active workers;
- work retained after response timeout.

A fast parser behind an unbounded queue is not a performant system.

## 20. Locking and Synchronization

Avoid global locks in request hot paths.

Prefer:

- immutable shared configuration;
- per-inspection state;
- atomic read-mostly state where appropriate;
- short critical sections.

Do not add `sync.Mutex` or `sync.RWMutex` simply because shared ownership is convenient.

If a lock is introduced in a hot path, benchmark contention under concurrent inspections.

## 21. Memory Requirements

Performance analysis must include memory, not only CPU.

Measure:

- bytes retained per active inspection;
- decoded-body expansion;
- parser allocations;
- request/replay metadata allocation;
- decoded protocol object retention;
- result/finding allocation;
- downstream-handler and transport retention;
- queue memory;
- memory retained by timed-out but still-running workers.

Peak RSS matters under hostile concurrency.

A low-latency implementation that permits excessive memory amplification is unacceptable.

## 22. Attacker-Controlled Amplification

For every parser or decoder, evaluate amplification.

Examples:

```text
compressed bytes → decoded bytes
small input → huge AST
small XML → large entity graph
small JSON → extreme nesting
small multipart metadata → many parts
small pattern → expensive parser recovery
small URL set → many DNS operations
```

Record both:

- input limit;
- maximum permitted derived work or memory.

Do not assume source-byte limits alone are sufficient.

## 23. Parsing Limits

Each parser integration must identify relevant limits such as:

- source length;
- nesting/depth;
- token count;
- node count;
- recursion;
- recovery complexity;
- generated synthetic-context size;
- number of parser attempts;
- number of dialect/context variants attempted.

Do not run every supported parser or context against every string.

Any required parse scheduling must be semantically justified and bounded.

## 24. Trusted Scope and Profile Selection

Select the reviewed native AppSec profile from trusted Caddy configuration and
the configured virtual-host/path scope. Use Caddy's trusted-client identity.

Public request headers must not choose a weaker profile or forge client identity.
Do not try every configured profile against every request. Keep any required
interpretation count explicit and bounded by the actual protocol contract.

Do not add local SQL, shell or template detection to reduce engine calls;
CrowdSec owns detection. Avoid request-count × profile-count × decoding-variant
work amplification. Optimize only after preserving the required policy semantics.

## 25. Module and Platform Expansion

Supporting additional compiled-in modules and target platforms has performance cost.

Compiled-in availability must not activate a module on unconfigured requests.

Use explicit imports and exact reviewed pins. Prefer a maintained upstream module
when it meets the contract; audit capabilities rather than infer them from its name.

Do not add runtime loaders, a generic registry or a build profile per combination.

Adding a module must include analysis of:

- configuration, directive and module-ID conflicts;
- extra processing and runtime dependencies;
- memory;
- latency;
- lifecycle, licensing and credential behavior;
- interaction with existing modules;
- bundle-wide inactive-path behavior;
- build compatibility and native acceptance on supported targets.

## 26. Content Decoding

Content decoding must be bounded by:

- encoded size;
- decoded size;
- expansion ratio;
- work budget;
- nesting/layer count.

Do not recursively decompress or decode until data appears stable.

Avoid copying decoded content multiple times.

Where a decoder can stream into the next stage safely and the next stage supports streaming, benchmark whether avoiding full materialization provides a meaningful benefit.

Do not introduce streaming complexity without evidence.

## 27. JSON and Structured Data

For JSON or similar structured formats, select the representation required by security semantics.

Requirements may include:

- duplicate-key preservation;
- order preservation;
- source locations;
- event/visitor processing;
- borrowing;
- bounded depth;
- bounded member count.

Do not select a parser solely for headline throughput if satisfying native
AppSec semantics requires immediately converting its output into a slower
secondary representation.

Likewise, do not use a slow generic tree if a typed or event/visitor path can
extract exactly what the integration needs with less allocation.

Benchmark both when the choice is material.

## 28. Protocol Types and Enforcement

Use types matching the reviewed native AppSec contract at the integration boundary.

Do not keep converting native responses into multiple redundant DTO layers.

One explicit conversion from transport representation to a suitable internal model is acceptable when it improves correctness or ownership.

Repeated transport/internal/transport/internal conversions are not.

Only explicit native allow permits continuation. Denials, malformed responses,
infrastructure errors and browser challenges are not allow. Preserve the full
challenge exchange, including envelope, status/body/headers/CSP, repeated cookies,
assets and submissions. HTTP 200 or 307 from a challenge must not invoke content.

Keep WAF-only, Bot-only and combined modes independent. A valid bot cookie cannot
bypass WAF and a bot exclusion cannot disable a matching WAF policy. Define and
test timeout/failure behavior before stable release; never invent implicit allow.

## 29. Error-Path Performance

Attack traffic frequently exercises error paths.

Benchmark and inspect:

- malformed JSON;
- malformed XML;
- broken compression;
- malformed URLs;
- parser recovery;
- malformed native decision/challenge envelopes;
- engine timeout, disconnect and interrupted exchange;
- oversized metadata;
- incomplete request bodies.

Read errors, invalid framing and interrupted input must not become successfully
inspected or replayed partial bodies. Never silently inspect or forward a
truncated prefix. Define and test oversize, compressed and streaming behavior;
derive limits from protocol and measured resource needs rather than fixture sizes.

Error handling must not be substantially more expensive than valid processing without a justified reason.

Do not allocate large formatted error messages for attacker-triggered failures.

## 30. Decisions, Diagnostics and Result Size

Decision metadata and diagnostic generation must be bounded. Preserve required
native response/challenge content; never truncate it into a different decision.

Avoid duplicating payload data in findings.

Prefer:

- reason code;
- source location;
- occurrence;
- compact semantic metadata;
- bounded explanation.

Do not attach entire AST fragments or complete attacker payloads to findings.

Result-size limits are part of performance and security.

## 31. Hot-Path Abstraction Requirements

Abstractions are acceptable when they do not materially obscure or degrade the hot path.

Avoid:

- boxing every event;
- interface dispatch in tight loops without measured need;
- heap allocation per token;
- dynamically typed maps for fixed internal structures;
- generic serialization-based message buses inside the process.

Do not remove a clear abstraction merely to avoid an unmeasured nanosecond-level cost.

Measure before changing architecture.

## 32. Collections

Choose collections based on access pattern.

Do not default to a Go `map` for every structure.

Consider:

- slices for small ordered collections and read-only traversal;
- constants/arrays for fixed categories;
- maps only when keyed lookup is actually needed.

For small bounded collections, linear search may outperform hashing and allocate less.

Benchmark where material.

## 33. Hashing

Do not replace standard hashing with a faster non-cryptographic hasher on attacker-controlled keys without considering hash-flooding resistance.

Performance optimizations must not introduce algorithmic denial-of-service risk.

## 34. Buffer Reuse and Pooling

Do not add object pools or buffer pools by default.

Pooling can introduce:

- retained peak memory;
- synchronization;
- complex lifecycle;
- stale sensitive data;
- cross-request contamination risk.

Use pooling only after measurement shows allocation is a material bottleneck and security/lifecycle behavior is clear.

## 35. Custom Allocators

Do not introduce a custom global allocator merely because benchmarks elsewhere show improvements.

A custom allocator requires:

- repository-specific measurement;
- target-platform validation;
- memory-profile comparison;
- concurrency testing;
- security review;
- explicit maintainer approval.

## 36. Unsafe Optimizations

Go's `unsafe` package is not a general performance tool.

Do not use unsafe aliases, raw pointer/buffer access, architecture-specific
assembly or custom memory management unless measurement proves the safe
implementation is a material bottleneck and the optimization is explicitly approved.

Security review and focused fuzzing are mandatory for unsafe hot-path code.

## 37. Benchmark Layers

Use three benchmark levels.

### 37.1 Microbenchmarks

Measure isolated operations such as:

```text
percent decode
native envelope decode
body capture / replay
header and cookie handling
URL classification
decision mapping
```

Useful for identifying local bottlenecks.

Not sufficient for architectural decisions alone.

### 37.2 Pipeline benchmarks

Measure realistic in-process flows:

```text
configured Caddy request
→ body / protocol handling
→ native-response decode
→ decision enforcement
→ next handler or terminal response
```

These should drive most implementation decisions.

### 37.3 End-to-end benchmarks

Measure:

```text
client
→ bundled Caddy with in-process AppSec handler
→ real native AppSec exchange
→ original Caddy content handler or terminal denial/challenge
```

These validate real product performance.

Do not use microbenchmarks to claim end-to-end performance.

Compare all of these controls using matching upstream Caddy versions, toolchains,
build flags, hardware, content, inspection configuration and connection behavior:

1. Upstream Caddy without custom modules.
2. The bundle with custom modules absent from the request chain.
3. The custom handler's body/protocol overhead control, explicitly labelled
   as synthetic control traffic rather than protected traffic.
4. Real WAF-only, Bot-only and combined inspection.
5. First challenge, valid-cookie traffic and excluded paths, including the
   configured both-policies-off path.

An external-proxy comparison may show the effect of removing a hop but cannot
be the only reference. Never compare unequal protection work and call the
difference an optimization. Synthetic inspection is not actual WAF/Bot capacity.

## 38. Benchmark Inputs

Benchmarks must contain more than ideal valid input.

Include:

- small common requests;
- representative normal requests;
- large allowed requests;
- malicious examples;
- malformed inputs;
- deeply nested inputs;
- high-field-count inputs;
- worst known parser cases;
- encoded/compressed variants;
- concurrent requests.

Security products must benchmark hostile paths as first-class workloads.

Cover application GETs, small and large POSTs, representative uploads and static
files. Exercise concurrency 1 and representative concurrent loads, HTTP/1.1 and
HTTP/2, relevant TLS behavior and supported upgrades/streaming. Handler support
requires integration evidence for the actual path, including file serving,
reverse proxy or FastCGI where claimed. Preserve streaming/upgrades outside
inspected scopes; do not claim inspection of WebSocket frames or unbounded
streaming bodies without proof.

## 39. Benchmark Reproducibility

Record:

- hardware;
- operating system;
- CPU;
- pinned Go toolchain;
- build flags and environment, including CGO and CPU target settings;
- upstream Caddy version and complete compiled-in module set;
- distribution version and source commit;
- dependency versions;
- corpus revision;
- command;
- concurrency;
- input size distribution.

Use repeated runs with balanced ordering and adequate warmup. Record duration,
errors, TLS/protocol and connection-reuse behavior, engine configuration and
load-generator placement. Disclose shared-host interference. Retain raw
measurements as CI/test artifacts, outside the task ledger; record durable
baseline definitions where future comparisons need them.

Do not compare numbers from materially different environments as though they were equivalent.

## 40. Build Profile

Benchmark optimized builds.

Do not use debug-build performance to choose production libraries or architecture.

Use the repository's intended release build flags and pinned toolchain.

If Go compiler/linker flags, PGO, CGO, CPU target settings or other build inputs
change for performance, measure their actual effect and document deployment
implications. Prefer CGO-disabled builds when the reviewed module set supports
them; new platform/runtime requirements need explicit support review.

Normal development, dependency work, tests and builds run on Windows. Native
Linux acceptance executes Windows-built artifacts or cross-compiled test
executables on the supported target, initially proposed as Ubuntu 24.04 for
Linux/amd64. Windows/amd64 acceptance runs natively. Do not create a second
Linux development toolchain for convenience. Cross-builds and short CI smoke
runs do not establish target-platform runtime or performance acceptance.

## 41. CPU-Specific Optimization

Do not compile production binaries for the development machine's CPU unless deployment targets guarantee compatible instruction sets.

If using CPU-specific settings such as an elevated `GOAMD64` level for local
benchmarking, label the result as local-only unless the release support policy
guarantees compatible deployment hardware.

Portable release builds must remain portable across supported target systems.

## 42. Regression Budgets

Performance-sensitive changes should compare against a recorded baseline.

Do not define arbitrary universal performance numbers in code.

For a specific release or benchmark profile, define acceptable regression thresholds before approving the change.

At minimum examine:

- throughput;
- errors;
- CPU;
- p50 latency;
- p95 latency;
- p99 latency;
- memory, including retained idle memory after upload bursts;
- allocation count/bytes where available;
- hostile-input latency;
- queue behavior.

A statistically noisy small difference is not automatically a regression.

Material regression requires investigation.

Disabled-path behavior must be materially equivalent to the matching upstream
control within measured baseline variation. Establish numeric regression budgets
from stable measurements on controlled hardware before enforcing percentage
thresholds. No unexplained material regression ships. Missing native performance
evidence or a failed required gate leaves the release unpublished.

Acceptance applies to the exact release binary: record its identity/checksum,
and publish that accepted artifact rather than rebuilding a different executable
after acceptance. Keep distribution and upstream versions distinct in manifests.

## 43. Performance Evidence for New Dependencies

A performance-sensitive dependency proposal should state:

```text
Requirement:
Why existing implementation is insufficient:
Candidate:
Alternative considered:
Expected benefit:
Integration cost:
Allocation/copy implications:
Semantic limitations:
Security/resource limitations:
Benchmark used:
Measured result:
Decision:
```

This can be brief for obvious choices.

Do not require bureaucracy for trivial non-hot-path dependencies.

## 44. Performance Evidence for Refactors

Do not justify a refactor with:

```text
"this should be faster"
```

Provide evidence.

A performance-motivated refactor must identify:

- measured bottleneck;
- profiler evidence where applicable;
- baseline;
- change;
- resulting measurement;
- semantic equivalence verification.

## 45. Profiling

Use profiling when benchmark results show a real bottleneck.

Appropriate tools may include, depending on environment:

- sampling profilers;
- allocation profilers;
- flamegraphs;
- Windows Performance Recorder/Analyzer;
- Go CPU/heap/allocation profiles and platform-supported profiling tooling.

Do not select a profiler first and search for something to optimize.

Profile the measured workload.

## 46. Serialization Profiling

When serialization appears in a hot path, measure separately:

- encoding time;
- decoding time;
- allocation;
- bytes produced;
- copies;
- number of serialization passes.

Do not assume serialization overhead is negligible.

Likewise, do not assume it is dominant without measurement.

## 47. Allocation Profiling

Where memory/allocation is material, determine:

- allocation count;
- total allocated bytes;
- peak retained bytes;
- largest allocations;
- allocation source;
- lifetime of retained buffers.

Distinguish sampled RSS from allocation peaks and Go heap retention. Measure
post-burst idle memory as well as active upload peaks. Release memory and owned
transports on reload/shutdown without dropping active requests or leaking goroutines.

Optimization should target measured allocation hot spots rather than blindly
replacing strings with byte slices everywhere.

## 48. Security Before Speed

The following are not acceptable performance optimizations:

- skipping required native inspection;
- substituting local heuristics for the required native decision;
- truncating required input and returning `ALLOW`;
- ignoring duplicate values;
- dropping provenance required for evidence;
- silently treating read, decoding or native-protocol failure as safe;
- reducing context validation;
- replacing deterministic evidence with probabilistic shortcuts;
- disabling resource accounting.

Unauthorized allow-cache reuse, discarded native denials and challenge-status
shortcuts are also forbidden. A cache must not weaken scope, identity, profile,
policy independence or the native challenge/allow contract.

If an optimization changes security semantics, it is an architecture change, not a performance change.

## 49. Performance Under Attack

The bundle and its AppSec integration must remain controlled under malicious workloads.

Evaluate:

```text
normal traffic only
malicious traffic only
mixed normal + malicious traffic
sustained resource-pressure traffic
recovery after pressure ends
```

Measure legitimate traffic during attack pressure.

A system that protects itself by making all legitimate requests unusably slow has not met the performance requirement.

## 50. Recovery Requirements

After hostile load ends:

- queues must drain;
- permits must recover;
- memory must return toward normal operating levels;
- timed-out workers must not accumulate indefinitely;
- normal request latency must recover.

Test recovery explicitly.

Do not stop the benchmark immediately when attack traffic stops.

## 51. Capacity Accounting

Concurrency limits must correspond to real resource ownership.

Do not release worker permits, memory reservations, or parser capacity when the caller times out if the computation is still executing.

Logical request completion and physical resource release are separate events.

## 52. Performance and Incomplete Inspection

Resource limits may legitimately prevent inspection from completing.

Do not invent an `INDETERMINATE` wire decision or automatically increase limits
to hide incomplete inspection. Apply the explicitly defined and tested native
timeout/failure policy; incomplete inspection is never an explicit native allow.

Track why analysis becomes incomplete:

```text
queue saturation
source size
protocol decode / work limit
memory budget
timeout
unsupported input
DNS timeout
```

Performance tuning must distinguish insufficient capacity from intentionally enforced security bounds.

## 53. Avoid Accidental Quadratic Behavior

Review attacker-controlled loops for hidden quadratic or worse complexity.

Common risks:

- repeated string concatenation;
- repeated scans from the beginning of input;
- nested lookup loops;
- repeated parsing of growing prefixes;
- repeated provenance-range merging;
- repeated tree traversal for each finding;
- duplicate deduplication with naive all-pairs comparison.

Prefer bounded linear or near-linear operations where practical.

If worse complexity is unavoidable, bound the controlling input dimension.

## 54. Finding Deduplication

Do not implement finding deduplication using unbounded all-pairs comparison.

Use bounded deterministic strategies appropriate to the finding limit.

Performance must not cause stronger evidence to be discarded.

## 55. Source Spans and Provenance

Prefer referencing source ranges rather than copying source substrings.

Materialize evidence text only when required for an API response and keep it bounded.

Do not store multiple copies of the same attacker-controlled substring merely for explanation.

## 56. Error Messages

Keep attacker-triggered error construction cheap.

Prefer stable codes plus bounded metadata.

Do not generate huge `fmt.Sprintf` strings containing complete request bodies
or decoded protocol structures. Exclude credentials and challenge secrets.

## 57. Feature Development Workflow

For performance-sensitive implementation:

1. establish required semantics;
2. identify likely hot path;
3. inspect existing representation and copy/allocation boundaries;
4. compare candidate libraries/designs when the choice is material;
5. implement the simplest correct version;
6. benchmark the relevant path;
7. profile only if a material bottleneck remains;
8. optimize the measured bottleneck;
9. rerun correctness/security tests;
10. rerun performance tests;
11. report measurements and retain raw evidence outside the repository/task
    ledger; mark existing ledger acceptance items complete only after verification.

Do not begin at step 8.

## 58. Agent Requirements

AI agents must not make performance claims without evidence.

Agents must not state:

```text
"zero-copy"
"SIMD accelerated"
"high performance"
"low allocation"
"faster"
"optimized"
```

unless the implementation path supports the claim and relevant evidence exists.

Before selecting a performance-sensitive library, the agent must inspect:

- how it will actually be called;
- what representation it returns;
- whether the module then converts that representation;
- whether it reduces or increases copies;
- whether it reduces or increases allocations;
- whether required semantics force a slower path;
- whether its fast path is enabled in the actual build.

Agents must not add a high-performance dependency and leave the existing slow conversion/serialization path unchanged while claiming the task is optimized.

## 59. Performance Review Questions

For every material hot-path change, ask:

1. How many times are these bytes copied?
2. How many times are they parsed?
3. How many representations are created?
4. Is anything serialized unnecessarily?
5. Are large strings cloned?
6. Are allocations proportional to attacker-controlled input?
7. Are loops bounded?
8. Can malformed input trigger more work than valid input?
9. Is the chosen library's fast path actually used?
10. Does parsing/enforcement preserve the native Caddy/AppSec semantics required?
11. Is concurrency bounded?
12. Are timed-out computations still consuming resources?
13. Is the optimization visible in pipeline or end-to-end measurement?
14. Did the optimization change security behavior?

## 60. Performance Change Checklist

Before handoff of a performance-sensitive slice:

- [ ] actual hot path was identified;
- [ ] no unnecessary serialization layer was added;
- [ ] material copies are understood;
- [ ] material allocations are understood;
- [ ] attacker-controlled loops are bounded;
- [ ] parser attempts are bounded;
- [ ] queues are bounded;
- [ ] concurrency is bounded;
- [ ] resource ownership survives caller timeout correctly;
- [ ] library fast paths used by the implementation were verified;
- [ ] SIMD claims, if any, were verified in the target build;
- [ ] microbenchmarks were not used as a substitute for pipeline evidence;
- [ ] representative benign input was measured;
- [ ] hostile/malformed input was measured where relevant;
- [ ] memory was evaluated, not only CPU;
- [ ] security semantics are unchanged unless the task explicitly changes them;
- [ ] focused correctness tests pass;
- [ ] benchmark environment and commands are recorded;
- [ ] any claimed improvement is supported by measured evidence.
- [ ] upstream, inactive bundle and synthetic overhead controls are distinguished;
- [ ] real WAF-only, Bot-only, combined and challenge/cookie paths are measured;
- [ ] configured disabled and excluded paths preserve required behavior;
- [ ] protocol, TLS, concurrency and connection settings are comparable;
- [ ] retained idle memory and recovery after upload/hostile bursts are measured;
- [ ] published-target evidence identifies the exact accepted binary;
- [ ] numeric release budgets derive from stable baseline variation.

## 61. Preferred Performance Design

When two implementations are semantically equivalent, prefer the one that:

1. performs fewer full-data transformations;
2. performs fewer large allocations;
3. performs fewer large copies;
4. creates fewer intermediate representations;
5. reuses parser output;
6. keeps data typed in-process;
7. uses bounded work and memory;
8. has simpler ownership and lifecycle;
9. is easier to benchmark and reason about;
10. provides better measured end-to-end behavior without sacrificing security.

Do not choose a more complex solution for a theoretical performance advantage.

The desired AppSec module hot path should be:

```text
configured Caddy request
    ↓
minimum necessary body capture / wire encoding
    ↓
native AppSec inspection / challenge exchange
    ↓
single required response decode
    ↓
explicit native decision enforcement
    ↓
direct original-handler continuation after allow, or terminal response
```

not:

```text
input
    ↓
copy
    ↓
normalize everything
    ↓
serialize
    ↓
deserialize
    ↓
convert
    ↓
reparse
    ↓
clone
    ↓
generic intermediate model
    ↓
another conversion
    ↓
enforcement
```

Performance engineering in this distribution means eliminating unnecessary
work while preserving native Caddy behavior, exact AppSec security semantics
and explicit resource bounds.
