# TrueOps AppSec Releases

The [release workflow](../.github/workflows/release.yml) builds Linux amd64
(64-bit Intel and AMD) and arm64 archives when a maintainer pushes a `v*` tag.
Manual dispatch also works when an existing `v*` tag is selected as the ref;
dispatching from a branch does not publish a release.

## Build and release invariants

- **Independent ownership:** Keep distribution source, tests, configuration
  examples, tooling and automation self-contained in this independent repository.
  No imports, file references, credentials or runtime callbacks into another
  management application or repository.
- **Upstream-owned server:** Consume Caddy through an exact reviewed Go module
  pin and retain standard modules through a thin launcher. Do not fork, clone,
  vendor, copy or patch Caddy's source tree. Use supported module registration
  and lifecycle interfaces.
- **Reviewed build inputs:** Commit exact dependency pins and checksums and
  select a reviewed Go toolchain. No floating branches or `@latest` in release
  builds. Explicit imports define the reviewed module set; do not add a runtime
  installer, generic registry, competing updater or deployment-host compilation.
  Keep distribution versions separate from upstream Caddy's version.
- **Verified artifacts:** Native runtime, real AppSec/browser and controlled
  performance acceptance must identify the exact binaries being published.
  Cross-compilation, mocks and smoke tests alone are insufficient. Packages
  preserve licenses/notices and carry manifests, SHA-256 checksums and provenance.
  Missing required evidence leaves acceptance/release pending. Preserve published
  assets and tags; corrections require a new reviewed distribution release.

Functional behavior and performance acceptance remain defined by the
[product invariants](product-invariants.md) and
[performance guide](performance-requirement.md).

## Repository prerequisites

- The tagged source must include the reviewed `go.mod`, `go.sum`,
  `cmd/caddy/main.go`, root `LICENSE` and complete `THIRD_PARTY_NOTICES`.
  The workflow reports a missing input as an error. It does not manufacture a
  launcher, choose upstream versions or generate placeholder license notices.
- `go.mod` must select a reviewed exact Go patch version. Dependency versions
  and checksums must be committed. Setup reads the module's toolchain selection;
  automatic Go toolchain switching and dependency-file changes are disabled.
- Configure a GitHub environment named `release` with required maintainer
  reviewers. Publication fails if required reviewers are missing. Reviewers
  must withhold approval until the exact candidate archives have the native,
  real AppSec/browser and controlled performance evidence required by the
  [proposal](proposals/bundled-caddy-binary.md) and
  [performance guide](performance-requirement.md).
- Enable GitHub Actions with access to Windows 2025, Ubuntu 24.04 x64 and
  Ubuntu 24.04 ARM64 runners, release writes and artifact attestations. The
  workflow uses its repository-scoped `GITHUB_TOKEN`; no NuGet/package token
  or personal access token is required.

## Verification and candidates

Windows performs formatting checks, dependency verification, `go test -v ./...`,
`go vet ./...`, a host build and CGO-disabled Linux cross-builds. It records
source commit, distribution/upstream versions, toolchain, module versions,
target, build flags and binary SHA-256 in each candidate manifest.

Ubuntu runners execute the matching Windows-built binary, verify its checksum,
run native Caddy diagnostics/configuration validation and serve a loopback HTTP
request. These jobs do not install or use a Go toolchain for development.
They package the same executable bytes with executable permissions, manifest,
build information and license notices.

Workflow artifacts are retained for 14 days:

- `linux-candidates`: binaries and metadata produced on Windows.
- `release-linux-amd64` and `release-linux-arm64`: native-checked archives and
  per-target manifests for review and additional acceptance.

Download those artifacts from the same workflow run before release approval.
Exercise those exact binaries for required acceptance; do not rebuild them.
The HTTP smoke test is not proof of AppSec/challenge/browser correctness or
target-platform capacity. Local acceptance evidence stays outside the task
ledger and must identify the source commit and candidate checksums.

## Local-dependency tests

GitHub jobs set `TRUEOPS_APPSEC_TEST_LOCAL=0` and `CI=true`. Tests that require a
maintainer-local engine, private endpoint, credential, file, tunnel or network
must skip before any setup or external side effect unless the flag is exactly
`1` and CI is not enabled. Follow the gate in [AGENTS.md](../AGENTS.md).
Ordinary unit tests and isolated fixtures remain enabled.

For an authorized local run on Windows, enable the flag only for the selected
test process and restore its prior value afterwards:

```powershell
$previousLocalTests = $env:TRUEOPS_APPSEC_TEST_LOCAL
try {
    $env:TRUEOPS_APPSEC_TEST_LOCAL = '1'
    go test -v ./...
} finally {
    $env:TRUEOPS_APPSEC_TEST_LOCAL = $previousLocalTests
}
```

Configure the affected test's documented credentials, endpoints and bounded
diagnostic tracing first. Use isolated resources or serial execution when tests
share mutable infrastructure. Never use a production engine or other live state
without explicit authorization. Skipped tests do not count as passed acceptance.

## Publishing and recovery

After both native jobs pass and release reviewers approve the exact candidates,
the publication job assembles `manifest.json` and `SHA256SUMS`, attests the release
assets, creates a draft GitHub Release, downloads the uploaded assets to verify
their SHA-256 values and then publishes the draft. Tags containing a hyphen are
marked as prereleases. Tag names must be safe archive-name components, starting
with `v` and containing only letters, digits, dots, plus signs, underscores or
hyphens. Tags and commits are created/pushed by the maintainer, not by the workflow.

Release notes include GitHub's generated PR/contributor summary and full changelog
link, preceded by the binary download information. The starting tag is the most
recently published stable release among the latest 100 stable releases, excluding
the current tag; drafts and prereleases are
excluded. The ending tag is the release being built, not the latest branch commit.
With no previous stable release, GitHub selects the default starting point.

For a tag such as `v0.1.0`, downloads include:

```text
trueops-appsec_v0.1.0_linux_amd64.tar.gz
trueops-appsec_v0.1.0_linux_arm64.tar.gz
manifest-linux-amd64.json
manifest-linux-arm64.json
manifest.json
SHA256SUMS
```

Binary contents are not rebuilt after acceptance. Existing releases/assets are
not overwritten, and the workflow never moves a tag. A failed upload or asset
verification leaves a draft; inspect it before taking any recovery action.
Rerunning against an existing release fails rather than replacing its contents.
Published corrections require a new reviewed tag and distribution release.
