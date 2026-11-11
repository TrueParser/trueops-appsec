# Per-virtual-host WAF rule policies

TrueOps AppSec uses native CrowdSec configuration for rule selection and
exceptions. No additional Caddy module settings are needed. Caddy selects the
reviewed inspection endpoint; CrowdSec loads and evaluates the selected rules.
The [complete examples](../modules/appsec/profiles/virtual-hosts/) run in **one
CrowdSec process**, with datasources for distinct policies and Bot trust domains.
`site-a` and `site-b` are illustrative configuration names, not module constants
or reserved sites. Consumers supply their own names, hosts, selections and endpoint
bindings; nothing automatically discovers or installs these example files.

## Versioned catalog and selection

[catalog.json](../modules/appsec/profiles/virtual-hosts/catalog.json) identifies
catalog `trueops-hub-04bf592e846e-v1`. Its authoritative inventory is
[pins.json](../modules/appsec/profiles/pins.json): exact Hub revision, individual
rule names, versions and SHA-256 hashes. The catalog has two groups:

| Group | Native `inband_rules` selection | Pinned members |
| --- | --- | --- |
| Virtual patching | `crowdsecurity/vpatch-*` | 227 |
| Generic attacks | `crowdsecurity/generic-*` | 3 |

Install **only the reviewed manifest assets**, verifying each checksum before
loading. Wildcards select installed rules; they do not fetch or pin anything.
Extra unreviewed files can expand a wildcard's meaning. Catalog upgrades require
an explicit manifest revision, review and acceptance, without `hub upgrade`,
floating collections or `@latest` in the deployment flow.

The consumer supplies native `appsec-configs/*.yaml` files:

```yaml
name: operator/my-waf-policy
default_remediation: ban
inband_rules:
  - crowdsecurity/base-config
  - crowdsecurity/generic-*
  - crowdsecurity/vpatch-git-config
```

`base-config` supplies body processors and stays enabled. Group selectors and
individual names may be combined; resolve every selection against the pinned
inventory and reject unknown names or empty group selections during deployment
review. Selecting a rule does not prove it detects every variant of an attack.
Do not edit arbitrary SecLang to configure these policies.

The examples give Site A both groups and Site B the generic group plus the
individual Git-config patch. Consequently `.env` access blocks on A but is not
selected on B; WordPress-PHP and Git-config attacks still block on B. Configs
loaded by a datasource **merge**: adding `appsec-default` would re-enable the
omitted virtual patches. Do not load it alongside these explicit selections.

## Rule-specific path exceptions

Use native **in-band `pre_eval` removal**, before evaluation:

```yaml
name: operator/my-exceptions
inband:
  pre_eval:
    - filter: req.Host matches '(?i)^site-a[.]test(:[0-9]+)?$' && req.URL.Path == '/legacy/.env'
      apply:
        - RemoveInBandRuleByName("crowdsecurity/vpatch-env-access")
```

This removes the named rule for that transaction. Other rules continue
evaluating and may block the same request. Never substitute `SetRemediation`
with `allow`, `SkipProcessing`, a global allowlist, or a Caddy path bypass for a
rule-specific exception. Keep exceptions in the same WAF policy for WAF-only
and combined datasources; never apply WAF exceptions as Bot exclusions.

The example matches the parsed URL path exactly, ignoring the query. Its host
match is case-insensitive, includes an optional numeric port, and excludes other
hosts and subdomains. Encoded paths follow the pinned engine's URL parsing;
acceptance covers the actual application/proxy path interpretation. Review
additional path patterns explicitly rather than broadening an exception to a
prefix unintentionally. Rules absent from a policy need no removal hook.

## Consumer configuration contract

| Owner | Required input and behavior |
| --- | --- |
| Rule assets | Versioned inventory and verified files from `pins.json`; no implicit updates. |
| CrowdSec policy | Native `inband_rules` and host/path-bound removal hooks. Keep oversize action `drop`, complete-body limits and `body_read_timeout: "0s"`. |
| CrowdSec datasource | Bind a reviewed policy/mode to a private endpoint. Load the same WAF rules/exceptions on its WAF-only and combined variants; Bot-only loads no WAF rules. |
| Caddy routing | Fixed `trueops_appsec` endpoint, key and WAF/Bot flags per trusted host/path route. Never build the endpoint/profile from public headers. |
| Bot trust domain | Separate persistent random `challenge.master_secret` per independent site; share it only between that site's Bot and combined datasources. Protect this private native config. |
| Credentials/network | Authenticate inspection; bind listeners to loopback or an authenticated private network, using verified TLS across untrusted links. Keep native admin APIs private. |
| Firewall isolation | Preserve the dedicated AppSec LAPI's decision-free profile; site detections must not become global IP/firewall decisions. |

The module replaces all supplied `X-Crowdsec-Appsec-*` headers with its own
metadata, including Caddy's trusted client identity and the original Host/URI.
Public `Forwarded`, profile or policy headers cannot select an endpoint. Host
selection itself follows Caddy's virtual hosting contract: sending Site B's
actual Host addresses Site B, so its original handler/upstream must also be B.
Do not send several security domains to a common privileged application while
assuming HTTP Host is an authenticated user identity.

Use the [Caddyfile](../modules/appsec/profiles/virtual-hosts/Caddyfile) and
[acquisition configuration](../modules/appsec/profiles/virtual-hosts/acquis.yaml)
together. Supply `APPSEC_API_KEY` and private `operator/site-a-challenge` and
`operator/site-b-challenge` configs separately. Replace example domains, ports,
budgets and original handlers with reviewed deployment values. This directory
does not install or change an existing service.

An entirely excluded/off route performs no inspection or body capture. A
rule-specific exception remains protected and **does** inspect the request.
A Bot exclusion selects WAF-only; a WAF exclusion selects Bot-only. Reserve
the host's native challenge route before application exclusions. Combined mode
uses one handler, one complete body capture and one native inspection, rather
than chaining WAF and Bot handlers. Native challenge/CAPTCHA handling, failure
actions, credentials and Caddy resource ownership retain their existing contract.

Datasources are configuration/runtime boundaries, not per-Site engine processes.
Hosts with identical rules and challenge trust may share one. Distinct runtime
policies load additional Coraza instances, so memory and startup cost grow with
policy count, rules, runners and challenge trust domains. Do not promise constant
memory per additional site. Host-filtered transaction exceptions can share a
datasource, as the integration's Site A/Site C case demonstrates.

## Verification

`go test -v ./tests/integration` checks the catalog, native configuration shape
and Caddyfile adaptation on Windows and CI. The real-engine suite is opt-in,
skips before setup unless explicitly enabled, and always skips under `CI=true`.
It uses pinned Linux/amd64 engine/CLI artifacts and verifies every asset hash.
It starts only private owned processes and listeners, with generated credentials,
its own database and Caddy storage; it never manages host services or firewall.

Build the executable and test binary on Windows:

```powershell
$env:GOFLAGS = '-mod=readonly'
$env:CGO_ENABLED = '0'
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
go build -trimpath -o ./out/policy-target/caddy ./cmd/caddy
go test -c -o ./out/policy-target/policy.test ./tests/integration
```

On the authorized Linux target, execute those bytes (no target Go installation):

```sh
env CI=false TRUEOPS_APPSEC_TEST_LOCAL=1 \
  TRUEOPS_APPSEC_TEST_REPO=/absolute/path/to/reviewed/configuration \
  TRUEOPS_APPSEC_TEST_BUNDLE=/absolute/path/to/verified/benchmark-bundle \
  TRUEOPS_APPSEC_TEST_CADDY=/absolute/path/to/policy-target/caddy \
  /absolute/path/to/policy-target/policy.test \
  -test.v '-test.run=^TestNativeVirtualHostPolicies$' -test.timeout=5m
```

The bundle supplies only the pinned engine/CLI and verified Hub assets; its
older Caddy binary is not used. Build it with the existing
[benchmark packaging workflow](../benchmarks/README.md) if a verified bundle is
not available. WSL target execution uses Windows-built artifacts only; no Go,
dependency management or Linux development setup is needed there.

The suite proves independent selection, other-rule blocking, host/path and
concurrent isolation, forged metadata, all modes, native Bot-cookie WAF
enforcement, complete-body replay, one combined inspection, reload/restart and
closed failures. It records balanced real-engine loopback request timings,
per-request p50/p95/p99, CPU, aggregate process RSS, Caddy validation/reload cost and engine startup/restart
cost in `results.json`. It retains a private evidence directory and prints its
path. Generated configs contain secrets: publish only reviewed result summaries.

For deterministic cookie tests, the isolated fixture uses native
`GrantChallengeCookie` on one test-only path, after WAF evaluation. This proves
WAF enforcement with an engine-issued valid Bot exemption cookie; it does not
prove browser JavaScript/PoW completion. That minting hook is absent from every
operator example. Timings on a shared development host are acceptance overhead
measurements, not production WAF capacity or VPS results.

Pinned implementation evidence: request metadata reconstruction in
[request.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/request.go),
request-bound helper closures in
[waf_helpers.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/waf_helpers.go),
transaction-local removals in
[appsec.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec.go),
and pre-evaluation ordering in
[appsec_runner.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/acquisition/modules/appsec/appsec_runner.go).
See also the official [rule override](https://docs.crowdsec.net/docs/appsec/configuration_rule_management/)
and [hook](https://docs.crowdsec.net/docs/appsec/hooks/) contracts.
