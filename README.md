# TrueOps AppSec

A standalone Caddy distribution with reviewed modules compiled into one binary,
bringing CrowdSec application security directly into Caddy's request pipeline.

TrueOps AppSec is for operators who want Caddy's web server, reverse proxy and
automatic HTTPS with integrated WAF and Bot Detection, without assembling a
custom build on every deployment machine. It runs independently of the TrueOps
management application.

## Application security inside Caddy

The AppSec module connects Caddy to a separately operated CrowdSec AppSec engine.
Protection is configured per virtual host or path using native Caddy
configuration, with independent WAF and Bot Detection policies.

- **WAF protection:** Submit protected requests to the configured AppSec engine
  and enforce its native decisions.
- **Bot Detection:** Handle native browser challenges, cookies and challenge
  exchanges while retaining WAF protection where configured.
- **Scoped policies:** Select protection for each host or path, using trusted
  configuration and Caddy's trusted client identity.
- **Direct continuation:** After explicit allow, continue to the original Caddy
  content handler in the same process.

```text
Client → Caddy routing → AppSec module → CrowdSec AppSec decision
                                         ├─ Allow → original Caddy handler
                                         └─ Deny / challenge → browser response
```

Content stays in Caddy's handler chain. The integration avoids an additional
content proxy or an internal HTTP round trip. Unprotected hosts and paths keep
the ordinary Caddy request path without inspection calls or body capture.

## Per-host WAF rules

Select pinned virtual-patching and generic-attack groups or individual rules
with native CrowdSec profiles. Rule-specific host/path exceptions remove only
the intended rules before evaluation; other enabled rules still protect the
request. See the [configuration contract and examples](guides/virtual-host-waf-policies.md).

## Performance with security intact

The design prioritizes minimal request-path work, connection reuse, bounded
memory and preservation of request bodies and streaming behavior. WAF and Bot
Detection remain independent: passing a bot challenge does not bypass WAF.

Performance is evaluated against upstream Caddy and real protection workloads,
including throughput, latency, CPU, allocations and memory recovery after bursts.
Engine failures deny requests by default. Operators can explicitly select a
scoped failure passthrough; this is not a successful inspection or native allow.
Malformed responses and native bans remain terminal.

## CAPTCHA remediation

Classic `action: captcha` can use **Turnstile**, **hCaptcha** or **reCAPTCHA v2**.
Enable it inside the `trueops_appsec` block with your provider's keys:

```caddyfile
captcha_provider turnstile
captcha_site_key {$CAPTCHA_SITE_KEY}
captcha_secret_key {$CAPTCHA_SECRET_KEY}
captcha_cookie_secret {$CAPTCHA_COOKIE_SECRET}
captcha_ttl 1h
captcha_path /trueops-internal/captcha/submit
```

In JSON, these are the `provider`, `site_key`, `secret_key`, `cookie_secret`,
`ttl` and `path` fields of the handler's `captcha` object. Other provider names
are `hcaptcha` and `recaptcha`. The signing secret must contain at least 32
cryptographically random bytes; keep it stable across reloads and separate for
different trust domains. Rotating it invalidates existing CAPTCHA grants.

The module renders the provider widget, verifies its proof server-side and issues
an expiring, signed, host-only cookie bound to trusted client IP, host, AppSec
endpoint and credentials. Every later request is still inspected by CrowdSec:
a valid grant satisfies only `captcha`, and never overrides `ban`, native Bot
`challenge`, malformed responses or engine failure policy. Native Bot Detection
uses its own engine-issued cookies and is unchanged.

`captcha_ttl` defaults to one hour; `captcha_path` defaults to the path above.
Route that endpoint through the same handler as the protected requests. For
several profiles on one host, use distinct callback paths inside their protected
routes. Provider scripts and verification endpoints require outbound HTTPS.
Do not append a conflicting site-wide CSP to CAPTCHA responses.

Successful submissions return a **303** to the original local URL. Original
POST/upload requests are never replayed automatically; retry them after solving.
The callback never reaches the application. Missing configuration, invalid or
expired proofs and provider failures deny access, including when
`failure_action passthrough` is enabled. No provider credentials, user bodies
or proof tokens are logged. Without a `captcha` configuration, remediation
remains a plain 403.

Provider contracts: [Turnstile](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/),
[hCaptcha](https://docs.hcaptcha.com/#server),
[reCAPTCHA](https://developers.google.com/recaptcha/docs/verify).

## AppSec failure policy

Set `failure_action` inside a `trueops_appsec` Caddyfile block or as the same
field in its JSON handler configuration:

```caddyfile
failure_action deny
```

`deny` is the default, including when omitted, and returns HTTP 503 for engine
transport failures or unexpected statuses (including 401 and 500).
Explicit `failure_action passthrough` continues directly to the original handler
with the complete captured request when those failures occur. This is the scoped
equivalent of CrowdSec's
[`APPSEC_FAILURE_ACTION`](https://docs.crowdsec.net/u/bouncers/nginx/#appsec_failure_action).
It trades inspection availability for application availability and must be an
operator's deliberate per-route choice. No global environment override is read.

Native denials, CAPTCHA/challenge responses, malformed or oversized envelopes,
incomplete request bodies, cancellation, missing trusted identity and local
resource limits cannot be bypassed by this setting. Internal challenge paths
never continue to the origin. Debug diagnostics distinguish failure passthrough
from native allow; nothing is cached and no inspection is retried.

## Dynamic upstream pools

The bundled pool module consumes unchanged upstream Caddy. Pool updates replace
an upstream generation without reloading Caddy's HTTP configuration, listeners
or security handlers. Applied updates are saved through Caddy's native storage
before success is acknowledged. Ordinary application requests perform no
storage access.

Configure the pool app, lease middleware and native reverse proxy together:

```json
{
  "admin": {"listen": "127.0.0.1:2019"},
  "apps": {
    "trueops_pools": {
      "state_id": "edge-a",
      "pools": {
        "example": {"revision": 1, "targets": ["127.0.0.1:9001", "127.0.0.1:9002"]}
      }
    },
    "http": {
      "servers": {
        "example": {
          "listen": ["127.0.0.1:8080"],
          "routes": [{"handle": [
            {"handler": "trueops_pool", "pool": "example"},
            {"handler": "reverse_proxy", "dynamic_upstreams": {
              "source": "trueops_pool", "pool": "example"
            }}
          ]}]
        }
      }
    }
  }
}
```

Place existing security handlers before `trueops_pool`. The pool source and
middleware must reference the same configured pool. Missing or mismatched
leases yield no eligible upstreams, including when static upstreams were
accidentally configured. Public request headers cannot select the pool.
Configuration uses Caddy JSON. The module does not register a Caddyfile directive.

The following routes extend the existing Caddy Admin endpoint; they do not
create another listener. Keep that endpoint private and retain its native
trust and permission controls.

- `GET /upstream-pools/example`: current instance, revision, targets, active
  request count and older generations with requests still executing.
- `PUT /upstream-pools/example`: complete replacement using this shape:

  ```json
  {
    "expected_instance": "instance returned by GET",
    "expected_revision": 1,
    "revision": 2,
    "targets": ["127.0.0.1:9003", "127.0.0.1:9004"]
  }
  ```

The revision must increase by one. An exact duplicate of the latest update is
idempotent; a conflicting revision or pool instance returns HTTP 409.
Targets are distinct literal single TCP or Unix socket addresses, not public
placeholders, URLs or port ranges. Control messages are bounded to 1 MiB;
this does not impose a limit on application bodies. Invalid/unknown JSON fields
or multiple JSON documents return HTTP 400; oversized updates return HTTP 413.
Unsupported methods return HTTP 405. Reads queue no work and return `no-store`.

Each admitted request retains its generation through native proxy retries.
Requests admitted after replacement select the new generation; earlier requests
may finish on the old one. Acquisition and replacement share one short critical
section, with no lock held during request processing or storage I/O. Cancellation alone does
not release a lease while its downstream handler is still executing. Completed
retired generations are removed rather than retained as history.

The caller must verify target readiness before replacement. Dynamic upstreams
do not receive Caddy's built-in active health checks. The module neither starts
nor stops application processes. A successful PUT confirms pool application,
not old-target drain completion: observe `draining` before retiring old targets.
A wait timeout must not be interpreted as permission to kill active work.

`state_id` identifies this Caddy instance's durable pool namespace. Keep it
stable across restarts and unique to this independently controlled gateway;
do not share it between simultaneously running Caddy processes using shared
storage. Keep the configured storage backend/location bound to that namespace.
Changing the namespace deliberately creates a different set of pools.

The configured revisions/targets are immutable bootstrap intent for that
namespace. Subsequent changes use the pool API. A mismatched bootstrap fails
configuration loading rather than silently replacing applied state. Caddy's
`/config/` remains bootstrap configuration; `/upstream-pools/` is runtime evidence.
Removing a pool from configuration does not delete its checkpoint. Do not reuse
its identity for an unrelated application; use a new pool ID or namespace.

The module stores one versioned checkpoint per updated pool under
`trueops_pools/` in Caddy's configured storage, using hashed namespace/pool keys.
Caddy's native storage lock serializes checkpoint comparisons and writes.
An ordinary reload with unchanged namespace/bootstrap retains the live pool,
its instance and admitted-generation counters through Caddy's native usage pool.
A process restart restores the saved applied targets under a new instance.
Old-process mutations are rejected; read the current instance before updating.

Storage errors return HTTP 503 and leave the current serving generation unchanged.
A failed/lost response can still have committed storage effects: inspect runtime
state or deliberately retry the exact reviewed update, never retire targets from
an HTTP acknowledgment alone. An exact retry can confirm an already-stored plan.
Corrupt/incompatible saved state fails startup instead of falling back to old
targets. Preserve and back up Caddy's data/storage: an absent checkpoint on a new
process is indistinguishable from first use and initializes the configured
bootstrap. This is not a guarantee against lost storage or physical power loss.

Native file storage is covered by restart/failure acceptance. Custom backends
must satisfy Caddy's storage consistency, locking and cancellation contract and
need their own native acceptance. Full configuration changes and deployment
operations remain the caller's coordinated responsibility. This module does not
repair Caddy's upstream reload lifecycle bug, promise atomicity across gateways,
or establish PHP/FastCGI, WebSocket or complete application deployment acceptance.

The self-contained candidate test uses disposable loopback origins, private
ephemeral certificates and verified TLS. On Windows, set `TRUEOPS_POOL_CADDY`
to the candidate path and run `go test -v ./tests/pool`. Without a candidate,
these tests skip. For native Linux testing, cross-build the candidate and test
executable on Windows, then execute those exact artifacts on the target.
The performance test compares native static upstreams and the pool path in the
same candidate; it is a short shared-host diagnostic, not a capacity budget.
Enable the `trueops_pools` logger at DEBUG for bounded update metadata, without
bodies or credentials.

The separate acceptance bundle contains `pool-origin` and
`run-pool-acceptance.sh`; production release archives contain neither fixture.
On each authorized test Machine, extract into a new
private temporary directory and run `sh run-pool-acceptance.sh origin PRIVATE_IP
NODE_ID`. This starts only disposable V1/V2 fixtures on that existing private
address, ports 52991/52992, and expires after 30 minutes. Those ports must be free;
no installed service is changed or restarted. Fixture control endpoints are
test-only and must remain on the private test network.

Once every origin is running, execute `sh run-pool-acceptance.sh gateway IP1 IP2
IP3` on the test gateway, supplying the actual private addresses. The argument
list supports any target count of at least two. The runner uses an isolated
candidate Caddy on ephemeral loopback ports and sends requests through it to
the remote fixtures. It checks a held remote request, pool cutovers and bodies,
then records per-origin node/version/request counts in `report.log`. It also
compares static and dynamic upstream paths against the same remote origins.
External fixture tests are gated by `TRUEOPS_APPSEC_TEST_LOCAL=1` outside CI;
the explicit gateway command sets that opt-in.

This exercises the private cross-Machine backend path. Client TLS load is
generated on the gateway itself; it is not an Internet-client or real runtime
deployment acceptance claim. Fixture readiness preflight is not production
health checking, and fixture retirement controls are not application lifecycle
operations. A failed test preserves its report and never modifies live Caddy.

## One binary, a reviewed module set

The distribution model is a versioned binary download with a fixed, reviewed
module set. Deployment machines do not need Go, `xcaddy` or a source checkout.
Native Caddy commands and configuration remain the operator interface.

Distribution versions identify the complete bundle separately from the upstream
Caddy version. Release packages carry a build manifest, SHA-256 checksums,
provenance and required license notices so operators can identify and verify
the executable and its included modules.

## License

Apache License 2.0. See [LICENSE](LICENSE). Caddy and included third-party modules
retain their respective licenses and attribution requirements.
