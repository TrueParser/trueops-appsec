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

## Performance with security intact

The design prioritizes minimal request-path work, connection reuse, bounded
memory and preservation of request bodies and streaming behavior. WAF and Bot
Detection remain independent: passing a bot challenge does not bypass WAF.

Performance is evaluated against upstream Caddy and real protection workloads,
including throughput, latency, CPU, allocations and memory recovery after bursts.
Engine failures deny requests by default. Operators can explicitly select a
scoped failure passthrough; this is not a successful inspection or native allow.
Malformed responses and native denials remain terminal.

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
