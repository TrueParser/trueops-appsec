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
Inspection failures and malformed responses must never be treated as permission
to serve a protected request.

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
