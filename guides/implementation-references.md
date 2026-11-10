# CrowdSec Implementation References

Consult these references when implementing or debugging CrowdSec API calls,
methods, request inspection and remediation handling. Their server/proxy
architectures may differ from Caddy's: use them for protocol behavior and reuse
opportunities while preserving our native in-process middleware design and
[product invariants](product-invariants.md).

## Repositories and study areas

The study areas below guide investigation; they are not a verified feature
matrix for any repository revision.

| Repository | What to study |
| --- | --- |
| [Official Nginx bouncer](https://github.com/crowdsecurity/cs-nginx-bouncer) | Primary reference for CrowdSec's Nginx integration, API exchanges and request/remediation handling. |
| [Traefik CrowdSec plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin) | Go reference to inspect for AppSec WAF and Bot Detection behavior, challenge routes and request-body forwarding. |
| [Caddy CrowdSec module](https://github.com/hslatman/caddy-crowdsec-bouncer) | Native Caddy module structure, lifecycle, configuration and AppSec handler. Audit Bot Detection support separately. |
| [Envoy CrowdSec bouncer](https://github.com/kdwils/envoy-proxy-crowdsec-bouncer) | External authorization integration, AppSec inspection, per-host routing and challenge handling. Its architecture differs from our in-process module. |
| [CrowdSec engine](https://github.com/crowdsecurity/crowdsec) | Authoritative server-side AppSec implementation and protocol behavior for the reviewed engine revision. |
| [CrowdSec Hub](https://github.com/crowdsecurity/hub) | AppSec rules, configurations and collections for selecting reviewed, pinned native profiles. |
| [CrowdSec Go bouncer library](https://github.com/crowdsecurity/go-cs-bouncer) | Existing Go client facilities; assess supported functionality for reuse before writing another implementation. |

## Recommended reading order

1. **Nginx:** Request/remediation flow and protocol semantics.
2. **Traefik:** Go challenge handling and request-body forwarding.
3. **Caddy:** Native integration, configuration and lifecycle boundaries.
4. **CrowdSec engine:** Resolve server-side protocol questions against the exact
   reviewed engine revision.

Keep the official [challenge protocol specification](https://docs.crowdsec.net/docs/appsec/bot_detection/challenge_protocol/)
alongside these implementations throughout the review.

## Applying reference behavior

- Verify support claims against the exact tag or immutable commit under review.
  Identify the relevant code and tests before relying on a README description
  or repository name. A link here does not select a dependency or engine pin.
- Use implementations to understand CrowdSec API methods, wire fields,
  decisions, challenges, headers/cookies and body handling. Do not copy another
  proxy's topology, external-authorization layer or content-forwarding path into
  Caddy merely because the reference uses it.
- Check reference behavior against the official specification and the reviewed
  engine implementation. Preserve our site isolation, independent WAF/Bot
  policies, complete-body semantics and direct continuation to the original
  Caddy handler. Reference behavior does not override our product contract.
- Evaluate reuse through the actual Caddy request path and
  [performance requirements](performance-requirement.md). A reference test or
  advertised feature does not establish correctness or performance for our module.
