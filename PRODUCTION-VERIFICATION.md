# APEX AEGIS production verification

Baseline source revision is `e000818edc7a4b50812f1677484ffe0144ad9d92`. The live health endpoint returned HTTP 200 with `sandbox: true` on 14 November 2026.

| Mission phase | Evidence in the baseline | Work still required |
| --- | --- | --- |
| 1. Audit | FastAPI, SQLite, static dashboard, worker, ACME modules and backend regression suite identified. | Finish full architecture and access-control review. |
| 2. Frontend | Spectrum Popover and Badge are now used in the React/TypeScript notifications widget. The incident link takes users to the matching card. Existing findings screen renders backend recommendations. | Migrate remaining views, add the five missing pages, and complete accessibility and browser acceptance. |
| 3. PKI | Local X.509 inventory, public-certificate import, chain checks, rule-based scoring, history and loopback TLS inspection. CT uses a mock feed. | Configured network inventory, production CT, OCSP/CRL and policy acceptance. |
| 4. Agents | Scanner, risk and response workflow code and regression tests exist. | Durable orchestration under restarts, retries and concurrent execution. |
| 5. ACME | Private CA local-worker paths and lifecycle test fixtures exist. | End-to-end acceptance with an isolated reachable CA, worker, deployment destination and trust verification. |
| 6. Gemini | Backend provider handling and deterministic fallback have existing tests. | Live credential-backed validation and analyst workspace. |
| 7. Identity and integrations | Shared operator token, SQLite and webhook support. The integrations API exposes configuration flags. | Durable production persistence, per-user RBAC, verified connection status, SMTP and delivery retries. |
| 8. Security | Operator checks apply to protected mutations. Certificate and incident read routes currently have no operator check. | Define tenancy and identity boundaries before storing real operational records. Complete worker replay and audit integrity review. |
| 9. Testing | Baseline backend suite passed 58 tests. TypeScript checks and the production JavaScript build passed locally. | Validate notification layout and navigation in a supported browser runner and run deployed lifecycle acceptance. |
| 10. Deployment | Existing Render service tracks main and deploys automatically. Its preview generation is disabled. | Verify the branch in staging before promotion. |
| 11. Documentation | Existing README covers demo and worker setup. This matrix records evidence and gaps. | Complete production runbooks once the architecture and integrations are validated. |

## Notification build

Run `npm ci`, `npm run typecheck` and `npm run build` from `frontend/`. The backend serves the checked-in bundles. `frontend/src/spectrum/README.md` records the upstream component revision and license.

The expected browser checks are viewport containment at desktop and narrow mobile sizes, Escape dismissal with focus returned to the trigger, and focus on the matching incident card when opening an alert. The local Chromium process failed before page load because the runtime denied creation of its process singleton socket.
