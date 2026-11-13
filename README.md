# AEGIS PKI — Certificate Security Operations

A working **local hackathon MVP** for the Praxis 2.0 preventive/reactive PKI security challenge. Includes a polished responsive dashboard, 30 generated sandbox certificates, separate certificate scanner/rule-based risk analysis/responder workflows, deterministic risk scoring, simulated key compromise, explicit approval, sandbox key rotation, and audit logs.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. On first startup the backend generates 30 mock RSA certificates in `data/certificates/` and populates SQLite. The first start can take a few seconds. Click **Run security scan**, then **Simulate key compromise**, then **Approve & remediate** in the incident screen. Inspect the **Audit trail**.

Tests: `pytest -q`.

## Architecture

- `backend/core.py`: certificate fixture generation, Scanner (reads registered local PEMs), deterministic Risk Analyst, score, simulated Responder, audit.
- `backend/main.py`: FastAPI endpoints.
- `frontend/`: responsive, dependency-free UI (no Node build step).
- `tests/`: end-to-end core workflow tests.

## Honest scope and security boundaries

**This is an isolated demo, not a production CA or certificate scanner.** It scans only generated local PEM files, not network TLS endpoints. Seeded certificates are intentionally self-signed and treated as test fixtures. No trust-chain validation is performed. Revocation is a sandbox database flag; it does **not** publish CRLs or OCSP. Reissuance uses a new self-signed sandbox certificate and updates the active inventory pointer, not a running TLS endpoint. The compromised-key signal is explicitly injected by the simulator, not inferred from certificate contents. The response workflow requires approval but is **not authenticated**; bind to loopback only and do not expose it publicly. Generated unencrypted private keys are test fixtures; do not reuse them for real systems.

The explanation endpoint currently provides **deterministic fallback**, clearly labeled. **LLM integration is not yet implemented.** Likewise, step-ca/ACME, endpoint discovery, deployed TLS verification, and production-ready authentication are not implemented. Those are future extensions; the UI does not claim otherwise.

Health score: for each active certificate, sum risk penalties (critical=30, high=15, medium=7, low=3), cap at 100; overall health = 100 minus the average per-certificate penalty. This is a demo policy, not an industry standard.

## Demo flow

1. Start app and scan inventory.
2. Review expiry, RSA-1024, SAN mismatch, and expired certificate findings.
3. Simulate a compromise (explicit incident marker).
4. Review pending incident; approve or reject.
5. Approve: backend generates a fresh key/certificate, retires the old active record, verifies replacement certificate properties, and records the steps.
6. Rescan and inspect score, incidents, and audit log.

Do not scan external targets without authorization.

## Enhanced sandbox workflow

The current build generates certificates signed by a local **AEGIS Sandbox Root CA** and maintains a serial-number revocation registry. This is a private demo CA, **not** a public trust service or ACME implementation. All targets are local, authorized sandbox targets.

To demonstrate a live TLS endpoint, open a second terminal in the project directory:

```bash
python -m backend.demo_tls
```

The local endpoint runs at `127.0.0.1:8443` with hostname `service-01.demo.local`. The endpoint runner reloads its certificate when the inventory pointer changes. Use `POST /api/scan-endpoint` with `{"host":"127.0.0.1","port":8443,"expected_hostname":"service-01.demo.local"}` to retrieve the actual TLS-presented certificate and validate its signature against the sandbox CA. `GET /api/revocations` exposes sandbox revocation entries.

For AI explanations, set `GROQ_API_KEY` in the backend environment (optionally `GROQ_MODEL`). If absent, the UI uses clearly labeled deterministic guidance; no model training is required. Only known finding IDs are accepted from the LLM. This demo must not be exposed to untrusted networks: its approval flow is not an authenticated production authorization system.

## Incident explanation timeline (updated)

The **Incident response** page now displays a step-by-step account of the detected simulated compromise, operator approval, sandbox serial revocation, fresh private-key generation, local CA signing, active inventory replacement, property checks, and a **mock** owner notification. These descriptions are derived from audit events, not invented by an LLM. A `GET /api/incidents/{id}/steps` endpoint returns the same structured timeline.

**Scope warning:** The current responder does not perform ACME issuance, publish OCSP/CRL, deliver an external notification, or prove redeployment to a live TLS server. The optional TLS demo server can reload the inventory-selected certificate, but the responder does not currently confirm its served fingerprint. Do not claim the complete PDF reactive playbook is implemented.

## Updated PS2 features and remaining limitations

- Local **mock CT replay** (`GET /api/ct-monitor`) includes a deliberately unauthorized certificate. This is not live crt.sh monitoring.
- **Tamper-evident audit chain** (`GET /api/audit-integrity`) hashes new events. The original audit table remains for backwards compatibility; the chain starts with events logged after this feature was added.
- Additional deterministic checks include unexpected self-signed leaves, unusually long validity, and simple wildcard misuse. Intermediate-chain ordering and multi-service wildcard reuse remain unimplemented.
- **Live redeployment verification**: run `python -m backend.demo_tls` in a second terminal before simulating a compromise on `service-01.demo.local`. After approval the Responder polls `127.0.0.1:8443`, compares the actual served serial with the replacement, checks CA signature, SAN and sandbox revocation registry, and records `verified`, `failed`, or `not_running` in the incident timeline. If the server isn't running, no live verification is claimed. The local CA issuance is not ACME.
- **Notifications** remain a mock audit event. No SMTP or webhook integration is configured.
- Approval is a demo-only name prompt and **not authenticated**. Do not expose this app beyond loopback.
- To keep the download free of test secrets and old run data, the ZIP omits `data/`. Certificates and the local CA private key are generated on first run.

### Recommended hackathon demo

1. Start FastAPI and the optional TLS server in separate terminals.
2. Use **Check local TLS server** to confirm the actual presented certificate.
3. Open **Incident response**, simulate compromise of `service-01.demo.local` (the first certificate), and explicitly approve.
4. Inspect the timeline: key generation, CA issuance, sandbox revocation, and **live TLS verification** (when the endpoint is running).
5. Open **Audit trail** and inspect the hash-chain status in the overview diagnostics.
6. Show the mocked CT feed and distinguish its rogue entry from actual internet CT results.

Run tests from the project root using `python -m pytest -q`.

## Team APEX dashboard

The dashboard uses [Circle](https://github.com/ln-dev7/circle) as the visual reference for the compact workspace layout and [React Flow](https://github.com/xyflow/xyflow) for the certificate relationship map. Select a service or click a finding to inspect its issuer, active certificate, and registered hostname. The incident timeline displays audited sandbox steps, the original and replacement certificates, and the separate live TLS result.

FastAPI serves the checked-in frontend build. To rebuild after editing the React Flow component, run `npm ci && npm run build` from `frontend/`.

## Additional integration: public certificate imports and scheduled scanning

Open **Certificate inventory** and select a public PEM/CRT/CER certificate, then enter the DNS hostname you expect it to cover. The backend parses the public X.509 certificate, stores it in the local sandbox, runs deterministic risk checks, and shows it in inventory. **Never upload a private key.** Imported certificates are intentionally scan-only and cannot be rotated by the Responder.

To enable periodic preventive scans, set `AEGIS_SCAN_INTERVAL_SECONDS=300` before starting FastAPI (minimum 30 seconds). By default, scans run at startup and on demand. For multiple authorized local TLS demo endpoints, run separate terminals:

```bash
python -m backend.demo_tls --hostname service-01.demo.local --port 8443
python -m backend.demo_tls --hostname service-02.demo.local --port 8444
```

The endpoint API supports loopback-only targets. The dashboard's quick TLS button still checks only port 8443. Local demo certificates are not trusted by public browsers. The backend does **not** provide ACME issuance, authenticated approvals, delivered notifications, or general internet scanning. These limitations must not be presented as completed features.

## LangGraph and OpenSSL integration

Install updated dependencies with `python -m pip install -r requirements.txt`. The backend now uses **LangGraph** to coordinate Scanner → Risk Analyst on startup, scheduled scans, and `POST /api/scan`. Simulated incidents use Detector → Approval Gate. The gate ends in `pending_approval`; the Responder is invoked only by `POST /api/incidents/{incident_id}/approve`, which also checks the pending state. This is a demo approval gate, **not authenticated authorization**. Inspect `GET /api/orchestration`.

Install the **OpenSSL command-line program** separately and ensure `openssl version` works. `GET /api/certificates/{certificate_id}/openssl` returns public X.509 inspection and `openssl verify` against the local sandbox CA. The command never passes private keys or arbitrary remote hosts. Imported certificates signed by other CAs will generally fail sandbox CA verification as expected. OpenSSL is optional for application startup but required for that endpoint.

Run `python -m pytest -q` after installing requirements. These integrations need to be tested on your target Windows environment before the hackathon; no CI result is claimed here. ACME, real notification delivery, authenticated approval and production-grade agent isolation are still not implemented.

## PS2 standards reference integrations (Render-safe)

- `GET /api/standards` lists the NIST SP 800-57 key-management reference, MITRE ATT&CK resource, and honest ACME/CT statuses.
- `GET /api/findings/enriched` augments real deterministic findings with relevant NIST guidance and MITRE technique references. These are educational classifications, not evidence that a real attack occurred.
- Existing sandbox CT replay remains supported; live crt.sh requests are not performed by default.
- ACME and Smallstep step-ca are **not** silently enabled: both require a running authorized CA, secure provisioning, and a verified issuance/revocation workflow. No production CA credentials should be stored in Git.
- Render's ephemeral filesystem may reset the SQLite database and generated CA keys across deployments. Use persistent storage or a managed database for state continuity. Never expose unauthenticated approval endpoints to untrusted users.

## Optional Render demo TLS and real webhook integration

The deployed FastAPI app can start its own **loopback-only** TLS test server by setting `AEGIS_ENABLE_TLS_DEMO=1` in Render's environment. This starts `service-01.demo.local` at `127.0.0.1:8443` inside the same Render instance. It is **not** the publicly accessible Render HTTPS certificate; it verifies the certificate served by the local sandbox TLS endpoint. The Responder records `verified`, `failed`, or `not_running` in the incident audit and returns the status from the approval API. Running multiple Render workers/instances can break this single-instance local demo; use one worker for the sandbox.

Set `AEGIS_NOTIFY_WEBHOOK_URL` to a trusted **HTTPS webhook** you control to deliver a JSON incident message after remediation. The URL may contain a secret path or query, so store it **only in Render environment variables**, never Git. The audit records delivery status without the URL or secrets. Without the setting, notifications are clearly marked `not_configured`. Check `GET /api/integrations` for configured status (never exposes the webhook URL).

## Optional private Smallstep ACME integration

The new `backend/acme_client.py` is an **operator-run** RFC 8555 ACME issuance helper using Certbot. It does not yet replace the sandbox responder's Python-CA issuance. To use it in a **separate local private CA environment**, install and configure Smallstep step-ca with an ACME provisioner and HTTP-01 challenge routing for your owned sandbox hostname, trust the private CA at the OS level, and install Certbot. Then run:

```bash
python -m backend.acme_client --hostname service-01.demo.local --directory https://your-private-step-ca/acme/acme/directory
```

This cannot work by merely pushing GitHub code to a standard Render web service: the private CA, challenge routing, and trusted CA certificate must exist separately. Do not configure a public ACME directory for fake `.demo.local` names. The helper never exposes certificate issuance as a public API and reports only whether the subprocess succeeded. Fully automatic ACME issuance, revocation, and integration into the Responder still require provisioning and end-to-end validation.

Run `python -m pytest -q` after pulling dependencies. No claim is made that the new integration tests have run on Render.
