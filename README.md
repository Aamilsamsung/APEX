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
