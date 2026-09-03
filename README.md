# Sentinel — AI User Behaviour Security Monitor

Sentinel is a lightweight Flask + SQLite demonstration of behaviour-based data security monitoring. It provides a fictional member directory, records user activity, calculates explainable risk scores, and applies auditable security policy decisions to sensitive actions.

This is a portfolio and demonstration project. It is not a production identity, fraud, or endpoint-protection system.

## Features

- Fictional member directory with search, profile viewing, and demo profile downloads.
- Browser telemetry for page entry/exit, search, profile views, copy attempts, session, device, IP, and browser context.
- Central SQLite audit log for user activity and security policy events.
- Explainable rule-based risk scoring over the previous 60 minutes.
- Risk levels and statuses:
  - 0–30: `LOW / NORMAL`
  - 31–60: `MEDIUM / MONITOR`
  - 61–80: `HIGH / RESTRICTED`
  - 81–100: `CRITICAL / TEMP_BLOCKED`
- Risk contributors for profile volume, profile velocity, distinct profiles, copies, downloads, API volume, searches, action frequency, and rapid actions.
- Backend enforcement for sensitive actions:
  - Low risk: allowed.
  - Medium risk: allowed and monitored.
  - High risk: sensitive actions return `403` and record `ACTION_RESTRICTED`.
  - Critical risk: sensitive actions return `403` and record `ACTION_BLOCKED`.
- Lightweight per-process rate limiting for copy attempts, profile views, and downloads. Exceeded limits return `429` and record `RATE_LIMITED`.
- `RISK_ESCALATED` events when a real action moves a user into a higher risk band.
- Admin dashboard with risk breakdowns, activity timeline, security metrics, and enforcement counts.

## Architecture and stack

The application intentionally uses a small server-rendered architecture:

- Backend: Python and Flask
- Database: SQLite (`audit_log` and `user_risk` tables)
- Frontend: HTML, CSS, and vanilla JavaScript
- Tests: Python `unittest`

The browser collects telemetry for the demonstration, but enforcement is performed by Flask routes before sensitive responses are returned. SQL statements use parameterized values. Risk configuration is kept in `risk_engine.py` so the scoring remains inspectable and configurable.

## Run locally

Ubuntu/Linux example:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000/` for the member portal and `http://127.0.0.1:5000/admin` for the dashboard.

The default database is created at `data/security_monitor.db`. Set `SECURITY_MONITOR_DATABASE` to use another SQLite path.

## Demonstration workflow

1. Open the member portal and search or open fictional profiles.
2. Use the copy and download interactions to generate audit events.
3. Generate repeated, rapid profile/copy/download activity to raise the demo user’s score.
4. Review the score, status, contributors, and latest events in the admin dashboard.
5. Once the score reaches HIGH or CRITICAL, sensitive backend actions return a policy response and appear in the audit timeline.

## Testing

From the repository root:

```bash
python -m unittest discover -s tests -v
python -m py_compile app.py audit_db.py risk_engine.py
git diff --check
```

The test suite covers database/audit compatibility, member and admin routes, risk scoring and clamping, LOW/MEDIUM/HIGH/CRITICAL behavior, enforcement responses, rate limiting, and security audit events.

## Security limitations

- Authentication is not production-grade; this demo uses a fixed synthetic user context and has no real admin authorization boundary.
- Rate limiting is in-memory and per process, so it is not shared across workers or machines and resets when the process restarts.
- Restrictions are local demonstration enforcement, not operating-system, firewall, IP-ban, or account-lock controls.
- The member data is synthetic/fictitious and must not be replaced with sensitive data without a proper security review.
- The rule-based engine is explainable monitoring logic, not a machine-learning model and not proof of malicious intent.
- Flask’s built-in development server is intended only for local demonstration.
