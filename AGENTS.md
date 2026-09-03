 # Project Instructions

## Project Name
AI-Based Data Security and User Behaviour Monitoring System

## Project Goal
Build a lightweight web application that monitors user behaviour,
detects suspicious data extraction activity, calculates a risk score,
and provides an administrator security dashboard.

## Development Environment
The development machine is Ubuntu Linux with only 4 GB RAM.

Keep all implementation lightweight and resource efficient.

## Required Technology Stack

Backend:
- Python
- Flask

Database:
- SQLite

Frontend:
- HTML
- CSS
- Vanilla JavaScript

Testing:
- pytest when needed

## Do NOT introduce

Do not use any of these unless explicitly requested:

- React
- Next.js
- Node.js
- Angular
- Vue
- Docker
- Kubernetes
- PostgreSQL
- MySQL
- Redis
- TensorFlow
- PyTorch
- Local LLM models
- Heavy UI frameworks
- Unnecessary dependencies

## Security Architecture

Frontend controls must NOT be treated as the primary security mechanism.

Frontend JavaScript may collect telemetry such as:

- copy attempts
- page activity
- keyboard shortcuts
- session events

Actual security enforcement must occur through:

- Backend
- API
- Authentication
- Authorization
- Rate limiting
- Audit logging
- Behaviour analysis

## Main Project Requirements

The application should eventually support:

1. Sample member directory
2. Member profile viewing
3. Search activity tracking
4. Copy attempt tracking
5. Download monitoring
6. Page/screen time tracking
7. Session tracking
8. API request monitoring
9. IP and device information logging
10. Central user activity audit log
11. Rule-based risk scoring from 0 to 100
12. Configurable security thresholds
13. Progressive security response
14. Rate limiting
15. Temporary restrictions
16. Admin security dashboard
17. Suspicious-user activity timeline
18. Security alerts
19. Lightweight AI anomaly detection later

## Risk Levels

Risk scoring should eventually follow:

0-30:
LOW
NORMAL

31-60:
MEDIUM
MONITOR

61-80:
HIGH
RESTRICTED

81-100:
CRITICAL
TEMP_BLOCKED

Do not classify a user as fraudulent because of one copy event.

Risk should use multiple behavioural signals such as:

- frequency
- volume
- speed
- pages viewed
- profile views
- copy behaviour
- downloads
- API request volume
- navigation behaviour
- session behaviour
- device/IP behaviour

## Development Rules

- Implement one requirement at a time.
- Preserve existing working functionality.
- Do not perform unnecessary refactoring.
- Keep functions simple and readable.
- Use meaningful variable and function names.
- Add comments only where useful.
- Never hard-code passwords or API keys.
- Never commit secrets.
- Use fake/sample member data only.
- Use parameterized SQL queries.
- Keep thresholds configurable.
- Validate inputs where appropriate.
- Handle errors gracefully.
- Avoid unnecessary memory usage.

## Codex Working Rules

Before making changes:

1. Read this AGENTS.md file.
2. Inspect the existing project.
3. Understand what already works.
4. Modify only files necessary for the requested task.

After changes:

1. Run the application if practical.
2. Check for syntax/runtime errors.
3. Run relevant tests if present.
4. Fix concrete errors found.
5. Report which files were changed.
6. Briefly explain what was implemented.

Do not silently introduce additional frameworks or architecture.
