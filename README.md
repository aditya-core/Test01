# Secure Digital Document Management System — Auth & Access Foundation

The **security core** for a government-oriented Secure Digital Document
Management System for Legal & Investigation Documents.

This milestone implements the complete multi-layer **authentication,
authorization, user provisioning and access-portal foundation**. Case,
document, evidence and report modules will plug into this core later without
rewriting authentication.

Three entry portals — **Classified**, **IT / Admin**, **General Officer** —
all served by **one central identity and authorization system**
(`accounts` + `audit`).

> Full design documentation lives in [`docs/`](docs/):
> architecture, app structure, data model, auth flow, authorization flow,
> portal access matrix, security model, URL structure, implementation plan.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env          # then fill in real values (SECRET_KEY, etc.)
python manage.py migrate
python manage.py seed_demo    # idempotent demo data (see below)
python manage.py runserver 0.0.0.0:8000
```

Open `http://localhost:8000/`.

## Demo accounts (created by `seed_demo`)

| Portal | Officer ID | Password | Secret code |
|---|---|---|---|
| General (field officer) | `OFF-101` | `ChangeMe!123` | `CODE-101` |
| General (inspector) | `OFF-102` | `ChangeMe!123` | `CODE-102` |
| Classified | `OFF-201` | `ChangeMe!123` | `CODE-201` |
| IT / Admin | `OFF-301` | `ChangeMe!123` | `CODE-301` |
| Security admin (audit) | `OFF-302` | `ChangeMe!123` | `CODE-302` |
| Dev superuser | `SU-900` | `ChangeMe!123` | `CODE-900` |

Seeded accounts are provisioned by Central IT and arrive in the workflow:
newly created officers are `INVITED` and activate through the
**activation link** shown in the provisioning result page. (Demo accounts are
pre-activated for convenience.)

## Tests

```bash
python manage.py test
```

Covers: valid login, invalid password / Officer ID / secret code, locked /
disabled / inactive accounts, unauthorized portal selection, junior→senior
resource access, cross-district denial, insufficient clearance, wrong case,
insufficient action permission, unauthorized download/delete, impersonation
rejection, session expiration, logout, CSRF, audit event generation, failed
access events, role/clearance modification, MFA reset, account deactivation.

## Environment

All secrets come from environment (see `.env.example`). Never commit
`.env`. Production should use PostgreSQL (`DJANGO_DATABASE_ENGINE` and friends);
SQLite is the development/test default.

> **Pepper caveat:** secret codes are stored as a salted HMAC digest keyed by
> `ACCOUNTS_SECRET_CODE_PEPPER`. If you change the pepper, existing secret codes
> stop verifying — re-run `python manage.py seed_demo` (or reset each officer's
> code) afterwards.

## Layout

```
config/       settings, root urls, wsgi/asgi
accounts/     central identity authority (custom User, RBAC, clearance, org,
              authorization service, login, activation, re-auth)
audit/        accountability engine (AuditEvent, SecurityEvent, viewer)
classified/   classified portal shell
it_admin/     IT / admin portal shell (provisioning, security, audit)
general/      general officer portal shell
portal/       shared authenticated shell (base template, nav)
docs/         design documents
```

## Security notes

- Custom `Officer` user model from day one (`AUTH_USER_MODEL`).
- Passwords via Django PBKDF2; secret codes via salted HMAC digest — never
  plaintext, never logged.
- Deny-by-default authorization; complete mediation; no impersonation.
- Brute-force lockout, rate limiting, escalating cooldown, security events.
- Secure sessions: rotation on login, expiry, inactivity timeout, secure +
  HttpOnly + SameSite cookies, CSRF everywhere, re-authentication for
  sensitive operations.
- Security headers (HSTS, X-Frame-Options, nosniff, referrer policy).
