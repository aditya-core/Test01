# 01 — Architecture

## 1. System overview

**Secure Digital Document Management System — Legal & Investigation Infrastructure**

This milestone delivers the **security foundation only**: one central identity,
multi-layer authorization, portal-based access, provisioning, audit and the
three portal shells. Case / document / evidence / report modules plug into this
core later **without rewriting authentication**.

```
                              SECURE LOGIN (portal selector)
                                        |
             +--------------------------+--------------------------+
             |                          |                          |
             v                          v                          v
      CLASSIFIED PORTAL          IT / ADMIN PORTAL          GENERAL PORTAL
             \                          |                         /
              \                         |                        /
               +------------------------+-----------------------+
                                        |
                               CENTRAL AUTH ENGINE   (accounts.auth_service)
                                        |
                              AUTHORIZATION ENGINE   (accounts.authorization)
                                        |
            +-------------+--------------+--------------+-------------+
            |             |              |              |             |
          Role        Clearance       Scope       Case access   Resource access
                                        |
                                   Action access
                                        |
                                  ALLOW / DENY
                                        |
                                  AUDIT ENGINE   (audit)
```

## 2. Layer responsibilities

| Layer | Question it answers | Owned by |
|---|---|---|
| Authentication | WHO ARE YOU? | `accounts` (Django auth backend + password hashing) |
| Account state | Is this identity currently permitted to authenticate? | `accounts` (`Officer.account_status`) |
| Portal authorization | WHICH PORTALS may this identity enter? | `accounts.authorization` (`PortalAccess`) |
| Role (RBAC) | WHAT CAPABILITIES does this role carry? | `accounts` (`Role` / `Permission`) |
| Clearance | WHAT SENSITIVITY LEVEL may be accessed? | `accounts` (`ClearanceLevel`) |
| Organizational scope | WHERE may this identity operate? | `accounts` (`Organization` / `OrganizationUnit`) |
| Case authorization | WHICH CASES is this identity assigned to? | future `cases` app (interface defined now) |
| Resource authorization | WHICH RESOURCES may be accessed? | future `documents` app (interface defined now) |
| Action authorization | WHAT can be done with the resource? | `accounts.authorization` |
| Accountability | WHO / WHAT / WHEN / RESULT? | `audit` |

## 3. Design principles (non-negotiable)

1. **Authentication ≠ authorization.** A successful login only proves identity.
2. **Deny by default.** Undecidable ⇒ DENY. Fail closed.
3. **Complete mediation.** Every view/action passes `AuthorizationService`.
4. **Least privilege.** Officers start with NO access; grant incrementally.
5. **No impersonation.** No "login as". Every action is attributable to the
   real identity that performed it.
6. **No client-side security.** The UI reflects permissions; the backend
   enforces them.
7. **Separation of duties.** Identity administration, security administration
   and investigation-data access are distinct grants. IT does not
   automatically read case documents.
8. **No secrets in logs or plaintext storage.** Passwords and secret codes are
   hashed; audit never records them.
9. **No custom cryptography.** Django password hashing + sessions + CSRF.
10. **Generic failure messages.** Never reveal whether an Officer ID exists.

## 4. Security equation (final model)

```
AUTHENTICATED + ACCOUNT ACTIVE + AUTHORIZED PORTAL + ROLE
  + CLEARANCE + ORGANIZATIONAL SCOPE + CASE AUTHORIZATION
  + RESOURCE CLASSIFICATION + REQUESTED ACTION
  = ALLOW / DENY

Any failed condition ⇒ DENY + audit event.
```

## 5. Technology choices

| Concern | Choice | Rationale |
|---|---|---|
| Language / framework | Python 3.11 + Django 5.0 | mature, batteries included |
| Database | PostgreSQL (production) / SQLite (dev/tests) | `DATABASES` is env-driven; models are PG-ready |
| Auth | Django auth framework + custom `Officer` model | no reinvented crypto |
| Password hashing | Django PBKDF2 (via `set_password`) | standard |
| Second factor | `AuthenticationFactor` abstraction + secure secret-code (MVP) + TOTP-ready field | migrate to TOTP/hardware later |
| Sessions | Django sessions + rotation + expiry + secure cookies | standard |
| Frontend | HTML5 + CSS3 + vanilla JS | institutional, minimal, no framework |

## 6. Threat model (addressed)

| Threat | Mitigation |
|---|---|
| Credential stuffing / brute force | failed-attempt tracking, temporary lockout, rate limiting, escalating cooldown, security events, optional IT alert |
| Username enumeration | identical generic message for unknown ID / wrong password / wrong code / locked account |
| Session hijacking / fixation | session rotation on login, secure+HttpOnly+SameSite cookies, expiry + inactivity timeout |
| Cross-site request forgery | Django CSRF middleware on all mutating requests |
| Clickjacking / MIME sniffing / HSTS | `X_FRAME_OPTIONS`, `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_HSTS_SECONDS`, referrer policy |
| Secret disclosure | `SECRET_KEY`, DB password, MFA secrets come from env; `.env.example` only |
| Privilege escalation via UI | backend authorization is authoritative; UI is decoration |
| Privilege escalation via impersonation | feature not implemented; architecture reserves audited break-glass for later |
| Insufficient logging | `audit` records allow AND deny events, keyed by event_id |
| One "superuser" doing everything | role separation; `IT_ADMIN`/`SECURITY_ADMIN` grants are explicit |
