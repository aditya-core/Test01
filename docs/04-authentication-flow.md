# 04 — Authentication Flow

## 1. Login (multi-step, security-conscious)

```
 STEP 1   Select portal         /           (classification UI hint only)
 STEP 2   Officer ID            /auth/login/<portal>/
 STEP 3   Identify account      backends.OfficerBackend
 STEP 4   Password verify       Django check_password (PBKDF2)
 STEP 5   Second factor         secret code / MFA factor
 STEP 6   Account status        ACTIVE only; handle SUSPENDED/LOCKED/DISABLED/...
 STEP 7   Role verification     via backend + authorization
 STEP 8   Clearance check       evaluated at access time (not stored at login)
 STEP 9   Scope check           evaluated at access time
 STEP 10  Portal authorization  AuthorizationService.can_access_portal()
 STEP 11  Secure session        login() → session rotation, flags, expiry
 STEP 12  Dashboard             capabilities computed by AuthorizationService
```

## 2. Detailed sequence (backend)

1. **Rate-limit / lockout gate** (`LoginProtectionService`)
   - If `locked_until > now` ⇒ generic failure + `ACCOUNT_LOCKED_BLOCK` event.
   - Apply escalating cooldown after repeated failures.
2. **Lookup by `officer_id`** (case-insensitive, uppercase-normalized).
   - Unknown ID ⇒ run a dummy `check_password` (constant-ish time) and return
     the **same generic message** as a wrong password (anti-enumeration).
3. **Password verify** (`OfficerBackend.authenticate`).
   - Failure ⇒ increment `failed_login_attempts`, record
     `LOGIN_FAILURE` + `SECURITY_EVENT`, maybe lock after `MAX_FAILED_ATTEMPTS`.
4. **Account status**
   - `PENDING/INVITED` ⇒ "complete activation".
   - `SUSPENDED/DISABLED/DEACTIVATED` ⇒ "contact Central IT".
   - `LOCKED` ⇒ "account temporarily locked".
   - Generic phrasing; no distinction that leaks why.
5. **Second factor** (`SecurityCodeService.verify`)
   - Factor must be enrolled AND enabled. On success, clear failed attempts,
     mark `last_verified_at`, then proceed.
   - On failure ⇒ treat as a failed login (same protections).
6. **Portal authorization** (`AuthorizationService.can_access_portal`)
   - `ACTIVE` + explicit `PortalAccess` (or role default) + (classified:
     required clearance) ⇒ else log `PORTAL_ACCESS_DENIED` + deny.
7. **Session establishment** (`SessionService` + `auth.login`)
   - `login()` rotates the session key (fixation protection).
   - Set session flags: portal, `mfa_verified_at`, `reauth_at`,
     `session_created_at`.
8. **Audit** `LOGIN_SUCCESS` / `PORTAL_ACCESS`.

## 3. Generic failure rule

| Situation | Message shown |
|---|---|
| Unknown Officer ID | "Invalid credentials or account status." |
| Wrong password | "Invalid credentials or account status." |
| Wrong/absent secret code | "Invalid credentials or account status." |
| Locked / suspended / disabled | "Invalid credentials or account status." (or "Account unavailable. Contact Central IT." where policy allows) |
| Unauthorized portal | "You are not authorized to access this portal." (after successful identity check) |

## 4. Account states

```
PENDING ──(Central IT provisions credentials)──► INVITED
INVITED ──(officer completes secure activation)──► ACTIVE
ACTIVE ──► SUSPENDED (manual) / LOCKED (auto after failures) / DISABLED / DEACTIVATED
LOCKED ──► ACTIVE (auto after cooldown or IT unlock)
SUSPENDED/DISABLED/DEACTIVATED ──► ACTIVE (IT reactivation)
```

## 5. Failure protection parameters (env-configurable)

| Setting | Default |
|---|---|
| `MAX_FAILED_LOGIN_ATTEMPTS` | 5 |
| `LOGIN_LOCKOUT_MINUTES` | 15 |
| `LOGIN_COOLDOWN_SECONDS` | 3 (escalating per failed attempt) |
| `LOGIN_RATE_LIMIT` (per officer per window) | 20 / 5 min |
| `SESSION_INACTIVITY_MINUTES` | 30 |
| `SESSION_MAX_AGE_MINUTES` | 480 (8 h) |
| `REAUTH_INTERVAL_SECONDS` | 600 (10 min) |

## 6. Session security

* Session key rotation on login (Django `login()`).
* `SESSION_EXPIRE_AT_BROWSER_CLOSE = True` + explicit max-age.
* Custom expiry middleware enforces inactivity + absolute lifetime.
* `SESSION_COOKIE_SECURE / HTTPONLY / SAMESITE`, `CSRF_COOKIE_SECURE`.
* Logout flushes the session (server-side invalidation).
* Re-authentication gate for sensitive operations
  (`SecurityCodeService.require_recent_reauth` / `reauth_required` decorator).

## 7. What is NEVER logged

passwords · secret codes · MFA tokens · OTP values · full session cookies ·
`SECRET_KEY` · DB credentials.
