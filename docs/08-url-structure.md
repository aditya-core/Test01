# 08 — URL Structure

| URL | Purpose |
|---|---|
| `/` | Landing / portal selector |
| `/auth/login/general/` | General officer login |
| `/auth/login/classified/` | Classified login |
| `/auth/login/admin/` | IT / admin login |
| `/auth/logout/` | Logout (POST, CSRF-protected) |
| `/auth/activate/<uidb64>/<token>/` | Secure account activation |
| `/auth/reauth/` | Re-authentication gate (sensitive ops) |
| `/account/` | Own profile + security settings |
| `/account/password/` | Change own password |
| `/account/security/` | Enrol / reset own secret code |
| `/auth/security-code/` | First-run secret-code setup |
| `/general/` | General portal dashboard |
| `/classified/` | Classified portal dashboard |
| `/admin-portal/` | IT / admin portal dashboard |
| `/admin-portal/officers/` | Officer management |
| `/admin-portal/officers/new/` | Create officer + generate Officer ID |
| `/admin-portal/officers/<pk>/` | Officer detail |
| `/admin-portal/officers/<pk>/status/` | Activate / suspend / disable / deactivate |
| `/admin-portal/officers/<pk>/lock/` · `/unlock/` | Lock / unlock |
| `/admin-portal/officers/<pk>/reset-password/` | Reset password |
| `/admin-portal/officers/<pk>/reset-code/` | Reset secret code |
| `/admin-portal/officers/<pk>/portals/` | Assign portal access |
| `/admin-portal/security/` | Security monitoring (SecurityEvents) |
| `/admin-portal/audit/` | Audit browser |
| `/audit/` | Authorized audit interface (shared) |
| `/security/` | Authorized security functionality |
