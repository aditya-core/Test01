# 02 — Django App Structure

```
project/
├── config/
│   ├── settings.py          # env-driven, hardened defaults
│   ├── urls.py              # root URLConf + custom error handlers
│   ├── asgi.py
│   └── wsgi.py
│
├── accounts/                # CENTRAL IDENTITY AUTHORITY
│   ├── models.py            # Officer (custom User), Role, Permission,
│   │                        #   ClearanceLevel, Organization, OrganizationUnit,
│   │                        #   Portal, PortalAccess, AuthenticationFactor
│   ├── managers.py          # OfficerManager (create_officer / create_superuser)
│   ├── constants.py         # account states, portal keys, event types
│   ├── backends.py          # OfficerBackend (ID/password, state checks)
│   ├── services.py          # AccountService, ProvisioningService,
│   │                        #   SecurityCodeService, LoginProtectionService,
│   │                        #   SessionService, ReauthenticationService
│   ├── authorization.py     # AuthorizationService (central engine)
│   ├── decorators.py        # portal_required, permission_required, clearance_required
│   ├── mixins.py            # PortalRequiredMixin, PermissionRequiredMixin
│   ├── forms.py             # login + provisioning + activation + reset forms
│   ├── views.py             # portal selector, multi-step login, activation,
│   │                        #   re-auth, account settings, first-run MFA setup
│   ├── admin.py             # IT-administered Django admin (Officer etc.)
│   ├── context_processors.py
│   ├── urls.py
│   ├── templates/accounts/...
│   └── tests/
│
├── audit/                   # ACCOUNTABILITY ENGINE
│   ├── models.py            # AuditEvent, SecurityEvent
│   ├── services.py          # AuditService (record_* helpers, filtering)
│   ├── views.py             # authorized audit browser
│   ├── urls.py
│   └── tests/
│
├── classified/              # CLASSIFIED PORTAL SHELL
│   ├── views.py
│   ├── urls.py
│   └── templates/classified/...
│
├── it_admin/                # IT / ADMIN PORTAL SHELL
│   ├── views.py             # officer management, provisioning, reset, MFA,
│   │                        #   security monitoring, audit viewer
│   ├── urls.py
│   └── templates/it_admin/...
│
├── general/                 # GENERAL OFFICER PORTAL SHELL
│   ├── views.py
│   ├── urls.py
│   └── templates/general/...
│
├── portal/                  # shared authenticated shell (base template, nav)
│   └── templates/portal/...
│
├── templates/               # error pages + global base
├── static/                  # css/js
├── docs/                    # this design set
├── .env.example             # environment template (no real secrets)
├── requirements.txt
└── manage.py
```

## Dependency direction (strict)

```
classified ─┐
it_admin  ──┼──► accounts  ──► audit
general   ──┘        │
                     └──► (future cases / documents plug in here)
```

* `accounts` owns identity + authorization and is the **only** authority.
* Portal apps are thin shells; they never decide "who" or "what", they call
  `AuthorizationService` and render the returned capabilities.
* `audit` is a leaf dependency — everything records into it; it records nothing back.
