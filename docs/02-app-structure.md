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
├── it_admin/                # IT / ADMIN PORTAL
│   ├── views/               # package, split by concern (re-exported through
│   │   │                    #   views/__init__.py so `it_admin.views` works)
│   │   ├── dashboard.py     # counters + recent administrative activity
│   │   ├── officers.py      # directory, provisioning wizard, lifecycle,
│   │   │                    #   credentials, transfers, timeline, "WHY?" page
│   │   ├── registries.py    # designations, departments, units, postings
│   │   ├── bulk.py          # CSV import: upload -> preview -> commit
│   │   ├── security.py      # account security, devices & sessions, reviews,
│   │   │                    #   temporary access, audit dashboard + verify
│   │   ├── access.py        # admin roles & capability matrix, assignments
│   │   ├── approvals.py     # four-eyes approval centre
│   │   └── _common.py       # shared helpers (activation links, querysets)
│   ├── navigation.py        # capability-driven sidebar (context processor)
│   ├── services.py          # OfficerAdmin, Transfer, Registry, TemporaryAccess,
│   │                        #   AccessReview and Approval services
│   ├── approvals.py         # executors run once an approval is granted
│   ├── bulk.py, timeline.py, models.py, forms.py, urls.py
│   └── templates/it_admin/...
│
├── general/                 # GENERAL OFFICER PORTAL (operational cases)
│   ├── models.py            # CaseRecord (+ security attributes), CaseEvidenceFile,
│   │                        #   CaseAssignment - the operational grant
│   ├── views.py             # dashboard, registration, authorized case register,
│   │                        #   protected FIR / evidence delivery
│   ├── forms.py             # case registration (classification is required)
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
* `accounts` never imports a portal app. Where the engine needs operational
  data (case assignment) it reaches it through duck-typed hooks on `Officer`
  (`is_assigned_to_case`, `case_actions_for`) that resolve the model via the
  app registry — so the dependency arrow never reverses.
