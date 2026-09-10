"""Django settings for the Secure Digital Document Management System.

All secrets come from environment variables (see ``.env.example``). Defaults are
safe for local development; production should set the DJANGO_SECURE_* flags and
a PostgreSQL database.
"""
from __future__ import annotations

import os
import warnings
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
SECRET_KEY = _env("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    warnings.warn(
        "DJANGO_SECRET_KEY is not set; using an insecure development key. "
        "Set it in the environment for any non-local use.",
        RuntimeWarning,
    )
    SECRET_KEY = "dev-only-insecure-secret-key-change-me"

DEBUG = _env_bool("DJANGO_DEBUG", True)

ALLOWED_HOSTS = [
    h.strip() for h in _env("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,*").split(",") if h.strip()
]

CSRF_TRUSTED_ORIGINS = [
    h.strip()
    for h in _env("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",")
    if h.strip()
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Security core.
    "accounts",
    "audit",
    # Portals.
    "classified",
    "it_admin",
    "general",
    "portal",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "accounts.middleware.SessionSecurityMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "accounts.context_processors.portal_context",
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Identity & authentication
# ---------------------------------------------------------------------------
AUTH_USER_MODEL = "accounts.Officer"
AUTHENTICATION_BACKENDS = ["accounts.backends.OfficerBackend"]

LOGIN_URL = "portal_selection"
LOGIN_REDIRECT_URL = "portal_selection"
LOGOUT_REDIRECT_URL = "portal_selection"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

# ---------------------------------------------------------------------------
# Database (PostgreSQL-ready; SQLite for local dev/tests)
# ---------------------------------------------------------------------------
_db_engine = _env("DJANGO_DATABASE_ENGINE", "sqlite")
if _db_engine in {"postgresql", "postgres", "postgresql_psycopg2"}:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _env("DJANGO_DATABASE_NAME", "sdms"),
            "USER": _env("DJANGO_DATABASE_USER", "sdms"),
            "PASSWORD": _env("DJANGO_DATABASE_PASSWORD", ""),
            "HOST": _env("DJANGO_DATABASE_HOST", "127.0.0.1"),
            "PORT": _env("DJANGO_DATABASE_PORT", "5432"),
            "CONN_MAX_AGE": _env_int("DJANGO_DATABASE_CONN_MAX_AGE", 60),
            "CONN_HEALTH_CHECKS": True,
            "OPTIONS": {"sslmode": "prefer"},
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# ---------------------------------------------------------------------------
# Sessions & CSRF (section 13 / 34)
# ---------------------------------------------------------------------------
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_AGE = 60 * 60 * 12  # 12 h (absolute lifetime enforced in middleware)
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = _env_bool("DJANGO_SESSION_COOKIE_SECURE", False)
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = _env_bool("DJANGO_CSRF_COOKIE_SECURE", False)

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "sdms-auth",
    }
}

# ---------------------------------------------------------------------------
# Web security headers (section 34)
# ---------------------------------------------------------------------------
SECURE_SSL_REDIRECT = _env_bool("DJANGO_SECURE_SSL_REDIRECT", False)
SECURE_HSTS_SECONDS = _env_int("DJANGO_SECURE_HSTS_SECONDS", 0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

# ---------------------------------------------------------------------------
# Static / i18n
# ---------------------------------------------------------------------------
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Application-specific settings (overridable via environment)
# ---------------------------------------------------------------------------
# Officer ID generation (section 6).
ACCOUNTS_OFFICER_ID_PREFIX = _env("ACCOUNTS_OFFICER_ID_PREFIX", "OFF-")
ACCOUNTS_OFFICER_ID_WIDTH = _env_int("ACCOUNTS_OFFICER_ID_WIDTH", 3)

# Login protection (section 12).
ACCOUNTS_MAX_FAILED_ATTEMPTS = _env_int("ACCOUNTS_MAX_FAILED_ATTEMPTS", 5)
ACCOUNTS_LOCKOUT_MINUTES = _env_int("ACCOUNTS_LOCKOUT_MINUTES", 15)
ACCOUNTS_COOLDOWN_SECONDS = _env_int("ACCOUNTS_COOLDOWN_SECONDS", 3)
ACCOUNTS_RATE_LIMIT_WINDOW_SECONDS = _env_int("ACCOUNTS_RATE_LIMIT_WINDOW_SECONDS", 300)
ACCOUNTS_RATE_LIMIT_MAX_ATTEMPTS = _env_int("ACCOUNTS_RATE_LIMIT_MAX_ATTEMPTS", 20)

# Sessions (section 13).
ACCOUNTS_SESSION_MAX_AGE_MINUTES = _env_int("ACCOUNTS_SESSION_MAX_AGE_MINUTES", 480)
ACCOUNTS_SESSION_INACTIVITY_MINUTES = _env_int("ACCOUNTS_SESSION_INACTIVITY_MINUTES", 30)
ACCOUNTS_REAUTH_INTERVAL_SECONDS = _env_int("ACCOUNTS_REAUTH_INTERVAL_SECONDS", 600)

# Secret-code second factor (section 10). Pepper for the salted HMAC digest.
ACCOUNTS_SECRET_CODE_PEPPER = _env("ACCOUNTS_SECRET_CODE_PEPPER", "dev-insecure-pepper-change-me")
if ACCOUNTS_SECRET_CODE_PEPPER == "dev-insecure-pepper-change-me":
    warnings.warn(
        "ACCOUNTS_SECRET_CODE_PEPPER is not set; using an insecure development "
        "pepper. Set it in the environment for any non-local use.",
        RuntimeWarning,
    )

# Classified portal required clearance (configurable).
ACCOUNTS_CLASSIFIED_MIN_CLEARANCE = _env("ACCOUNTS_CLASSIFIED_MIN_CLEARANCE", "L4")
