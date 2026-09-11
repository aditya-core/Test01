"""Authentication and account views.

The login view is the orchestration point for the multi-step flow:
    rate-limit → identify → password → status → second factor → portal → session.
Every step fails with a single generic message so nothing about account
existence or state is leaked.
"""
from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.urls import reverse, reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from audit.services import audit_service

from . import constants as C
from .authorization import authorization_service
from .backends import OfficerBackend
from .decorators import reauth_required
from .forms import (
    ActivationForm,
    PasswordChangeForm,
    PortalLoginForm,
    ReauthForm,
    SecretCodeForm,
)
from .devices import device_session_service
from .services import (
    login_protection_service,
    security_code_service,
    session_service,
)

Officer = get_user_model()

GENERIC_FAILURE = "Invalid credentials or account status."

# URL-slug aliases (spec §51 uses /auth/login/admin/ for the IT portal; the
# canonical portal key remains ``it_admin``).
PORTAL_KEY_ALIASES = {"admin": C.PORTAL_IT_ADMIN}

PORTAL_META = {
    C.PORTAL_CLASSIFIED: {
        "title": "Classified Access",
        "subtitle": "Highly restricted access",
        "login_url": reverse_lazy("accounts:login", kwargs={"portal_key": C.PORTAL_CLASSIFIED}),
        "dashboard_url": "classified:dashboard",
    },
    C.PORTAL_IT_ADMIN: {
        "title": "IT Department / Administration",
        "subtitle": "Identity & system administration",
        "login_url": reverse_lazy("accounts:login", kwargs={"portal_key": "admin"}),
        "dashboard_url": "it_admin:dashboard",
    },
    C.PORTAL_GENERAL: {
        "title": "General Officer",
        "subtitle": "Authorized officer access",
        "login_url": reverse_lazy("accounts:login", kwargs={"portal_key": C.PORTAL_GENERAL}),
        "dashboard_url": "general:dashboard",
    },
}


def _portal_or_404(portal_key: str):
    portal_key = PORTAL_KEY_ALIASES.get(portal_key, portal_key)
    if portal_key not in PORTAL_META:
        from django.http import Http404

        raise Http404("Unknown portal")
    return portal_key


def redirect_to_first_portal(user):
    """Landing redirect: send an authenticated officer to their first
    authorized portal."""
    portals = authorization_service.list_authorized_portals(user)
    order = [C.PORTAL_GENERAL, C.PORTAL_CLASSIFIED, C.PORTAL_IT_ADMIN]
    for key in order:
        if key in portals:
            return redirect(PORTAL_META[key]["dashboard_url"])
    return redirect("portal_selection")


# ---------------------------------------------------------------------------
# Landing / portal selection
# ---------------------------------------------------------------------------
def portal_selection(request):
    if request.user.is_authenticated:
        return redirect_to_first_portal(request.user)
    return render(request, "accounts/portal_selection.html", {"portals": PORTAL_META})


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
@require_http_methods(["GET", "POST"])
def portal_login(request, portal_key: str):
    portal_key = _portal_or_404(portal_key)
    meta = PORTAL_META[portal_key]

    if request.user.is_authenticated:
        return redirect_to_first_portal(request.user)

    form = PortalLoginForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        officer_id = form.cleaned_data["officer_id"]
        password = form.cleaned_data["password"]
        secret_code = form.cleaned_data["secret_code"]

        # --- Step: rate limiting (per identifier + IP) --------------------
        if not login_protection_service.rate_limit_allowed(request, officer_id):
            audit_service.record_event(
                C.EVENT_LOGIN_BLOCKED,
                officer_id_snapshot=officer_id,
                result=C.RESULT_DENY,
                portal=portal_key,
                reason="Rate limit exceeded",
                request=request,
            )
            audit_service.record_security_event(
                C.EVENT_LOGIN_BLOCKED,
                severity=C.SEVERITY_WARNING,
                details={"officer_id": officer_id},
                request=request,
            )
            form.add_error(None, "Too many attempts. Please wait and try again.")
            return render(request, "accounts/login.html", {"form": form, "portal": meta, "portal_key": portal_key})

        # --- Step: identify account (never reveal whether it exists) ------
        try:
            officer = Officer.objects.get(officer_id__iexact=officer_id)
        except Officer.DoesNotExist:
            officer = None

        # --- Step: lockout gate -------------------------------------------
        if officer is not None and officer.is_locked_out:
            audit_service.record_event(
                C.EVENT_LOGIN_BLOCKED,
                officer=officer,
                result=C.RESULT_DENY,
                portal=portal_key,
                reason="Account temporarily locked",
                request=request,
            )
            form.add_error(None, GENERIC_FAILURE)
            return render(request, "accounts/login.html", {"form": form, "portal": meta, "portal_key": portal_key})

        # --- Step: password verification -----------------------------------
        user = OfficerBackend().authenticate(
            request, officer_id=officer_id, password=password
        )
        if user is None:
            if officer is not None:
                login_protection_service.record_failure(officer, request=request)
            else:
                audit_service.record_event(
                    C.EVENT_LOGIN_FAILURE,
                    officer_id_snapshot=officer_id,
                    result=C.RESULT_FAILURE,
                    portal=portal_key,
                    request=request,
                )
            form.add_error(None, GENERIC_FAILURE)
            return render(request, "accounts/login.html", {"form": form, "portal": meta, "portal_key": portal_key})

        # --- Step: account status ------------------------------------------
        if not user.is_active or user.account_status != C.ACCOUNT_STATUS_ACTIVE:
            audit_service.record_event(
                C.EVENT_LOGIN_BLOCKED,
                officer=user,
                result=C.RESULT_DENY,
                portal=portal_key,
                reason=f"Account status {user.account_status}",
                request=request,
            )
            form.add_error(None, GENERIC_FAILURE)
            return render(request, "accounts/login.html", {"form": form, "portal": meta, "portal_key": portal_key})

        # --- Step: second factor -------------------------------------------
        if not security_code_service.verify_for(user, secret_code):
            login_protection_service.record_failure(user, request=request)
            form.add_error(None, GENERIC_FAILURE)
            return render(request, "accounts/login.html", {"form": form, "portal": meta, "portal_key": portal_key})

        # --- Step: portal authorization (post-identity) ---------------------
        if not authorization_service.can_access_portal(user, portal_key):
            audit_service.record_event(
                C.EVENT_PORTAL_ACCESS_DENIED,
                officer=user,
                actor=user,
                portal=portal_key,
                result=C.RESULT_DENY,
                reason="Portal authorization failed",
                request=request,
            )
            audit_service.record_security_event(
                C.EVENT_PORTAL_ACCESS_DENIED,
                severity=C.SEVERITY_WARNING,
                officer=user,
                details={"portal": portal_key},
                request=request,
            )
            return render(
                request,
                "accounts/portal_denied.html",
                {"portal": meta, "portal_key": portal_key},
                status=403,
            )

        # --- Step: success — establish session (rotates the session key) ----
        login_protection_service.clear_failures(user)
        login(request, user, backend="accounts.backends.OfficerBackend")
        session_service.establish(request, user, portal_key)
        # The session key only exists after it is saved; force it so the
        # device/session registry can bind to the real key.
        if not request.session.session_key:
            request.session.save()
        _device, _session_row, device_token = device_session_service.register_login(request, user, portal_key)

        audit_service.record_event(
            C.EVENT_LOGIN_SUCCESS,
            officer=user,
            actor=user,
            portal=portal_key,
            result=C.RESULT_SUCCESS,
            request=request,
        )
        audit_service.record_event(
            C.EVENT_PORTAL_ACCESS,
            officer=user,
            actor=user,
            portal=portal_key,
            result=C.RESULT_ALLOW,
            request=request,
        )
        response = redirect(meta["dashboard_url"])
        if device_token:
            device_session_service.set_device_cookie(response, device_token)
        return response

    return render(request, "accounts/login.html", {"form": form, "portal": meta, "portal_key": portal_key})


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
@require_POST
def portal_logout(request):
    user = request.user
    portal = request.session.get(C.SESSION_PORTAL_KEY, "")
    if user.is_authenticated:
        audit_service.record_event(
            C.EVENT_LOGOUT,
            officer=user,
            actor=user,
            portal=portal,
            result=C.RESULT_SUCCESS,
            request=request,
        )
        device_session_service.close_current(request, C.SESSION_END_LOGOUT)
    logout(request)
    return redirect("portal_selection")


# ---------------------------------------------------------------------------
# Account activation (secure)
# ---------------------------------------------------------------------------
@require_http_methods(["GET", "POST"])
def activate_account(request, uidb64: str, token: str):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Officer.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Officer.DoesNotExist):
        user = None

    if user is None or not default_token_generator.check_token(user, token):
        return render(
            request,
            "accounts/activation_invalid.html",
            {"portal": PORTAL_META[C.PORTAL_GENERAL]},
            status=400,
        )

    if user.account_status == C.ACCOUNT_STATUS_ACTIVE:
        messages.info(request, "This account has already been activated.")
        return redirect("portal_selection")

    form = ActivationForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        if not user.check_password(form.cleaned_data["provisional_password"]):
            form.add_error("provisional_password", "Provisional password is incorrect.")
            return render(
                request, "accounts/activation.html", {"form": form, "user": user}
            )

        user.set_password(form.cleaned_data["new_password"])
        user.account_status = C.ACCOUNT_STATUS_ACTIVE
        user.is_active = True
        user.failed_login_attempts = 0
        user.locked_until = None
        user.save()

        security_code_service.set_secret_code(
            user, form.cleaned_data["new_secret_code"], actor=None
        )

        audit_service.record_event(
            C.EVENT_ACCOUNT_ACTIVATED,
            officer=user,
            actor=user,
            result=C.RESULT_SUCCESS,
            request=request,
        )
        messages.success(request, "Account activated. You may now sign in.")
        return redirect(
            "accounts:login", portal_key=C.PORTAL_GENERAL
        )

    return render(request, "accounts/activation.html", {"form": form, "user": user})


# ---------------------------------------------------------------------------
# Re-authentication gate
# ---------------------------------------------------------------------------
@login_required
@require_http_methods(["GET", "POST"])
def reauth(request):
    user = request.user
    form = ReauthForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        ok_password = user.check_password(form.cleaned_data["password"])
        ok_factor = security_code_service.verify_for(user, form.cleaned_data["secret_code"])
        if ok_password and ok_factor:
            session_service.mark_reauth(request)
            audit_service.record_event(
                C.EVENT_REAUTH_SUCCESS,
                officer=user,
                actor=user,
                result=C.RESULT_SUCCESS,
                request=request,
            )
            nxt = request.session.pop("reauth_next", None)
            return redirect(nxt or "portal_selection")
        audit_service.record_event(
            C.EVENT_REAUTH_FAILURE,
            officer=user,
            actor=user,
            result=C.RESULT_FAILURE,
            request=request,
        )
        form.add_error(None, "Re-authentication failed. Please try again.")

    return render(request, "accounts/reauth.html", {"form": form})


# ---------------------------------------------------------------------------
# Account self-service
# ---------------------------------------------------------------------------
@login_required
def account_profile(request):
    user = request.user
    capabilities = {
        "portals": authorization_service.list_authorized_portals(user),
        "permissions": sorted(authorization_service.get_user_permissions(user)),
    }
    return render(
        request,
        "accounts/profile.html",
        {"officer": user, "capabilities": capabilities},
    )


@login_required
@require_http_methods(["GET", "POST"])
def account_password(request):
    user = request.user
    form = PasswordChangeForm(user, request.POST or None)
    if request.method == "POST" and form.is_valid():
        user.set_password(form.cleaned_data["new_password"])
        user.save()
        update_session_auth_hash(request, user)
        audit_service.record_event(
            C.EVENT_PASSWORD_CHANGED,
            officer=user,
            actor=user,
            result=C.RESULT_SUCCESS,
            request=request,
        )
        messages.success(request, "Password changed.")
        return redirect("account_profile")
    return render(request, "accounts/password.html", {"form": form})


@login_required
@require_http_methods(["GET", "POST"])
def account_security(request):
    user = request.user
    form = SecretCodeForm(user, request.POST or None)
    if request.method == "POST" and form.is_valid():
        security_code_service.set_secret_code(
            user, form.cleaned_data["secret_code"], actor=user
        )
        audit_service.record_event(
            C.EVENT_MFA_CHANGED,
            officer=user,
            actor=user,
            result=C.RESULT_SUCCESS,
            request=request,
        )
        messages.success(request, "Security code updated.")
        return redirect("account_profile")
    return render(
        request,
        "accounts/security.html",
        {"form": form, "configured": user.secret_code_configured},
    )
