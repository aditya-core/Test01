"""Forms for authentication, provisioning and account self-service.

Validation happens server-side; forms never carry authorization weight.
"""
from __future__ import annotations

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from . import constants as C
from .models import (
    ClearanceLevel,
    Department,
    Designation,
    OrganizationUnit,
    Portal,
    Role,
)
from .services import SecurityCodeService

Officer = get_user_model()

SECRET_CODE_HELP = "The organization-issued security code (your second factor)."
NEW_SECRET_CODE_HELP = (
    "Choose a new security code (6–32 characters, letters and digits). "
    "Store it securely — it is never shown again and never stored in plaintext."
)


def validate_secret_code(value: str):
    if not (6 <= len(value) <= 32):
        raise ValidationError("Security code must be 6–32 characters long.")
    if not value.replace("-", "").replace("_", "").isalnum():
        raise ValidationError("Use letters and digits only.")


class PortalLoginForm(forms.Form):
    """Multi-step login: officer ID → password → secret code (single card)."""

    officer_id = forms.CharField(
        label="Officer ID",
        max_length=32,
        widget=forms.TextInput(attrs={"autocomplete": "username", "autofocus": True}),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
    secret_code = forms.CharField(
        label="Security Code / MFA",
        widget=forms.PasswordInput(attrs={"autocomplete": "one-time-code"}),
        help_text=SECRET_CODE_HELP,
    )

    def clean_officer_id(self):
        value = self.cleaned_data["officer_id"].strip().upper()
        if not value:
            raise ValidationError("Officer ID is required.")
        return value


class ActivationForm(forms.Form):
    """Secure activation: prove the provisional password, then set a new
    password and a new secret code."""

    provisional_password = forms.CharField(
        label="Provisional password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
    new_password = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    confirm_password = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    new_secret_code = forms.CharField(
        label="New security code",
        widget=forms.PasswordInput(attrs={"autocomplete": "one-time-code"}),
        help_text=NEW_SECRET_CODE_HELP,
    )

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("new_password")
        p2 = cleaned.get("confirm_password")
        if p1 and p2 and p1 != p2:
            raise ValidationError("Passwords do not match.")
        return cleaned


class PasswordChangeForm(forms.Form):
    current_password = forms.CharField(
        label="Current password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
    new_password = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    confirm_password = forms.CharField(
        label="Confirm new password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        value = self.cleaned_data["current_password"]
        if not self.user.check_password(value):
            raise ValidationError("Current password is incorrect.")
        return value

    def clean_new_password(self):
        value = self.cleaned_data["new_password"]
        validate_password(value, self.user)
        return value

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("new_password") and cleaned.get("confirm_password"):
            if cleaned["new_password"] != cleaned["confirm_password"]:
                raise ValidationError("Passwords do not match.")
        return cleaned


class SecretCodeForm(forms.Form):
    """Set / change the second factor. Re-verifies the password first."""

    password = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
    secret_code = forms.CharField(
        label="New security code",
        widget=forms.PasswordInput(attrs={"autocomplete": "one-time-code"}),
        help_text=NEW_SECRET_CODE_HELP,
        validators=[validate_secret_code],
    )
    confirm_secret_code = forms.CharField(
        label="Confirm security code",
        widget=forms.PasswordInput(attrs={"autocomplete": "one-time-code"}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        value = self.cleaned_data["password"]
        if not self.user.check_password(value):
            raise ValidationError("Password is incorrect.")
        return value

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("secret_code") and cleaned.get("confirm_secret_code"):
            if cleaned["secret_code"] != cleaned["confirm_secret_code"]:
                raise ValidationError("Security codes do not match.")
        return cleaned


class ReauthForm(forms.Form):
    """Re-verification before a sensitive operation."""

    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
    secret_code = forms.CharField(
        label="Security Code / MFA",
        widget=forms.PasswordInput(attrs={"autocomplete": "one-time-code"}),
    )


# ---------------------------------------------------------------------------
# Provisioning forms (Central IT only)
# ---------------------------------------------------------------------------
class OfficerCreateForm(forms.ModelForm):
    """Single-page provisioning form (kept for API/test compatibility; the
    portal UI uses the stepped ``it_admin.forms`` wizard)."""

    class Meta:
        model = Officer
        fields = [
            "officer_id",
            "employee_id",
            "email",
            "full_name",
            "designation",
            "phone",
            "role",
            "clearance",
            "unit",
        ]

    officer_id = forms.CharField(
        label="Officer ID",
        required=False,
        help_text="Leave blank to auto-generate a unique Officer ID.",
    )
    # Legacy compatibility: older callers post ``department`` / ``rank`` as
    # free text. Values matching an active registry row are resolved to it;
    # anything else is preserved verbatim as a descriptive label.
    department = forms.CharField(required=False, help_text="Department code, name or ID.")
    rank = forms.CharField(required=False, max_length=64)
    initial_password = forms.CharField(
        label="Initial password",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="Officer will set their own password during activation.",
    )
    initial_secret_code = forms.CharField(
        label="Initial security code",
        required=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "off"}),
        help_text=NEW_SECRET_CODE_HELP,
    )
    portals = forms.ModelMultipleChoiceField(
        queryset=Portal.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
    )
    reason = forms.CharField(
        label="Provisioning reason",
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "e.g. New posting — Investigation Unit"}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].queryset = Role.objects.all()
        self.fields["clearance"].queryset = ClearanceLevel.objects.all()
        self.fields["unit"].queryset = OrganizationUnit.objects.filter(is_active=True).select_related("organization")
        self.fields["designation"].queryset = Designation.objects.filter(is_active=True)

    def clean_officer_id(self):
        value = self.cleaned_data["officer_id"].strip().upper()
        if not value:
            return ""
        if Officer.objects.filter(officer_id__iexact=value).exists():
            raise ValidationError("Officer ID already exists.")
        return value

    def clean_department(self):
        value = (self.cleaned_data.get("department") or "").strip()
        if not value:
            return None
        from django.db.models import Q

        lookup = Q(code__iexact=value) | Q(name__iexact=value)
        if value.isdigit():
            lookup |= Q(pk=int(value))
        match = Department.objects.filter(lookup).first()
        if match is None:
            return value  # legacy free-text label
        if not match.is_active:
            raise ValidationError("Selected department is not available.")
        return match

    def clean(self):
        cleaned = super().clean()
        rank = (cleaned.get("rank") or "").strip()
        if rank and not cleaned.get("designation"):
            cleaned["designation"] = Designation.objects.filter(name__iexact=rank, is_active=True).first()
        cleaned["rank"] = rank
        return cleaned

    def clean_employee_id(self):
        value = (self.cleaned_data.get("employee_id") or "").strip().upper()
        if value and Officer.objects.filter(employee_id__iexact=value).exists():
            raise ValidationError("Employee ID already exists.")
        return value

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if Officer.objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with this email already exists.")
        return email

    def clean_initial_password(self):
        value = self.cleaned_data["initial_password"]
        validate_password(value)
        return value


class OfficerEditForm(forms.ModelForm):
    """Central IT edits authorization attributes (role/clearance/unit)."""

    class Meta:
        model = Officer
        fields = ["full_name", "email", "phone", "designation", "department", "role", "clearance", "unit"]

    portals = forms.ModelMultipleChoiceField(
        queryset=Portal.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        officer = kwargs.get("instance")
        if officer:
            self.fields["portals"].initial = list(
                officer.portal_accesses.filter(revoked_at__isnull=True).values_list(
                    "portal_id", flat=True
                )
            )


class OfficerStatusForm(forms.Form):
    STATUS_ACTIONS = (
        (C.ACCOUNT_STATUS_ACTIVE, "Activate"),
        (C.ACCOUNT_STATUS_SUSPENDED, "Suspend"),
        (C.ACCOUNT_STATUS_DISABLED, "Disable"),
        (C.ACCOUNT_STATUS_DEACTIVATED, "Deactivate"),
    )
    status = forms.ChoiceField(choices=STATUS_ACTIONS)
    reason = forms.CharField(max_length=255, required=False)
