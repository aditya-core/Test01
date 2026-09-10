"""User managers for the custom ``Officer`` model."""
from __future__ import annotations

from django.contrib.auth.base_user import BaseUserManager
from django.utils import timezone

from . import constants as C


class OfficerManager(BaseUserManager):
    """Manager for ``Officer``; centralises officer-id normalisation."""

    use_in_migrations = True

    def _normalize_officer_id(self, officer_id: str) -> str:
        return self.normalize_email(officer_id).strip().upper() if officer_id else officer_id

    def create_officer(self, officer_id, email, password, full_name="", **extra):
        """Create a regular officer with a hashed password (never plaintext)."""
        if not officer_id:
            raise ValueError("An Officer ID is required.")
        if not email:
            raise ValueError("An email address is required.")
        email = self.normalize_email(email)
        officer = self.model(
            officer_id=self._normalize_officer_id(officer_id),
            email=email,
            full_name=full_name,
            **extra,
        )
        officer.set_password(password)
        officer.save(using=self._db)
        return officer

    def create_superuser(self, officer_id, email, password, full_name="", **extra):
        """Development-only superuser. Production flows do not depend on it."""
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        extra.setdefault("is_active", True)
        extra.setdefault("account_status", C.ACCOUNT_STATUS_ACTIVE)
        if not extra.get("is_staff") or not extra.get("is_superuser"):
            raise ValueError("Superuser must have is_staff=True and is_superuser=True.")
        return self.create_officer(officer_id, email, password, full_name, **extra)

    def active(self):
        return self.filter(account_status=C.ACCOUNT_STATUS_ACTIVE, is_active=True)

    def locked_out(self):
        return self.filter(locked_until__gt=timezone.now())
