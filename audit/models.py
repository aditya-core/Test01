"""Audit & security-event models.

These tables are the system's memory of WHO did WHAT, WHEN, in WHAT CONTEXT
and with WHAT RESULT. They never contain passwords, secret codes, MFA tokens
or other authentication secrets.
"""
from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models

from accounts import constants as C


class AuditEvent(models.Model):
    """A single auditable occurrence (allowed OR denied)."""

    event_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    event_type = models.CharField(max_length=48, db_index=True)

    # The identity the event is about.
    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_events",
    )
    officer_id_snapshot = models.CharField(max_length=32, blank=True, default="")
    # The identity who *performed* the action (usually the same; differs for
    # admin-provisioning actions).
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="acted_events",
    )

    portal = models.CharField(max_length=16, blank=True, default="")
    resource_type = models.CharField(max_length=48, blank=True, default="")
    resource_id = models.CharField(max_length=64, blank=True, default="")
    action = models.CharField(max_length=48, blank=True, default="")
    result = models.CharField(max_length=16, blank=True, default="")
    reason = models.CharField(max_length=255, blank=True, default="")

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True, default="")
    session_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="SHA-256 of the session key (not the raw cookie).",
    )

    context = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-occurred_at"]
        indexes = [
            models.Index(fields=["event_type", "-occurred_at"]),
            models.Index(fields=["officer", "-occurred_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.event_id} {self.event_type} {self.officer_id_snapshot or '-'}"


class SecurityEvent(models.Model):
    """Aggregated, higher-value security signals for monitoring."""

    event_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    event_type = models.CharField(max_length=48, db_index=True)
    severity = models.CharField(max_length=12, choices=C.SEVERITY_CHOICES, default=C.SEVERITY_INFO)

    officer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_events",
    )
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True, default="")
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-occurred_at"]
        indexes = [
            models.Index(fields=["event_type", "-occurred_at"]),
            models.Index(fields=["severity", "-occurred_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.event_id} {self.severity} {self.event_type}"
