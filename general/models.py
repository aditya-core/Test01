"""General portal case and evidence models."""
from __future__ import annotations

import os
from uuid import uuid4

from django.conf import settings
from django.db import models
from django.utils import timezone


def case_storage_path(instance, filename):
    base, ext = os.path.splitext(filename)
    safe_base = base.replace(" ", "_")
    unique_name = f"{safe_base}-{uuid4().hex}{ext}"
    case_id = getattr(getattr(instance, "case", None), "case_id", "UNASSIGNED")
    return os.path.join("cases", str(case_id), unique_name)


def _generate_case_id() -> str:
    date_prefix = timezone.localdate().strftime("%Y%m%d")
    seq = 1
    while True:
        candidate = f"CASE-{date_prefix}-{seq:04d}"
        if not CaseRecord.objects.filter(case_id=candidate).exists():
            return candidate
        seq += 1


class CaseRecord(models.Model):
    STATUS_OPEN = "Open"
    STATUS_IN_PROGRESS = "In Progress"
    STATUS_PENDING = "Pending"
    STATUS_CLOSED = "Closed"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_IN_PROGRESS, "In Progress"),
        (STATUS_PENDING, "Pending"),
        (STATUS_CLOSED, "Closed"),
    ]

    case_id = models.CharField(max_length=32, unique=True, editable=False)
    title = models.CharField(max_length=200)
    case_type = models.CharField(max_length=80)
    police_station = models.CharField(max_length=150, blank=True)
    investigating_agency = models.CharField(max_length=150, blank=True)
    incident_date = models.DateField()
    location = models.CharField(max_length=200, blank=True)
    summary = models.TextField(blank=True)
    complainant_name = models.CharField(max_length=160, blank=True)
    complainant_contact = models.CharField(max_length=50, blank=True)
    status = models.CharField(max_length=24, choices=STATUS_CHOICES, default=STATUS_OPEN)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="cases")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    fir_document = models.FileField(upload_to=case_storage_path, blank=True, null=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]

    def save(self, *args, **kwargs):
        if not self.case_id:
            self.case_id = _generate_case_id()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.case_id} - {self.title}"

    @property
    def recent_activity(self):
        return self.updated_at or self.created_at



class CaseEvidenceFile(models.Model):
    case = models.ForeignKey(CaseRecord, on_delete=models.CASCADE, related_name="evidence_files")
    file = models.FileField(upload_to=case_storage_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["uploaded_at"]

    def __str__(self) -> str:
        return f"{self.case.case_id} - {self.file.name}"
