"""Tamper-evident hash chain + structured before/after state.

Existing rows are back-filled into the chain in ``occurred_at, id`` order so
the whole history becomes verifiable; nothing is deleted or rewritten
except the new (previously empty) hash/sequence columns.
"""
from __future__ import annotations

from django.db import migrations, models


def backfill_chain(apps, schema_editor):
    AuditEvent = apps.get_model("audit", "AuditEvent")
    AuditChainHead = apps.get_model("audit", "AuditChainHead")

    # Import lazily so the migration does not depend on model methods.
    from audit.hashing import GENESIS_HASH, compute_event_hash

    head, _ = AuditChainHead.objects.get_or_create(singleton=True)
    prev_hash = head.last_hash or GENESIS_HASH
    seq = head.last_sequence

    qs = AuditEvent.objects.filter(sequence__isnull=True).order_by("occurred_at", "id")
    for event in qs.iterator():
        seq += 1
        fields = {
            "sequence": seq,
            "event_id": str(event.event_id),
            "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
            "event_type": event.event_type,
            "officer_id": event.officer_id,
            "officer_id_snapshot": event.officer_id_snapshot,
            "actor_id": event.actor_id,
            "portal": event.portal,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "action": event.action,
            "result": event.result,
            "reason": event.reason,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
            "session_id": event.session_id,
            "context": event.context,
        }
        current = compute_event_hash(prev_hash, fields)
        AuditEvent.objects.filter(pk=event.pk).update(
            sequence=seq, previous_hash=prev_hash, current_hash=current
        )
        prev_hash = current

    head.last_sequence = seq
    head.last_hash = prev_hash if seq else ""
    head.save()


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("audit", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuditChainHead",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("singleton", models.BooleanField(default=True, editable=False, unique=True)),
                ("last_sequence", models.PositiveBigIntegerField(default=0)),
                ("last_hash", models.CharField(blank=True, default="", max_length=80)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"verbose_name": "audit chain head"},
        ),
        migrations.AddField(
            model_name="auditevent",
            name="previous_state",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="auditevent",
            name="new_state",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="auditevent",
            name="sequence",
            field=models.PositiveBigIntegerField(blank=True, editable=False, null=True, unique=True),
        ),
        migrations.AddField(
            model_name="auditevent",
            name="previous_hash",
            field=models.CharField(blank=True, default="", editable=False, max_length=80),
        ),
        migrations.AddField(
            model_name="auditevent",
            name="current_hash",
            field=models.CharField(blank=True, db_index=True, default="", editable=False, max_length=80),
        ),
        migrations.RunPython(backfill_chain, noop),
    ]
