"""Tamper-evident hash chain for the audit trail.

Each ``AuditEvent`` stores ``previous_hash`` (the ``current_hash`` of the
event before it) and ``current_hash`` (a SHA-256 over its own canonical
payload + ``previous_hash``). Editing or deleting any historical row breaks
the chain from that point onwards, which ``verify_chain`` detects.

This is a tamper-*evident* mechanism, not a tamper-*proof* one: it makes
silent modification detectable. It is deliberately simple — reliability of
the audit write path matters more than cryptographic sophistication.

The algorithm is versioned (``HASH_VERSION``) so it can evolve without
invalidating the verification of older rows.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

HASH_VERSION = "v1"
GENESIS_HASH = "0" * 64


def canonical_payload(fields: Mapping[str, Any]) -> str:
    """Deterministic JSON representation of the hashed fields."""
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)


def compute_event_hash(previous_hash: str, fields: Mapping[str, Any]) -> str:
    """Return ``<version>$<sha256hex>`` for the event payload."""
    digest = hashlib.sha256()
    digest.update((previous_hash or GENESIS_HASH).encode("utf-8"))
    digest.update(b"|")
    digest.update(canonical_payload(fields).encode("utf-8"))
    return f"{HASH_VERSION}${digest.hexdigest()}"


def event_hash_fields(event) -> dict:
    """The subset of an ``AuditEvent`` that participates in the hash.

    Mutable bookkeeping columns (the hash columns themselves) are excluded.
    ``occurred_at`` is rendered in ISO-8601 so the value is stable regardless
    of database driver precision.
    """
    occurred = event.occurred_at
    return {
        "sequence": event.sequence,
        "event_id": str(event.event_id),
        "occurred_at": occurred.isoformat() if occurred else None,
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
