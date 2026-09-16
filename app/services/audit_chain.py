"""Hash-chained audit log (foundation for HU19).

Each entry stores the SHA-256 hash of its own payload concatenated with the
previous entry's hash. Recomputing the chain end-to-end detects any entry that
was altered or deleted after the fact — the log doesn't prevent tampering, it
makes it detectable.

Payloads must never contain secrets or free-text identifiers (service names,
emails): only UUIDs and enums. This is deliberate so that deleting a user's
account (Ley 21.719 right to erasure) never has to touch, and therefore never
has to break, the chain — the user_id simply stops mapping to a real person.
"""

import hashlib
import json

from app.services.db_client import get_supabase_admin

GENESIS = "0" * 64


def compute_hash(prev_hash: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def append_entry(table: str, payload: dict) -> dict:
    admin = get_supabase_admin()
    last = (
        admin.table(table)
        .select("entry_hash")
        .order("seq", desc=True)
        .limit(1)
        .execute()
    )
    prev_hash = last.data[0]["entry_hash"] if last.data else GENESIS
    entry_hash = compute_hash(prev_hash, payload)

    row = {**payload, "prev_hash": prev_hash, "entry_hash": entry_hash}
    result = admin.table(table).insert(row).execute()
    return result.data[0] if result.data else row


def verify_chain(table: str) -> tuple[bool, str | None]:
    """Recompute the whole chain. Returns (True, None) if intact, or
    (False, <id of the first broken entry>) otherwise."""
    admin = get_supabase_admin()
    result = admin.table(table).select("*").order("seq").execute()

    prev_hash = GENESIS
    for row in result.data:
        payload = {
            k: v
            for k, v in row.items()
            if k not in ("id", "seq", "prev_hash", "entry_hash", "created_at")
        }
        if row["prev_hash"] != prev_hash:
            return False, row["id"]
        expected = compute_hash(prev_hash, payload)
        if row["entry_hash"] != expected:
            return False, row["id"]
        prev_hash = row["entry_hash"]

    return True, None


__all__ = ["GENESIS", "compute_hash", "append_entry", "verify_chain"]
