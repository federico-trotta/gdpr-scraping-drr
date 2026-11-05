"""Data-subject rights as code: erasure (Art. 17) and rectification (Art. 16).

Article section: "Erasure and Rectification Keyed on the Pseudonym".

The raw identifier is never stored, so lookups re-derive the keyed token from
the identifier the data subject supplies. This only works if INGESTION uses the
same derivation: always key stored rows with ``_derive_token()`` (see
``insert_record()``), not with a per-entity random Presidio salt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from operators import load_hash_salt

logger = logging.getLogger("scrape.rights")

DEFAULT_DB = "pipeline.db"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")
QUARANTINE_DAYS = 30


# --------------------------------------------------------------------------- #
# Token derivation and DB helpers
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def _salt() -> bytes:
    """Load ``PII_HASH_SALT`` once (fails fast with RuntimeError)."""
    return load_hash_salt().encode("utf-8")


def _normalize(raw_identifier: str) -> str:
    """Canonical form used at ingestion AND at request time.

    Trims whitespace and lower-cases, so "Jane@Example.com " and
    "jane@example.com" map to the same token. Adjust per identifier type
    (e.g. E.164 for phone numbers) and apply identically everywhere.
    """
    return raw_identifier.strip().lower()


def _derive_token(raw_identifier: str) -> str:
    """Deterministic HMAC-SHA-256 token - same as ingestion time.

    Raises:
        ValueError: on an empty identifier (would collide across subjects).
        RuntimeError: if ``PII_HASH_SALT`` is missing or too short.
    """
    if raw_identifier is None or not str(raw_identifier).strip():
        raise ValueError("Identifier must be a non-empty string")
    return hmac.new(
        _salt(), _normalize(raw_identifier).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _prefix(token: str) -> str:
    """Partial token for logs - never log the full hash."""
    return token[:8] + "…"


def init_db(db_path: str = DEFAULT_DB) -> None:
    """Create all tables from ``schema.sql`` (idempotent)."""
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    logger.info("Schema ensured at %s", db_path)


def insert_record(
    raw_identifier: str,
    payload: str,
    *,
    sink: str = "pseudonymized",
    source_domain: str | None = None,
    db_path: str = DEFAULT_DB,
) -> str:
    """Store an already-redacted payload keyed on the derived token.

    ``payload`` must have passed DRR and routing. Returns the token.
    """
    token = _derive_token(raw_identifier)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO scrape_records (pseudonym, sink, source_domain, payload)"
            " VALUES (?, ?, ?, ?)",
            (token, sink, source_domain, payload),
        )
    return token


# --------------------------------------------------------------------------- #
# Art. 17 erasure
# --------------------------------------------------------------------------- #
def handle_erasure(
    raw_identifier: str,
    reason: str,
    db_path: str = DEFAULT_DB,
) -> dict:
    """Art. 17 erasure handler.

    Steps (single transaction - all or nothing):
      1. Derive the pseudonym token from the raw identifier.
      2. Copy live rows to quarantine with a 30-day expiry (backup window),
         and cap any pre-existing quarantine rows for the token at the same
         expiry so nothing survives indefinitely.
      3. Delete from ``scrape_records`` and ``aggregates``.
      4. ``INSERT OR IGNORE`` into ``suppression_list`` so the scrape loop never
         re-collects (idempotent on repeated requests).
      5. Append an ``erasure_log`` row with the token and row counts only.

    Returns:
        ``{"pseudonym", "erased_at", "rows": {...}}`` where ``rows`` holds
        ``quarantined``, ``quarantine_expiry_capped``, ``scrape_records_deleted``,
        ``aggregates_deleted``, ``suppression_added`` (0 if already suppressed).

    Backups and log sinks outside this database are NOT reached by this
    function - your retention schedule must cover them.
    """
    token = _derive_token(raw_identifier)
    now = datetime.now(timezone.utc).isoformat()
    stats: dict = {"pseudonym": token, "erased_at": now, "rows": {}}
    rows_stats = stats["rows"]
    expiry_modifier = f"+{QUARANTINE_DAYS} days"

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        # Cap pre-existing quarantine rows first, so step 2's copies aren't counted.
        cur = conn.execute(
            """
            UPDATE quarantine
               SET quarantine_expires_at = datetime('now', ?)
             WHERE pseudonym = ?
               AND quarantine_expires_at > datetime('now', ?)
            """,
            (expiry_modifier, token, expiry_modifier),
        )
        rows_stats["quarantine_expiry_capped"] = cur.rowcount

        rows = conn.execute(
            "SELECT payload FROM scrape_records WHERE pseudonym = ?", (token,)
        ).fetchall()
        conn.executemany(
            """
            INSERT INTO quarantine
                (pseudonym, payload, quarantine_reason, quarantine_at,
                 quarantine_expires_at)
            VALUES (?, ?, ?, ?, datetime('now', ?))
            """,
            [(token, r["payload"], f"Art.17 erasure: {reason}", now, expiry_modifier)
             for r in rows],
        )
        rows_stats["quarantined"] = len(rows)

        cur = conn.execute("DELETE FROM scrape_records WHERE pseudonym = ?", (token,))
        rows_stats["scrape_records_deleted"] = cur.rowcount

        cur = conn.execute("DELETE FROM aggregates WHERE pseudonym = ?", (token,))
        rows_stats["aggregates_deleted"] = cur.rowcount

        cur = conn.execute(
            "INSERT OR IGNORE INTO suppression_list (pseudonym, reason, added_at)"
            " VALUES (?, ?, ?)",
            (token, f"Art.17 erasure: {reason}", now),
        )
        rows_stats["suppression_added"] = cur.rowcount

        conn.execute(
            "INSERT INTO erasure_log (pseudonym, erased_at, rows_deleted)"
            " VALUES (?, ?, ?)",
            (token, now, json.dumps(rows_stats)),
        )
        conn.commit()

    logger.info("erasure_complete pseudonym=%s rows=%s", _prefix(token), rows_stats)
    return stats


# --------------------------------------------------------------------------- #
# Art. 16 rectification
# --------------------------------------------------------------------------- #
def handle_rectification(
    old_raw_identifier: str,
    new_raw_identifier: str,
    db_path: str = DEFAULT_DB,
) -> dict:
    """Art. 16 rectification handler.

    Re-derives a new token from the corrected identifier and migrates every
    stored pseudonym (records, aggregates, quarantine, suppression) from the old
    token to the new one. Does NOT delete data - it re-keys it.

    Returns ``{"status": "noop", "reason": "tokens_identical"}`` when the
    corrected input normalizes to the same token (e.g. only case changed).
    """
    old_token = _derive_token(old_raw_identifier)
    new_token = _derive_token(new_raw_identifier)

    if hmac.compare_digest(old_token, new_token):
        logger.info("rectification_noop pseudonym=%s", _prefix(old_token))
        return {"status": "noop", "reason": "tokens_identical"}

    now = datetime.now(timezone.utc).isoformat()
    stats: dict = {
        "status": "rectified",
        "old_token_prefix": old_token[:8],
        "new_token_prefix": new_token[:8],
    }

    with sqlite3.connect(db_path) as conn:
        for table in ("scrape_records", "aggregates", "quarantine"):
            cur = conn.execute(
                f"UPDATE {table} SET pseudonym = ? WHERE pseudonym = ?",  # noqa: S608
                (new_token, old_token),
            )
            stats[f"{table}_rewritten"] = cur.rowcount

        # Suppression is keyed by PRIMARY KEY: migrate without colliding if the
        # new token is already suppressed, then drop the old entry.
        cur = conn.execute(
            "UPDATE OR IGNORE suppression_list SET pseudonym = ? WHERE pseudonym = ?",
            (new_token, old_token),
        )
        stats["suppression_migrated"] = cur.rowcount
        conn.execute("DELETE FROM suppression_list WHERE pseudonym = ?", (old_token,))

        conn.execute(
            "INSERT INTO erasure_log (pseudonym, erased_at, rows_deleted)"
            " VALUES (?, ?, ?)",
            (f"RECTIFICATION:{old_token}→{new_token}", now, json.dumps(stats)),
        )
        conn.commit()

    logger.info("rectification_complete stats=%s", stats)
    return stats


# --------------------------------------------------------------------------- #
# Quarantine expiry
# --------------------------------------------------------------------------- #
def sweep_expired_quarantine(db_path: str = DEFAULT_DB) -> int:
    """Delete quarantine rows whose ``quarantine_expires_at`` has passed.

    Run nightly (cron, scheduler). Returns the number of rows deleted.
    """
    with sqlite3.connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM quarantine WHERE quarantine_expires_at < datetime('now')"
        )
        deleted = cur.rowcount
        conn.commit()
    logger.info("quarantine_sweep deleted=%d", deleted)
    return deleted


if __name__ == "__main__":
    import os
    import tempfile

    logging.basicConfig(level=logging.INFO)
    os.environ.setdefault("PII_HASH_SALT", "demo-only-salt-not-for-production")

    db = os.path.join(tempfile.mkdtemp(), "pipeline.db")
    init_db(db)

    # Fictional fixtures only.
    t = insert_record("jane@example.com", "[PERSON] translator, MEM-******", db_path=db)
    with sqlite3.connect(db) as c:
        c.execute("INSERT INTO aggregates (pseudonym, metric, value) VALUES (?, 'listings', 1)", (t,))

    print(handle_rectification("jane@example.com", "Jane@Example.com", db))
    print(handle_rectification("jane@example.com", "jane.smith@example.com", db))
    print(handle_erasure("jane.smith@example.com", "data subject request", db))
    print(handle_erasure("jane.smith@example.com", "repeat request", db))  # idempotent
    print("swept:", sweep_expired_quarantine(db))
