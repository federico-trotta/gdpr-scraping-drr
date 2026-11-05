-- Demo schema for pipeline.db (SQLite). Safe to run repeatedly.
--
-- Every identifier column holds a keyed HMAC-SHA-256 token (rights._derive_token),
-- never a raw identifier. Erasure and rectification look rows up by that token.

PRAGMA foreign_keys = ON;

-- Live records written by the DRR pipeline after routing.
CREATE TABLE IF NOT EXISTS scrape_records (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    pseudonym      TEXT    NOT NULL,
    sink           TEXT    NOT NULL DEFAULT 'pseudonymized'
                   CHECK (sink IN ('non-personal', 'pseudonymized', 'quarantine')),
    source_domain  TEXT,
    payload        TEXT    NOT NULL,          -- redacted / transformed text only
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scrape_records_pseudonym ON scrape_records (pseudonym);

-- Downstream rollups keyed on the same token.
CREATE TABLE IF NOT EXISTS aggregates (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pseudonym  TEXT NOT NULL,
    metric     TEXT NOT NULL,
    value      REAL
);
CREATE INDEX IF NOT EXISTS idx_aggregates_pseudonym ON aggregates (pseudonym);

-- Restricted processing area: uncertain records and post-erasure backup window.
-- quarantine_expires_at uses SQLite datetime format ('YYYY-MM-DD HH:MM:SS', UTC)
-- so rights.sweep_expired_quarantine() can compare it with datetime('now').
CREATE TABLE IF NOT EXISTS quarantine (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    pseudonym              TEXT NOT NULL,
    payload                TEXT NOT NULL,
    quarantine_reason      TEXT NOT NULL,
    quarantine_at          TEXT NOT NULL,
    quarantine_expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_pseudonym ON quarantine (pseudonym);
CREATE INDEX IF NOT EXISTS idx_quarantine_expires   ON quarantine (quarantine_expires_at);

-- Checked inside the fetch loop on every scrape cycle (Art. 17 / Art. 21).
CREATE TABLE IF NOT EXISTS suppression_list (
    pseudonym  TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,
    added_at   TEXT NOT NULL
);

-- Audit trail for erasure and rectification. Tokens and counts only.
CREATE TABLE IF NOT EXISTS erasure_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    pseudonym     TEXT NOT NULL,
    erased_at     TEXT NOT NULL,
    rows_deleted  TEXT NOT NULL               -- JSON row-count stats
);
