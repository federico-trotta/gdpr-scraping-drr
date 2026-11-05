"""Objection and the re-scrape loop: suppression checked inside every fetch cycle.

Article section: "Objection, and the Re-Scrape Loop That Defeats It".

An Art. 21(1) objection or an Art. 17 erasure is only durable if the scraper
checks the suppression list *before each fetch*, every cycle - not once at
intake. Otherwise the next run quietly recreates the data you deleted.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator
from urllib.parse import urlparse

from rights import DEFAULT_DB, _derive_token

logger = logging.getLogger("scrape.suppression")

# Fictional example directory: profile URLs look like
#   https://directory.example/members/MEM-123456
_MEMBER_PATH = re.compile(r"/members/(MEM-\d{6})(?:[/?#]|$)")


@dataclass
class ScrapeSession:
    """Per-run counters. Holds domains and counts only - never identifiers."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    ended_at: str | None = None
    fetched: int = 0
    skipped_suppressed: int = 0
    unidentifiable: int = 0
    fetch_errors: int = 0
    per_domain_hits: Counter = field(default_factory=Counter)   # fetched
    per_domain_skips: Counter = field(default_factory=Counter)  # suppressed

    def log_summary(self) -> None:
        """Emit one end-of-run summary line (metadata only)."""
        logger.info(
            "scrape_session_summary session=%s started=%s ended=%s fetched=%d "
            "skipped_suppressed=%d unidentifiable=%d fetch_errors=%d "
            "hits_by_domain=%s skips_by_domain=%s",
            self.session_id, self.started_at, self.ended_at, self.fetched,
            self.skipped_suppressed, self.unidentifiable, self.fetch_errors,
            dict(self.per_domain_hits), dict(self.per_domain_skips),
        )


def extract_identifier_from_url(url: str) -> str | None:
    """Extract the subject identifier a URL points to, BEFORE fetching it.

    STUB - replace with the logic for each source you scrape. This version
    only understands the fictional pattern ``/members/MEM-NNNNNN``.

    Contract:
      * Return the raw identifier in the same form used at ingestion, so
        ``rights._derive_token()`` yields the same token.
      * Return ``None`` when the URL does not reveal an identifier (e.g. a
        search-results page). The loop then decides via
        ``skip_unidentifiable``; consider a post-fetch check for such pages.
      * Must not log the URL or the identifier.
    """
    if not url:
        return None
    match = _MEMBER_PATH.search(urlparse(url).path + "/")
    return match.group(1) if match else None


def is_suppressed(token: str, conn: sqlite3.Connection) -> bool:
    """Return True if the token is on the suppression list."""
    return (
        conn.execute(
            "SELECT 1 FROM suppression_list WHERE pseudonym = ? LIMIT 1", (token,)
        ).fetchone()
        is not None
    )


def scrape_with_suppression_check(
    urls: Iterable[str],
    fetch: Callable[[str], str],
    *,
    session: ScrapeSession | None = None,
    db_path: str = DEFAULT_DB,
    skip_unidentifiable: bool = False,
) -> Iterator[tuple[str, str]]:
    """Yield ``(url, raw_body)`` for every URL that is not suppressed.

    The suppression list is queried per URL on a live connection, so an
    erasure processed mid-run takes effect on the next URL. Skips are counted
    per domain; the session summary is logged when the generator finishes or
    is closed early. Raw bodies must go straight into the DRR pipeline.

    Args:
        urls: candidate URLs for this cycle.
        fetch: callable returning the raw response body for a URL.
        session: counters object; pass your own instance to read the
            counters afterwards (a private one is created if omitted).
        skip_unidentifiable: fail closed on URLs with no extractable
            identifier instead of fetching them.
    """
    if session is None:
        session = ScrapeSession()
    conn = sqlite3.connect(db_path)
    try:
        for url in urls:
            domain = urlparse(url).netloc or "<unknown>"
            identifier = extract_identifier_from_url(url)

            if identifier is None:
                session.unidentifiable += 1
                if skip_unidentifiable:
                    continue
            elif is_suppressed(_derive_token(identifier), conn):
                session.skipped_suppressed += 1
                session.per_domain_skips[domain] += 1
                logger.debug("Suppressed identifier skipped domain=%s", domain)
                continue
            del identifier

            try:
                body = fetch(url)
            except Exception as exc:  # noqa: BLE001
                session.fetch_errors += 1
                # Class name only: messages can embed URLs or bodies.
                logger.warning("Fetch failed (%s) domain=%s", type(exc).__name__, domain)
                continue

            session.fetched += 1
            session.per_domain_hits[domain] += 1
            yield url, body
    finally:
        conn.close()
        session.ended_at = datetime.now(timezone.utc).isoformat()
        session.log_summary()


if __name__ == "__main__":
    import os
    import tempfile

    from rights import handle_erasure, init_db

    logging.basicConfig(level=logging.INFO)
    os.environ.setdefault("PII_HASH_SALT", "demo-only-salt-not-for-production")

    db = os.path.join(tempfile.mkdtemp(), "pipeline.db")
    init_db(db)
    handle_erasure("MEM-123456", "Art.21 objection", db)  # fictional subject

    urls = [
        "https://directory.example/members/MEM-123456",   # suppressed
        "https://directory.example/members/MEM-654321",
        "https://other.example/members/MEM-111111",
        "https://directory.example/search?q=translators",  # unidentifiable
    ]
    session = ScrapeSession()
    for url, body in scrape_with_suppression_check(
        urls, fetch=lambda u: "<html>fictional</html>", session=session, db_path=db
    ):
        pass
    print(session)
