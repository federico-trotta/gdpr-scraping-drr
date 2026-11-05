"""Art. 14 notices: per-domain collection metadata and a plain-text disclosure.

Article section: "The Art. 14 Notice Nobody Ever Schedules".

When data is not obtained from the data subject, Art. 14(3)(a) requires the
information within a reasonable period, at the latest within one month. The
Art. 14(5)(b) "disproportionate effort" exemption is read narrowly and, where
it applies, still requires appropriate measures including making the
information publicly available. ``exemption_basis`` records that reasoning; it
does not switch the duty off.

Collection events hold metadata only: domains, counts, categories, dates.
Never identifiers or record contents.
"""

from __future__ import annotations

import calendar
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from suppression import ScrapeSession

logger = logging.getLogger("scrape.notices")

DEFAULT_EVENT_LOG = "collection_events.jsonl"


def _add_one_month(d: date) -> date:
    """Same day next month, clamped to month end (31 Jan -> 28/29 Feb)."""
    year, month = (d.year + 1, 1) if d.month == 12 else (d.year, d.month + 1)
    return date(year, month, min(d.day, calendar.monthrange(year, month)[1]))


@dataclass
class CollectionEvent:
    """Everything an Art. 14 notice needs for one source domain in one run."""

    # Who
    controller_name: str
    controller_contact: str
    # What / why
    source_domain: str
    purposes: list[str]
    lawful_basis: str                       # e.g. "Art. 6(1)(f) legitimate interests"
    data_categories: list[str]              # e.g. ["business contact email (hashed)"]
    records_collected: int
    # When / how long
    retention_period_days: int
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    session_id: str | None = None
    # Optional Art. 14(1)/(2) items
    dpo_contact: str | None = None
    eu_representative: str | None = None    # Art. 27, if applicable
    legitimate_interests: str | None = None # required when relying on 6(1)(f)
    recipients: list[str] = field(default_factory=list)
    third_country_transfers: list[str] = field(default_factory=list)
    source_publicly_accessible: bool = True
    automated_decision_making: bool = False
    exemption_basis: str | None = None      # Art. 14(5) reasoning, if claimed

    def __post_init__(self) -> None:
        if not self.source_domain:
            raise ValueError("source_domain is required")
        if self.records_collected < 0:
            raise ValueError("records_collected cannot be negative")
        if self.retention_period_days <= 0:
            raise ValueError("retention_period_days must be positive")
        if "6(1)(f)" in self.lawful_basis and not self.legitimate_interests:
            raise ValueError("legitimate_interests must be stated for Art. 6(1)(f)")

    @property
    def notice_due_by(self) -> str:
        """Latest notice date: one month after collection (Art. 14(3)(a))."""
        collected = datetime.fromisoformat(self.collected_at).date()
        return _add_one_month(collected).isoformat()


def emit_collection_event(
    event: CollectionEvent,
    path: str | Path = DEFAULT_EVENT_LOG,
) -> dict:
    """Append the event as one JSON line and return the serialized dict.

    Events with ``records_collected == 0`` are skipped (nothing to notify).
    """
    record = {**asdict(event), "notice_due_by": event.notice_due_by}
    if event.records_collected == 0:
        logger.debug("No records for domain=%s; event not emitted", event.source_domain)
        return record

    with Path(path).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    logger.info(
        "collection_event domain=%s records=%d notice_due_by=%s exemption=%s",
        event.source_domain, event.records_collected, event.notice_due_by,
        bool(event.exemption_basis),
    )
    return record


def _bullets(items: list[str], empty: str) -> str:
    return "\n".join(f"  - {i}" for i in items) if items else f"  - {empty}"


def generate_art14_notice(event: CollectionEvent) -> str:
    """Render a plain-text Art. 14 disclosure from a ``CollectionEvent``.

    A template, not legal advice: have the wording reviewed for your context.
    """
    lines = [
        f"PRIVACY NOTICE - INFORMATION NOT OBTAINED FROM YOU (GDPR Art. 14)",
        f"Notice due by: {event.notice_due_by}",
        "",
        "1. Who we are",
        f"  Controller: {event.controller_name} ({event.controller_contact})",
    ]
    if event.dpo_contact:
        lines.append(f"  Data Protection Officer: {event.dpo_contact}")
    if event.eu_representative:
        lines.append(f"  EU representative (Art. 27): {event.eu_representative}")

    lines += [
        "",
        "2. Why we process your data and on what basis",
        _bullets(event.purposes, "purpose not specified"),
        f"  Lawful basis: {event.lawful_basis}",
    ]
    if event.legitimate_interests:
        lines.append(f"  Our legitimate interests: {event.legitimate_interests}")

    lines += [
        "",
        "3. Categories of personal data",
        _bullets(event.data_categories, "not specified"),
        "",
        "4. Source",
        f"  {event.source_domain}"
        + (" (a publicly accessible source)" if event.source_publicly_accessible else ""),
        "",
        "5. Recipients",
        _bullets(event.recipients, "No recipients outside our organisation"),
        "",
        "6. Transfers outside the EEA",
        _bullets(event.third_country_transfers, "None"),
        "",
        "7. Retention",
        f"  We keep this data for {event.retention_period_days} days, then delete it.",
        "",
        "8. Your rights",
        "  You may request access (Art. 15), rectification (Art. 16), erasure",
        "  (Art. 17), restriction (Art. 18) and portability where applicable",
        "  (Art. 20). You may object at any time to processing based on",
        "  legitimate interests (Art. 21); we will then stop collecting your data.",
        f"  Contact: {event.controller_contact}",
        "  You may also lodge a complaint with a supervisory authority (Art. 77).",
        "",
        "9. Automated decision-making",
        "  " + ("We use automated decision-making; details available on request."
                if event.automated_decision_making
                else "We do not make decisions about you based solely on automated processing."),
    ]
    if event.exemption_basis:
        lines += [
            "",
            "Note: individual notification relies on Art. 14(5). Reasoning on file:",
            f"  {event.exemption_basis}",
            "  This notice is made publicly available as an appropriate measure.",
        ]
    return "\n".join(lines) + "\n"


def close_scrape_session(
    session: ScrapeSession,
    event_defaults: dict,
    path: str | Path = DEFAULT_EVENT_LOG,
) -> list[CollectionEvent]:
    """Turn a finished session's per-domain hit counters into collection events.

    ``event_defaults`` supplies the fields shared by every domain (controller,
    purposes, lawful_basis, data_categories, retention_period_days, ...).
    One event is emitted per domain with at least one fetched record.
    """
    events: list[CollectionEvent] = []
    for domain, hits in sorted(session.per_domain_hits.items()):
        if hits <= 0:
            continue
        event = CollectionEvent(
            **event_defaults,
            source_domain=domain,
            records_collected=hits,
            session_id=session.session_id,
        )
        emit_collection_event(event, path)
        events.append(event)
    logger.info("session_closed session=%s events=%d", session.session_id, len(events))
    return events


if __name__ == "__main__":
    import os
    import tempfile

    logging.basicConfig(level=logging.INFO)

    # Fictional controller and session.
    session = ScrapeSession()
    session.per_domain_hits.update({"directory.example": 42, "other.example": 3})

    defaults = dict(
        controller_name="Example Analytics Ltd",
        controller_contact="privacy@analytics.example",
        purposes=["Market analysis of independent translation services"],
        lawful_basis="Art. 6(1)(f) legitimate interests",
        legitimate_interests="Understanding supply and pricing in the translation market",
        data_categories=["Business contact email (keyed hash)", "Membership ID prefix"],
        retention_period_days=180,
        recipients=["Hosting provider (processor, EU)"],
    )
    out = os.path.join(tempfile.mkdtemp(), DEFAULT_EVENT_LOG)
    events = close_scrape_session(session, defaults, out)
    print(generate_art14_notice(events[0]))
