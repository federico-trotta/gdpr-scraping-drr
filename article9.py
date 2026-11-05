"""Article 9 guard: halt suspected special-category records, never tokenize them.

Article section: "Article 9 Fields Get Halted, Not Tokenized".

Presidio's NRP entity (nationality, religious or political group) is a warning
signal, not a legal classifier. Health, ethnicity, and other special-category
data can appear with no NRP finding, so the guard also accepts a source-review
flag supplied by your own process.
"""

from __future__ import annotations

import logging

from presidio_analyzer import RecognizerResult

from detection import SITE_ENTITIES, detect, get_analyzer
from operators import OPERATORS, anonymizer

logger = logging.getLogger("scrape.article9")

# Separate, metadata-only decision log. Give it its own restricted handler and
# retention policy: a separate logger NAME alone does not create separate storage.
decision_log = logging.getLogger("scrape.sensitive_decisions")
decision_log.propagate = False  # don't leak into the main scrape.* handlers

GUARD_ENTITIES = [*SITE_ENTITIES, "NRP"]


def guard_special_categories(
    findings: list[RecognizerResult],
    *,
    source_review_flags_sensitive: bool,
) -> bool:
    """Return ``True`` if processing may continue, ``False`` to halt.

    The decision log records only that a halt occurred: no span, source URL,
    record identifier, or inferred category.
    """
    suspected = source_review_flags_sensitive or any(
        item.entity_type == "NRP" for item in findings
    )
    if suspected:
        decision_log.warning("Record halted by special-category screening policy")
        return False
    return True


def transform_or_halt(
    raw: dict[str, str],
    *,
    source_review_flags_sensitive: bool,
) -> str | None:
    """Screen, then either anonymize with ``OPERATORS`` or halt.

    Call inside ``pipeline.transient_text()``. ``raw`` is always cleared on
    exit. ``None`` means STOP: no storage write, no payload retry, and no raw
    quarantine copy. The whole payload is discarded (removing one word can
    leave surrounding text that reveals the same belief).

    Raises:
        KeyError: if ``raw`` has no ``"text"`` key (container still cleared).
    """
    try:
        text = raw["text"]
        if not text or not text.strip():
            return text

        findings = detect(get_analyzer(), text, GUARD_ENTITIES)

        if not guard_special_categories(
            findings, source_review_flags_sensitive=source_review_flags_sensitive
        ):
            return None

        if "EMAIL_ADDRESS" not in OPERATORS:
            # Unmapped entities fall through to DEFAULT (redact): fail closed.
            logger.debug("EMAIL_ADDRESS operator not configured; using DEFAULT")

        return anonymizer.anonymize(
            text=text,
            analyzer_results=findings,
            operators=OPERATORS,
        ).text
    finally:
        raw.clear()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    decision_log.addHandler(logging.StreamHandler())  # demo only

    from pipeline import transient_text

    # Fictional fixtures only.
    for sample, flagged in [
        ("Jane Smith, MEM-123456, phone +44 7700 900123", False),
        ("Jane Smith, a Catholic translator in Leeds", False),  # NRP -> halt
        # NRP is a signal, not a classifier: invented party names may be missed.
        ("Jane Smith is a member of the Example Party", False),
        ("Jane Smith listing, reviewer flagged health content", True),
    ]:
        with transient_text(sample) as raw:
            print(transform_or_halt(raw, source_review_flags_sensitive=flagged))
