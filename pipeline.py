"""Detect -> Redact -> Route (DRR) pipeline.

Article sections:
  * "Custom Recognizers and the Entity-Scope Decision" (redact, inspect_and_route)
  * "Transient Raw Text Is Still Processing" (transient_text,
    log_processing_failure, process_transient)

Processing in memory is still processing (Art. 4(2)) and needs an Art. 6 basis.
The helpers here limit *onward* persistence of raw text; they do not securely
erase Python strings from memory.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from presidio_analyzer import RecognizerResult

from detection import SITE_ENTITIES, detect, get_analyzer
from routing import Sink, route_record

logger = logging.getLogger("scrape.drr")

REDACTION_TOKEN = "[REDACTED]"


def _merge_spans(findings: list[RecognizerResult]) -> list[tuple[int, int]]:
    """Merge overlapping or touching [start, end) spans."""
    merged: list[tuple[int, int]] = []
    for result in sorted(findings, key=lambda item: (item.start, item.end)):
        start, end = result.start, result.end
        if end <= start:
            continue  # zero-length / malformed finding
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return merged


def redact(text: str, findings: list[RecognizerResult]) -> str:
    """Replace every detected span with ``[REDACTED]``.

    Overlapping findings are merged first, so overlapping recognizers cannot
    produce partial or doubled replacements. Replacement runs right-to-left so
    earlier offsets stay valid.

    >>> from presidio_analyzer import RecognizerResult as R
    >>> redact("Call Jane Smith", [R("PERSON", 5, 15, 0.85)])
    'Call [REDACTED]'
    """
    if not text or not findings:
        return text

    for start, end in reversed(_merge_spans(findings)):
        start, end = max(0, start), min(len(text), end)
        text = text[:start] + REDACTION_TOKEN + text[end:]
    return text


def inspect_and_route(
    text: str,
    *,
    coverage_approved: bool,
    pseudonymization_approved: bool,
) -> tuple[str, Sink]:
    """Detect, redact, and route one text record.

    The record stays in quarantine until BOTH detection coverage and the
    separate pseudonymization assessment have been approved. Registering
    recognizers alone never authorizes a sink change, and zero findings never
    establish that a record is non-personal.

    Returns ``(transformed_text, destination)``.
    """
    findings = detect(get_analyzer(), text, SITE_ENTITIES)
    transformed = redact(text, findings)

    destination = route_record(
        # Illustrative routing-policy confidence, not an NER score.
        confidence=1.0 if coverage_approved else 0.0,
        non_personal_assessment_passed=False,
        pseudonymization_assessment_passed=(
            coverage_approved and pseudonymization_approved
        ),
        unresolved_identifiers=not coverage_approved,
    )
    logger.debug("Record routed sink=%s findings=%d", destination, len(findings))
    return transformed, destination


@contextmanager
def transient_text(text: str) -> Iterator[dict[str, str]]:
    """Hold raw text in a container that is cleared when the block exits.

    This drops the references *held by the container*. It is not secure
    erasure: strings are immutable, and HTTP buffers, tracebacks, or NLP
    objects may retain copies. Pair with deployment controls (crash dumps,
    swap, tracing, monitoring integrations).
    """
    holder = {"text": text}
    del text
    try:
        yield holder
    finally:
        holder.clear()


def log_processing_failure(exc: Exception) -> None:
    """Log a DRR failure without emitting exception text or a traceback.

    Even the redacted message is not emitted: automated detection can miss
    identifiers. Only the exception *class name* is logged, which carries no
    input data. A redaction failure never falls back to raw logging.
    """
    exc_type = type(exc).__name__
    try:
        message = str(exc)
        findings = detect(get_analyzer(), message, SITE_ENTITIES)
        sanitized_message = redact(message, findings)
        del message, sanitized_message
        logger.warning(
            "DRR processing failed (%s); exception text suppressed",
            exc_type,
            exc_info=False,
        )
    except Exception:
        logger.warning(
            "DRR processing failed (%s); diagnostic text unavailable",
            exc_type,
            exc_info=False,
        )


def process_transient(text: str) -> str | None:
    """Detect and redact raw text inside a ``transient_text`` block.

    Returns redacted text, or ``None`` on failure (which the caller must treat
    as "do not store, do not retry with the raw payload").

    Returned text is NOT approved for storage: it must still pass routing.
    """
    if not text:
        return text

    with transient_text(text) as raw:
        del text
        try:
            findings = detect(get_analyzer(), raw["text"], SITE_ENTITIES)
            return redact(raw["text"], findings)
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all
            log_processing_failure(exc)
            return None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    fixture = "Member MEM-123456; phone +44 7700 900123."  # fictional

    _, before = inspect_and_route(
        fixture, coverage_approved=False, pseudonymization_approved=False
    )
    # Hypothetical approvals for this fictional fixture only.
    redacted, after = inspect_and_route(
        fixture, coverage_approved=True, pseudonymization_approved=True
    )
    print(f"Before approval: {before}")
    print(f"After approval:  {after}")
    print(f"Redacted text:   {redacted}")
    print(f"process_transient: {process_transient('Contact jane@example.com')}")
