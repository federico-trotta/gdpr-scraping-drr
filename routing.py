"""Sink routing: non-personal, pseudonymized, quarantine.

Article section: "Rename the Sinks You Write To".

These are engineering categories, not GDPR-defined destinations. The function's
arguments are assessment results supplied by your pipeline, not source fields.
A confidence score never establishes anonymity.
"""

from __future__ import annotations

import logging
from math import isfinite
from typing import Literal

logger = logging.getLogger("scrape.routing")

Sink = Literal["non-personal", "pseudonymized", "quarantine"]

SINKS: tuple[Sink, ...] = ("non-personal", "pseudonymized", "quarantine")

# Illustrative policy threshold, not a GDPR requirement.
# Changes to this value belong in your Art. 30 record.
CONFIDENCE_FLOOR = 0.95


def route_record(
    *,
    confidence: float,
    non_personal_assessment_passed: bool,
    pseudonymization_assessment_passed: bool,
    unresolved_identifiers: bool,
) -> Sink:
    """Return the destination sink for one record.

    Guard order (first match wins):
      1. Non-numeric, NaN, infinite, or out-of-range confidence -> quarantine.
      2. Confidence below ``CONFIDENCE_FLOOR`` or unresolved identifiers
         -> quarantine.
      3. Both assessments passed: contradictory (a record cannot be both
         non-personal and pseudonymized personal data) -> quarantine.
      4. Non-personal assessment passed -> non-personal.
      5. Pseudonymization assessment passed -> pseudonymized.
      6. Anything else -> quarantine (fail closed).
    """
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        logger.warning("Routing: non-numeric confidence -> quarantine")
        return "quarantine"

    if not isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        logger.warning("Routing: invalid confidence -> quarantine")
        return "quarantine"

    if confidence < CONFIDENCE_FLOOR or unresolved_identifiers:
        return "quarantine"

    if non_personal_assessment_passed and pseudonymization_assessment_passed:
        logger.warning("Routing: contradictory assessments -> quarantine")
        return "quarantine"

    if non_personal_assessment_passed:
        return "non-personal"

    if pseudonymization_assessment_passed:
        return "pseudonymized"

    return "quarantine"


if __name__ == "__main__":
    cases = [
        dict(confidence=float("nan"), non_personal_assessment_passed=True,
             pseudonymization_assessment_passed=False, unresolved_identifiers=False),
        dict(confidence=0.90, non_personal_assessment_passed=True,
             pseudonymization_assessment_passed=False, unresolved_identifiers=False),
        dict(confidence=0.99, non_personal_assessment_passed=True,
             pseudonymization_assessment_passed=True, unresolved_identifiers=False),
        dict(confidence=0.99, non_personal_assessment_passed=False,
             pseudonymization_assessment_passed=True, unresolved_identifiers=False),
        dict(confidence=0.99, non_personal_assessment_passed=True,
             pseudonymization_assessment_passed=False, unresolved_identifiers=False),
    ]
    for case in cases:
        print(route_record(**case), case)
