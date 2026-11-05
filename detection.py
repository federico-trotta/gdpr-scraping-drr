"""Local PII detection: business-name screening, analyzer setup, custom recognizers.

Article sections:
  * "Business Names Are Indirect Identifiers You Leak"
  * "Detection That Never Leaves Your Infrastructure"
  * "Custom Recognizers and the Entity-Scope Decision"

Everything here runs locally (Presidio + a locally installed spaCy model).
No scraped text is sent to an external inference service.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache

from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider

logger = logging.getLogger("scrape.detection")

SPACY_MODEL = "en_core_web_lg"

BASE_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"]
SITE_ENTITIES = [*BASE_ENTITIES, "MEMBER_ID"]

# Illustrative English-language patterns, not a legal-form classifier.
SOLE_TRADER_HINTS = re.compile(
    r"\b(?:sole trader|freelance|freelancer)\b"
    r"|\btrading as\b|\bt/a\b",
    re.IGNORECASE,
)

# Minimum NER score for a PERSON finding inside a business name to raise a flag.
# Deliberately low: a false flag costs a review, a miss costs a leaked identifier.
BUSINESS_NAME_PERSON_FLOOR = 0.5


# --------------------------------------------------------------------------- #
# Analyzer construction
# --------------------------------------------------------------------------- #
def build_analyzer() -> AnalyzerEngine:
    """Build a Presidio AnalyzerEngine backed by the local spaCy model.

    Build once and reuse: model loading is expensive.

    Raises:
        OSError: if ``en_core_web_lg`` is not installed
            (``python -m spacy download en_core_web_lg``).
    """
    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": SPACY_MODEL}],
        }
    )
    analyzer = AnalyzerEngine(
        nlp_engine=provider.create_engine(),
        supported_languages=["en"],
    )
    logger.info("Analyzer built with local model %s", SPACY_MODEL)
    return analyzer


def register_site_recognizers(analyzer: AnalyzerEngine) -> None:
    """Register source-specific recognizers for the fictional example directory.

    * ``MEMBER_ID``: ``MEM-`` followed by exactly six digits.
    * ``PHONE_NUMBER``: the exact fictional format ``+44 7700 900NNN``.

    The 0.98 scores are illustrative starting values, not measured accuracy.
    Document positives, negatives and observed errors before relying on them.

    Idempotent: calling twice does not register duplicate recognizers.
    """
    existing = {r.name for r in analyzer.registry.recognizers}

    if "ExampleMembershipRecognizer" not in existing:
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                name="ExampleMembershipRecognizer",
                supported_entity="MEMBER_ID",
                supported_language="en",
                patterns=[
                    Pattern(
                        name="example_member_id",
                        regex=r"\bMEM-\d{6}\b",
                        score=0.98,
                    )
                ],
            )
        )

    if "ExampleInternationalPhoneRecognizer" not in existing:
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                name="ExampleInternationalPhoneRecognizer",
                supported_entity="PHONE_NUMBER",
                supported_language="en",
                patterns=[
                    Pattern(
                        name="example_phone_format",
                        regex=r"(?<!\w)\+44 7700 900\d{3}\b",
                        score=0.98,
                    )
                ],
            )
        )
    logger.debug("Site recognizers registered")


@lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Process-wide analyzer with site recognizers registered (lazy, cached)."""
    analyzer = build_analyzer()
    register_site_recognizers(analyzer)
    return analyzer


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def detect(
    analyzer: AnalyzerEngine,
    text: str,
    entities: list[str],
) -> list[RecognizerResult]:
    """Run local detection and return findings sorted by offset.

    ``score_threshold=0.0`` keeps low-scoring findings available for review.
    Scores are recognizer confidences, not calibrated probabilities.

    Returns an empty list for empty / whitespace-only text or empty scope.
    """
    if not text or not text.strip() or not entities:
        return []

    return sorted(
        analyzer.analyze(
            text=text,
            language="en",
            entities=entities,
            score_threshold=0.0,
        ),
        key=lambda result: (result.start, result.end),
    )


def detect_business_name(
    business_name: str,
    analyzer: AnalyzerEngine | None = None,
) -> list[str]:
    """Screen an extracted business name before it reaches storage.

    Combines two signals:
      * ``possible_sole_trader``: explicit wording such as "freelance" or
        "trading as" (regex, see ``SOLE_TRADER_HINTS``).
      * ``contains_person_name``: the NER model finds a PERSON span inside
        the business name (only when an analyzer is supplied).

    An empty result is NOT clearance to store: it only means these two checks
    found nothing. Record-level checks still apply.

    Never logs the business name itself.

    >>> detect_business_name("Jane Smith — Freelance Translator")  # fictional
    ['possible_sole_trader']
    """
    if not business_name or not business_name.strip():
        return []

    flags: list[str] = []

    if SOLE_TRADER_HINTS.search(business_name):
        flags.append("possible_sole_trader")

    if analyzer is not None:
        persons = detect(analyzer, business_name, ["PERSON"])
        if any(r.score >= BUSINESS_NAME_PERSON_FLOOR for r in persons):
            flags.append("contains_person_name")

    if flags:
        logger.info("Business name held for review flags=%s", flags)
    return flags


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    analyzer = get_analyzer()

    # Fictional fixtures only.
    for name in [
        "Jane Smith — Freelance Translator",
        "Alex Morgan trading as Riverside Repairs",
        "Example Manufacturing Ltd",
    ]:
        print(f"{name!r}: {detect_business_name(name, analyzer) or 'no flags (not clearance)'}")

    for sample in [
        "My name is Jane Smith. Email jane@example.com.",
        "Member MEM-123456; phone +44 7700 900123.",
    ]:
        for result in detect(analyzer, sample, SITE_ENTITIES):
            # Printing spans is acceptable for fictional fixtures ONLY.
            print(
                f"entity={result.entity_type} "
                f"span={sample[result.start:result.end]!r} "
                f"offset=[{result.start}, {result.end}) "
                f"score={result.score:.2f}"
            )
