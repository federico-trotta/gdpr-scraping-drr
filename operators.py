"""Presidio operators and the legal status of each output.

Article sections:
  * "A Corrected Operator Table"
  * "Your Salt Is Re-Identification Material You Hold"

Operators transform values. They do not decide whether a record is anonymous.
``OUTPUT_STATUS`` notes explain each operator's limits and must never be used
as an automatic routing shortcut.
"""

from __future__ import annotations

import logging
import os

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

logger = logging.getLogger("scrape.operators")
secret_audit = logging.getLogger("scrape.secret_access")

SALT_ENV_VAR = "PII_HASH_SALT"
MIN_SALT_BYTES = 16  # Presidio's minimum for a supplied hash salt.

# Fixture assumptions:
#   PHONE_NUMBER: "(415) 555-0142" -> retain "(415)"   (9 chars masked)
#   MEMBER_ID:    "MEM-123456"     -> retain "MEM-"    (6 chars masked)
# chars_to_mask counts characters, not digits: spaces and punctuation count.
# For variable-length or international formats, parse and validate the
# numbering plan first. Don't reuse these counts.
OPERATORS: dict[str, OperatorConfig] = {
    "DEFAULT": OperatorConfig("redact", {}),
    "PERSON": OperatorConfig("replace", {"new_value": "[PERSON]"}),
    "PHONE_NUMBER": OperatorConfig(
        "mask",
        {"masking_char": "*", "chars_to_mask": 9, "from_end": True},
    ),
    "MEMBER_ID": OperatorConfig(
        "mask",
        {"masking_char": "*", "chars_to_mask": 6, "from_end": True},
    ),
    # EMAIL_ADDRESS is added by configure_email_hashing() once the salt loads.
}

# Assessment notes - not automatic routing decisions.
OUTPUT_STATUS: dict[str, str] = {
    "PERSON": "Placeholder only; assess the remaining record",
    "PHONE_NUMBER": "Minimized; retain personal-data controls",
    "MEMBER_ID": "Minimized; assess remaining linkage",
    "EMAIL_ADDRESS": "Pseudonymized if separation is effective",
    "DEFAULT": "Removed; does nothing about identifiers the analyzer misses",
}

anonymizer = AnonymizerEngine()


def load_hash_salt() -> str:
    """Load the hashing secret from ``PII_HASH_SALT`` and fail fast.

    Raises:
        RuntimeError: if the variable is missing, empty, or shorter than
            16 bytes (UTF-8). Length validation does not prove randomness.

    Never logs the secret or any value-derived fingerprint; only the fact that
    it was loaded. Your secret manager's audit trail is the real access log.
    """
    salt = os.environ.get(SALT_ENV_VAR)
    if salt is None or not salt.strip():
        raise RuntimeError("Required hashing secret is unavailable")

    if len(salt.encode("utf-8")) < MIN_SALT_BYTES:
        raise RuntimeError("Hashing secret fails minimum length policy")

    secret_audit.info("PII hashing secret loaded")
    return salt


def configure_email_hashing(salt: str | None = None) -> None:
    """Install a deterministic (fixed-salt) EMAIL_ADDRESS hash operator.

    A fixed salt restores equality matching across records - which is exactly
    the linkage your assessment must account for.
    """
    OPERATORS["EMAIL_ADDRESS"] = OperatorConfig(
        "hash",
        {"hash_type": "sha256", "salt": salt or load_hash_salt()},
    )


def hash_fixture(salt: str | None = None) -> str:
    """Hash the fictional address ``jane@example.com`` with Presidio.

    * ``salt=None``: Presidio (>= 2.2.361) draws a random salt per entity, so
      repeated calls differ.
    * fixed ``salt``: output is stable for the same input, salt and version.
    """
    text = "jane@example.com"
    params: dict[str, str] = {"hash_type": "sha256"}
    if salt is not None:
        params["salt"] = salt

    result = anonymizer.anonymize(
        text=text,
        analyzer_results=[
            RecognizerResult(
                entity_type="EMAIL_ADDRESS", start=0, end=len(text), score=1.0
            )
        ],
        operators={"EMAIL_ADDRESS": OperatorConfig("hash", params)},
    )
    return result.text


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    salt = load_hash_salt()
    configure_email_hashing(salt)

    print("Default outputs match:   ", hash_fixture() == hash_fixture())
    print("Fixed-salt outputs match:", hash_fixture(salt) == hash_fixture(salt))
    # Fictional fixture only: compare this output across process runs.
    print("Stable fixture digest:   ", hash_fixture(salt))

    sample = "Call (415) 555-0142 about MEM-123456"  # fictional
    masked = anonymizer.anonymize(
        text=sample,
        analyzer_results=[
            RecognizerResult("PHONE_NUMBER", 5, 19, 1.0),
            RecognizerResult("MEMBER_ID", 26, 36, 1.0),
        ],
        operators=OPERATORS,
    ).text
    print("Masked fixture:          ", masked)
