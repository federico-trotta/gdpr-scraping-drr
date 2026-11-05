# gdpr_drr — companion code for *GDPR-Compliant Web Scraping: Real-Time PII Anonymization*

Full implementations of the shortened snippets in the article (still need to be published). The pipeline
**detects** personal data locally, **redacts/transforms** it, and **routes** each
record to one of three sinks (`non-personal`, `pseudonymized`, `quarantine`).
It also covers the rights that apply after collection: erasure, rectification,
objection (suppression), and Art. 14 notices.

> This is engineering illustration, not legal advice. Every fixture is fictional.
> Scores, thresholds and regexes are starting points you must validate on your
> own sources.

## Install

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

Install the model *before* you restrict outbound network access in the
processing environment. Nothing in this repo calls a remote inference service.

## Environment

| Variable        | Required | Purpose |
|-----------------|----------|---------|
| `PII_HASH_SALT` | yes, for `operators`, `rights`, `suppression` | Secret used for keyed hashing. Must be ≥ 16 bytes; the code raises `RuntimeError` if it is missing or too short. |

```bash
export PII_HASH_SALT="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Provision it via your secret manager in production, never a committed file.
Treat it as re-identification material: anyone holding it can test candidate
identifiers against stored tokens.

## Module map

| Module | Article section | Contents |
|---|---|---|
| `detection.py`   | Business names are indirect identifiers · Detection that never leaves your infrastructure · Custom recognizers | `SOLE_TRADER_HINTS`, `detect_business_name()`, `build_analyzer()`, `detect()`, `register_site_recognizers()`, `get_analyzer()` |
| `routing.py`     | Rename the sinks you write to | `Sink`, `CONFIDENCE_FLOOR`, `route_record()` |
| `pipeline.py`    | Custom recognizers (redaction) · Transient raw text is still processing | `redact()`, `inspect_and_route()`, `transient_text()`, `log_processing_failure()`, `process_transient()` |
| `operators.py`   | A corrected operator table · Your salt is re-identification material | `OPERATORS`, `OUTPUT_STATUS`, `load_hash_salt()`, `configure_email_hashing()`, `hash_fixture()` |
| `article9.py`    | Article 9 fields get halted, not tokenized | `GUARD_ENTITIES`, `guard_special_categories()`, `transform_or_halt()` |
| `rights.py`      | Erasure and rectification keyed on the pseudonym | `_derive_token()`, `handle_erasure()`, `handle_rectification()`, `sweep_expired_quarantine()`, `init_db()`, `insert_record()` |
| `suppression.py` | Objection, and the re-scrape loop that defeats it | `ScrapeSession`, `is_suppressed()`, `scrape_with_suppression_check()`, `extract_identifier_from_url()` (stub) |
| `notices.py`     | The Art. 14 notice nobody ever schedules | `CollectionEvent`, `emit_collection_event()`, `generate_art14_notice()`, `close_scrape_session()` |
| `schema.sql`     | — | SQLite tables: `scrape_records`, `aggregates`, `quarantine`, `suppression_list`, `erasure_log` |

Note: the article's first snippet calls the business-name check `detect()`. In
the repo it is `detect_business_name()` so it doesn't clash with the analyzer
`detect()`; it also adds the person-name (NER) check the article recommends.

## Loggers

All loggers are named `scrape.<module>` (`scrape.detection`, `scrape.drr`,
`scrape.routing`, `scrape.operators`, `scrape.rights`, `scrape.suppression`,
`scrape.notices`, `scrape.article9`). Two are special:

- `scrape.secret_access`: records only that the salt was loaded.
- `scrape.sensitive_decisions`: the Art. 9 halt log. It does **not** propagate
  to the parent handlers, so attach your own restricted handler and retention policy.

Production paths never log raw identifiers or matched spans. Only the
`__main__` demos print spans, and only for fictional fixtures.

## Quickstart

Each module runs its own demo: `python detection.py`, `python rights.py`, and so on.
End to end:

```python
import os, logging
logging.basicConfig(level=logging.INFO)

from rights import init_db, insert_record, handle_erasure
from pipeline import transient_text, inspect_and_route
from article9 import transform_or_halt
from operators import configure_email_hashing
from suppression import ScrapeSession, scrape_with_suppression_check
from notices import close_scrape_session, generate_art14_notice

init_db("pipeline.db")
configure_email_hashing()          # reads PII_HASH_SALT

session = ScrapeSession()
urls = ["https://directory.example/members/MEM-123456"]   # fictional
fetch = lambda url: "Jane Smith, MEM-123456, jane@example.com"  # your HTTP client

for url, body in scrape_with_suppression_check(urls, fetch, session=session):
    with transient_text(body) as raw:
        del body
        transformed = transform_or_halt(raw, source_review_flags_sensitive=False)
    if transformed is None:
        continue                    # Art. 9 halt: no write, no retry
    _, sink = inspect_and_route(transformed,
                                coverage_approved=True,          # your assessment
                                pseudonymization_approved=True)  # your assessment
    insert_record("MEM-123456", transformed, sink=sink,
                  source_domain="directory.example")

events = close_scrape_session(session, dict(
    controller_name="Example Analytics Ltd",
    controller_contact="privacy@analytics.example",
    purposes=["Market analysis"],
    lawful_basis="Art. 6(1)(f) legitimate interests",
    legitimate_interests="Understanding supply in the translation market",
    data_categories=["Membership ID prefix", "Business email (keyed hash)"],
    retention_period_days=180,
))
print(generate_art14_notice(events[0]))

handle_erasure("MEM-123456", "data subject request")  # next run skips this subject
```

## Design notes

- **Token consistency.** Erasure and rectification re-derive the
  HMAC-SHA-256 token from the identifier the data subject supplies. That only
  works if rows were keyed with the same `_derive_token()` at ingestion, which
  is what `insert_record()` does. Presidio's `hash` operator transforms text
  inside the payload. It is not the lookup key.
- **Quarantine after erasure** keeps a 30-day backup window, then
  `sweep_expired_quarantine()` (run it nightly) deletes the rows. Backups and log
  sinks outside `pipeline.db` are not reached by the handlers. Cover them in
  your retention schedule.
- **Suppression** is queried per URL on a live connection, so an erasure
  processed mid-run takes effect on the next URL.
- **`route_record()` fails closed.** Invalid confidence, unresolved
  identifiers, or contradictory assessments all go to `quarantine`.
