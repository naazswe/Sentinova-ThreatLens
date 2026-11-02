from sqlalchemy.orm import Session

from backend.app.feeds.parser import parse_feed_payload
from backend.app.services.indicator_service import save_indicator


def ingest_feed_payload(
    db: Session,
    payload: dict,
    source: str,
):
    accepted, rejected = parse_feed_payload(payload, source)

    inserted = 0
    updated = 0

    for indicator in accepted:
        _, created = save_indicator(db, indicator)

        if created:
            inserted += 1
        else:
            updated += 1

    return {
        "source": source,
        "received": len(payload["indicators"]),
        "inserted": inserted,
        "updated": updated,
        "rejected": len(rejected),
        "rejected_records": rejected,
    }