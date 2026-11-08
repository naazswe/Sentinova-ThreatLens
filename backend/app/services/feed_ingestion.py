from sqlalchemy.orm import Session

from backend.app.feeds.csv_parser import parse_csv_feed
from backend.app.feeds.parser import parse_feed_payload
from backend.app.services.indicator_service import save_indicator


def ingest_validated_indicators(
    db: Session,
    accepted: list,
    rejected: list,
    source: str,
    received: int,
):
    """Persist validated indicators and return ingestion statistics."""

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
        "received": received,
        "inserted": inserted,
        "updated": updated,
        "rejected": len(rejected),
        "rejected_records": rejected,
    }


def ingest_feed_payload(
    db: Session,
    payload: dict,
    source: str,
):
    accepted, rejected = parse_feed_payload(payload, source)

    return ingest_validated_indicators(
        db=db,
        accepted=accepted,
        rejected=rejected,
        source=source,
        received=len(payload["indicators"]),
    )


def ingest_csv_feed(
    db: Session,
    csv_content: str,
    source: str,
):
    accepted, rejected, received = parse_csv_feed(
        csv_content,
        source,
    )

    return ingest_validated_indicators(
        db=db,
        accepted=accepted,
        rejected=rejected,
        source=source,
        received=received,
    )
