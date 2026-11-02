from datetime import timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.models import IOCRecord
from backend.app.schemas import Indicator


def to_db_datetime(value):
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def to_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def save_indicator(db: Session, indicator: Indicator):
    """Insert an IOC or update its seen timestamps if it already exists."""

    existing = db.query(IOCRecord).filter(
        IOCRecord.indicator_type == indicator.indicator_type.value,
        IOCRecord.value == indicator.value,
    ).first()

    if existing:
        existing_last_seen = to_utc(existing.last_seen)
        existing_first_seen = to_utc(existing.first_seen)

        if indicator.last_seen > existing_last_seen:
            existing.last_seen = to_db_datetime(indicator.last_seen)

        if indicator.first_seen < existing_first_seen:
            existing.first_seen = to_db_datetime(indicator.first_seen)

        db.commit()
        db.refresh(existing)
        return existing, False

    record = IOCRecord(
        indicator_type=indicator.indicator_type.value,
        value=indicator.value,
        source=indicator.source,
        first_seen=to_db_datetime(indicator.first_seen),
        last_seen=to_db_datetime(indicator.last_seen),
        created_at=to_db_datetime(indicator.created_at),
    )

    db.add(record)

    try:
        db.commit()

    except IntegrityError:
        db.rollback()

        existing = db.query(IOCRecord).filter(
            IOCRecord.indicator_type == indicator.indicator_type.value,
            IOCRecord.value == indicator.value,
        ).first()

        if existing is None:
            raise

        existing_last_seen = to_utc(existing.last_seen)
        existing_first_seen = to_utc(existing.first_seen)

        if indicator.last_seen > existing_last_seen:
            existing.last_seen = to_db_datetime(indicator.last_seen)

        if indicator.first_seen < existing_first_seen:
            existing.first_seen = to_db_datetime(indicator.first_seen)

        db.commit()
        db.refresh(existing)
        return existing, False

    db.refresh(record)
    return record, True