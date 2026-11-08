
from datetime import timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.models import IOCRecord, IOCSource
from backend.app.schemas import Indicator


def to_db_datetime(value):
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def to_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def record_source_observation(
    db: Session,
    indicator_id: int,
    indicator: Indicator,
):
    """Create or update the observation for one IOC source."""

    observation = (
        db.query(IOCSource)
        .filter(
            IOCSource.indicator_id == indicator_id,
            IOCSource.source == indicator.source,
        )
        .first()
    )

    if observation is None:
        observation = IOCSource(
            indicator_id=indicator_id,
            source=indicator.source,
            first_seen=to_db_datetime(indicator.first_seen),
            last_seen=to_db_datetime(indicator.last_seen),
        )
        db.add(observation)
        return

    if indicator.first_seen < to_utc(observation.first_seen):
        observation.first_seen = to_db_datetime(
            indicator.first_seen
        )

    if indicator.last_seen > to_utc(observation.last_seen):
        observation.last_seen = to_db_datetime(
            indicator.last_seen
        )


def update_indicator_timestamps(
    existing: IOCRecord,
    indicator: Indicator,
):
    """Update the overall first-seen and last-seen timestamps."""

    if indicator.first_seen < to_utc(existing.first_seen):
        existing.first_seen = to_db_datetime(
            indicator.first_seen
        )

    if indicator.last_seen > to_utc(existing.last_seen):
        existing.last_seen = to_db_datetime(
            indicator.last_seen
        )


def save_indicator(db: Session, indicator: Indicator):
    """Insert an IOC or update its timestamps and source history."""

    existing = (
        db.query(IOCRecord)
        .filter(
            IOCRecord.indicator_type
            == indicator.indicator_type.value,
            IOCRecord.value == indicator.value,
        )
        .first()
    )

    if existing:
        update_indicator_timestamps(existing, indicator)

        record_source_observation(
            db,
            existing.id,
            indicator,
        )

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
        source_observation = IOCSource(
            indicator=record,
            source=indicator.source,
            first_seen=to_db_datetime(indicator.first_seen),
            last_seen=to_db_datetime(indicator.last_seen),
        )

        db.add(source_observation)
        db.commit()

    except IntegrityError:
        db.rollback()

        existing = (
            db.query(IOCRecord)
            .filter(
                IOCRecord.indicator_type
                == indicator.indicator_type.value,
                IOCRecord.value == indicator.value,
            )
            .first()
        )

        if existing is None:
            raise

        update_indicator_timestamps(existing, indicator)

        record_source_observation(
            db,
            existing.id,
            indicator,
        )

        db.commit()
        db.refresh(existing)

        return existing, False

    db.refresh(record)

    return record, True
