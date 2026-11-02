
from datetime import timezone

from fastapi import Depends, FastAPI, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.database import Base, engine, get_db
from backend.app.models import IOCRecord
from backend.app.schemas import Indicator


def to_db_datetime(value):
    """Convert timezone-aware datetime to UTC-naive for SQLite."""
    return value.astimezone(timezone.utc).replace(tzinfo=None)


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="Sentinova ThreatLens",
    description="Cyber Threat Intelligence and Analysis Platform",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Sentinova ThreatLens",
    }


@app.post(
    "/indicators",
    response_model=Indicator,
    status_code=status.HTTP_201_CREATED,
)
def create_indicator(
    indicator: Indicator,
    response: Response,
    db: Session = Depends(get_db),
):
    existing = db.query(IOCRecord).filter(
        IOCRecord.indicator_type == indicator.indicator_type.value,
        IOCRecord.value == indicator.value,
    ).first()

    if existing:
        response.status_code = status.HTTP_200_OK

        existing_last_seen = existing.last_seen.replace(
            tzinfo=timezone.utc
        )
        existing_first_seen = existing.first_seen.replace(
            tzinfo=timezone.utc
        )

        if indicator.last_seen > existing_last_seen:
            existing.last_seen = to_db_datetime(indicator.last_seen)

        if indicator.first_seen < existing_first_seen:
            existing.first_seen = to_db_datetime(indicator.first_seen)

        db.commit()
        db.refresh(existing)

        return existing

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

        response.status_code = status.HTTP_200_OK

        existing_last_seen = existing.last_seen.replace(
            tzinfo=timezone.utc
        )
        existing_first_seen = existing.first_seen.replace(
            tzinfo=timezone.utc
        )

        if indicator.last_seen > existing_last_seen:
            existing.last_seen = to_db_datetime(indicator.last_seen)

        if indicator.first_seen < existing_first_seen:
            existing.first_seen = to_db_datetime(indicator.first_seen)

        db.commit()
        db.refresh(existing)

        return existing

    db.refresh(record)

    return record


@app.get("/indicators", response_model=list[Indicator])
def get_indicators(db: Session = Depends(get_db)):
    return db.query(IOCRecord).order_by(IOCRecord.id).all()
