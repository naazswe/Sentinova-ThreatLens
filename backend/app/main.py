from backend.app.models import IOCRecord
from fastapi import Depends, FastAPI, Response, status
from sqlalchemy.orm import Session

from backend.app.database import Base, engine, get_db
from backend.app.schemas import Indicator
from backend.app.services.indicator_service import save_indicator
from backend.app.services.feed_ingestion import ingest_feed_payload


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
    record, created = save_indicator(db, indicator)

    if not created:
        response.status_code = status.HTTP_200_OK

    return record


@app.get("/indicators", response_model=list[Indicator])
def get_indicators(db: Session = Depends(get_db)):
    return db.query(IOCRecord).order_by(IOCRecord.id).all()


@app.post("/feeds/ingest")
def ingest_feed(
    payload: dict,
    source: str = "manual",
    db: Session = Depends(get_db),
):
    return ingest_feed_payload(db, payload, source)