import csv
from io import StringIO

from fastapi import (
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Response,
    status,
)
from sqlalchemy import asc, desc
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models import (
    IOCAlert,
    IOCEnrichment,
    IOCRecord,
)
from backend.app.schemas import (
    AlertRead,
    AlertStatusUpdate,
    EnrichmentRead,
    Indicator,
    IndicatorRead,
)
from backend.app.services.alert_service import (
    evaluate_all_indicator_alerts,
)
from backend.app.services.abuseipdb_client import (
    AbuseIPDBError,
    lookup_ip_reputation,
)
from backend.app.services.enrichment_service import (
    save_abuseipdb_enrichment,
)
from backend.app.services.feed_ingestion import (
    ingest_csv_feed,
    ingest_feed_payload,
)
from backend.app.services.indicator_service import save_indicator

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
    response_model=IndicatorRead,
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


@app.get(
    "/indicators",
    response_model=list[IndicatorRead],
)
def get_indicators(
    indicator_type: str | None = Query(
        default=None,
        pattern="^(ip|domain)$",
    ),
    severity: str | None = Query(
        default=None,
        pattern="^(low|medium|high|critical|unknown)$",
    ),
    source: str | None = Query(
        default=None,
        max_length=100,
    ),
    search: str | None = Query(
        default=None,
        max_length=253,
    ),
    min_score: int | None = Query(
        default=None,
        ge=0,
        le=100,
    ),
    max_score: int | None = Query(
        default=None,
        ge=0,
        le=100,
    ),
    sort_by: str = Query(
        default="id",
        pattern="^(id|severity_score|first_seen|last_seen|created_at)$",
    ),
    sort_order: str = Query(
        default="asc",
        pattern="^(asc|desc)$",
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    db: Session = Depends(get_db),
):
    if (
        min_score is not None
        and max_score is not None
        and min_score > max_score
    ):
        raise HTTPException(
            status_code=400,
            detail="min_score cannot exceed max_score",
        )

    query = build_indicator_query(
        db=db,
        indicator_type=indicator_type,
        severity=severity,
        source=source,
        search=search,
        min_score=min_score,
        max_score=max_score,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    return query.offset(offset).limit(limit).all()


@app.post("/feeds/ingest")
def ingest_feed(
    payload: dict,
    source: str = "manual",
    db: Session = Depends(get_db),
):
    return ingest_feed_payload(db, payload, source)


@app.post(
    "/indicators/{indicator_id}/enrich/abuseipdb",
    response_model=EnrichmentRead,
    status_code=status.HTTP_201_CREATED,
)
def enrich_indicator_with_abuseipdb(
    indicator_id: int,
    db: Session = Depends(get_db),
):
    indicator = (
        db.query(IOCRecord)
        .filter(IOCRecord.id == indicator_id)
        .first()
    )

    if indicator is None:
        raise HTTPException(
            status_code=404,
            detail="Indicator not found",
        )

    if indicator.indicator_type != "ip":
        raise HTTPException(
            status_code=400,
            detail="AbuseIPDB enrichment requires an IP indicator",
        )

    try:
        provider_data = lookup_ip_reputation(indicator.value)

    except AbuseIPDBError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"AbuseIPDB lookup failed: {exc}",
        ) from exc

    try:
        enrichment = save_abuseipdb_enrichment(
            db,
            indicator,
            provider_data,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Invalid AbuseIPDB response: {exc}",
        ) from exc

    return enrichment


@app.get(
    "/indicators/{indicator_id}/enrichments",
    response_model=list[EnrichmentRead],
)
def get_indicator_enrichment_history(
    indicator_id: int,
    db: Session = Depends(get_db),
):
    indicator = (
        db.query(IOCRecord)
        .filter(IOCRecord.id == indicator_id)
        .first()
    )

    if indicator is None:
        raise HTTPException(
            status_code=404,
            detail="Indicator not found",
        )

    records = (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.indicator_id == indicator_id)
        .order_by(IOCEnrichment.lookup_at.desc())
        .all()
    )

    return records

@app.post("/feeds/ingest/csv")
def ingest_csv(
    csv_content: str = Body("", media_type="text/csv"),
    source: str = "manual",
    db: Session = Depends(get_db),
):
    try:
        return ingest_csv_feed(
            db=db,
            csv_content=csv_content,
            source=source,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

@app.get("/alerts", response_model=list[AlertRead])
def get_alerts(db: Session = Depends(get_db)):
    return (
        db.query(IOCAlert)
        .order_by(IOCAlert.created_at.desc())
        .all()
    )


@app.get(
    "/indicators/{indicator_id}/alerts",
    response_model=list[AlertRead],
)
def get_indicator_alerts(
    indicator_id: int,
    db: Session = Depends(get_db),
):
    indicator = (
        db.query(IOCRecord)
        .filter(IOCRecord.id == indicator_id)
        .first()
    )

    if indicator is None:
        raise HTTPException(
            status_code=404,
            detail="Indicator not found",
        )

    return (
        db.query(IOCAlert)
        .filter(IOCAlert.indicator_id == indicator_id)
        .order_by(IOCAlert.created_at.desc())
        .all()
    )

def build_indicator_query(
    db: Session,
    indicator_type=None,
    severity=None,
    source=None,
    search=None,
    min_score=None,
    max_score=None,
    sort_by="id",
    sort_order="asc",
):
    query = db.query(IOCRecord)

    if indicator_type:
        query = query.filter(
            IOCRecord.indicator_type == indicator_type
        )

    if severity:
        query = query.filter(
            IOCRecord.severity == severity
        )

    if source:
        query = query.filter(
            IOCRecord.source.ilike(f"%{source}%")
        )

    if search:
        query = query.filter(
            IOCRecord.value.ilike(f"%{search}%")
        )

    if min_score is not None:
        query = query.filter(
            IOCRecord.severity_score >= min_score
        )

    if max_score is not None:
        query = query.filter(
            IOCRecord.severity_score <= max_score
        )

    sortable_columns = {
        "id": IOCRecord.id,
        "severity_score": IOCRecord.severity_score,
        "first_seen": IOCRecord.first_seen,
        "last_seen": IOCRecord.last_seen,
        "created_at": IOCRecord.created_at,
    }

    sort_column = sortable_columns[sort_by]

    if sort_order == "desc":
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))

    return query

@app.get("/indicators/export/csv")
def export_indicators_csv(
    indicator_type: str | None = Query(
        default=None,
        pattern="^(ip|domain)$",
    ),
    severity: str | None = Query(
        default=None,
        pattern="^(low|medium|high|critical|unknown)$",
    ),
    source: str | None = None,
    search: str | None = None,
    min_score: int | None = Query(default=None, ge=0, le=100),
    max_score: int | None = Query(default=None, ge=0, le=100),
    sort_by: str = Query(
        default="id",
        pattern="^(id|severity_score|first_seen|last_seen|created_at)$",
    ),
    sort_order: str = Query(
        default="asc",
        pattern="^(asc|desc)$",
    ),
    db: Session = Depends(get_db),
):
    if (
        min_score is not None
        and max_score is not None
        and min_score > max_score
    ):
        raise HTTPException(
            status_code=400,
            detail="min_score cannot exceed max_score",
        )

    records = build_indicator_query(
        db=db,
        indicator_type=indicator_type,
        severity=severity,
        source=source,
        search=search,
        min_score=min_score,
        max_score=max_score,
        sort_by=sort_by,
        sort_order=sort_order,
    ).all()

    output = StringIO(newline="")
    writer = csv.writer(output)

    writer.writerow([
        "id",
        "indicator_type",
        "value",
        "source",
        "severity_score",
        "severity",
        "confidence",
        "first_seen",
        "last_seen",
        "created_at",
    ])

    def safe_value(value):
        if isinstance(value, str) and value.startswith(
            ("=", "+", "-", "@", "\t", "\r")
        ):
            return "'" + value
        return value

    for record in records:
        writer.writerow([
            safe_value(record.id),
            safe_value(record.indicator_type),
            safe_value(record.value),
            safe_value(record.source),
            safe_value(record.severity_score),
            safe_value(record.severity),
            safe_value(record.confidence),
            safe_value(record.first_seen),
            safe_value(record.last_seen),
            safe_value(record.created_at),
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                'attachment; filename="sentinova_indicators.csv"'
        },
    )

@app.post("/alerts/evaluate")
def evaluate_alerts(db: Session = Depends(get_db)):
    try:
        evaluated, alerts = evaluate_all_indicator_alerts(db)
        db.commit()

        return {
            "evaluated_indicators": evaluated,
            "alerts_created_or_updated": len(alerts),
        }

    except Exception:
        db.rollback()
        raise


@app.patch("/alerts/{alert_id}/status", response_model=AlertRead)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    alert = (
        db.query(IOCAlert)
        .filter(IOCAlert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    alert.status = payload.status

    db.commit()
    db.refresh(alert)

    return alert
