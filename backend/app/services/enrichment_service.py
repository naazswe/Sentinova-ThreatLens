import ipaddress
import json

from datetime import datetime, timezone

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.models import IOCEnrichment, IOCRecord

from backend.app.services.scoring_service import (
    calculate_threat_score,
)
from backend.app.services.alert_service import (
    evaluate_indicator_alerts,
)

def _to_db_datetime(value: datetime) -> datetime:
    """Normalize datetime to UTC and remove timezone for SQLite storage."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return value.replace(tzinfo=None)


def _parse_optional_datetime(value):
    """Parse an optional ISO-8601 timestamp from the provider."""

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("Invalid last-reported timestamp")

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid last-reported timestamp") from exc

    return _to_db_datetime(parsed)


def _validate_optional_count(value, field_name):
    """Validate optional non-negative integer fields."""

    if value is None:
        return None

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Invalid {field_name}")

    return value


def save_abuseipdb_enrichment(
    db: Session,
    indicator: IOCRecord,
    provider_data: dict,
    lookup_at: datetime | None = None,
) -> IOCEnrichment:
    """Persist one AbuseIPDB lookup as a historical enrichment record."""

    if indicator.indicator_type != "ip":
        raise ValueError("AbuseIPDB enrichment requires an IP indicator")

    if not isinstance(provider_data, dict):
        raise ValueError("Invalid AbuseIPDB response")

    try:
        returned_ip = ipaddress.ip_address(
            provider_data.get("ipAddress")
        )
        stored_ip = ipaddress.ip_address(indicator.value)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid IP address in enrichment data") from exc

    if returned_ip != stored_ip:
        raise ValueError("Enrichment IP does not match the IOC")

    confidence = provider_data.get("abuseConfidenceScore")

    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, int)
        or not 0 <= confidence <= 100
    ):
        raise ValueError("Invalid abuse confidence score")

    total_reports = _validate_optional_count(
        provider_data.get("totalReports"),
        "total reports",
    )

    distinct_users = _validate_optional_count(
        provider_data.get("numDistinctUsers"),
        "distinct users",
    )

    last_reported_at = _parse_optional_datetime(
        provider_data.get("lastReportedAt")
    )

    if lookup_at is None:
        lookup_at = datetime.now(timezone.utc)

    if not isinstance(lookup_at, datetime):
        raise ValueError("Invalid lookup timestamp")

    score_result = calculate_threat_score(
        abuse_confidence=confidence,
    )

    indicator.severity_score = score_result["score"]
    indicator.severity = score_result["severity"]
    indicator.confidence = confidence

    enrichment = IOCEnrichment(
        indicator_id=indicator.id,
        provider="AbuseIPDB",
        abuse_confidence_score=confidence,
        total_reports=total_reports,
        num_distinct_users=distinct_users,
        last_reported_at=last_reported_at,
        lookup_at=_to_db_datetime(lookup_at),
        raw_data=json.dumps(provider_data, sort_keys=True),
    )


    try:
        db.add(enrichment)

        evaluate_indicator_alerts(
            db,
            indicator,
        )

        db.commit()
        db.refresh(enrichment)

    except SQLAlchemyError:
        db.rollback()
        raise

    return enrichment
