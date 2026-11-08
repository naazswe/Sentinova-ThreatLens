import json

import pytest

from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from backend.app.database import (
    Base,
    enable_sqlite_foreign_keys,
)
from backend.app.models import IOCAlert, IOCEnrichment, IOCRecord
from backend.app.services.enrichment_service import (
    save_abuseipdb_enrichment,
)


@pytest.fixture
def db_session(tmp_path):
    database_path = tmp_path / "test_enrichment.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    event.listen(
        engine,
        "connect",
        enable_sqlite_foreign_keys,
    )

    Base.metadata.create_all(bind=engine)

    TestingSessionLocal = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
    )

    db = TestingSessionLocal()

    indicator = IOCRecord(
        indicator_type="ip",
        value="8.8.8.8",
        source="manual",
        first_seen=datetime(2026, 11, 1),
        last_seen=datetime(2026, 11, 1),
        created_at=datetime(2026, 11, 1),
    )

    db.add(indicator)
    db.commit()
    db.refresh(indicator)

    try:
        yield db, indicator
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def sample_provider_data():
    return {
        "ipAddress": "8.8.8.8",
        "isPublic": True,
        "abuseConfidenceScore": 25,
        "totalReports": 10,
        "numDistinctUsers": 5,
        "lastReportedAt": "2026-11-04T12:30:00+00:00",
    }


def test_save_abuseipdb_enrichment(db_session):
    db, indicator = db_session

    result = save_abuseipdb_enrichment(
        db,
        indicator,
        sample_provider_data(),
    )

    assert result.id is not None
    assert result.indicator_id == indicator.id
    assert result.provider == "AbuseIPDB"
    assert result.abuse_confidence_score == 25
    assert result.total_reports == 10
    assert result.num_distinct_users == 5
    assert result.raw_data is not None


def test_enrichment_preserves_raw_provider_data(db_session):
    db, indicator = db_session

    provider_data = sample_provider_data()

    result = save_abuseipdb_enrichment(
        db,
        indicator,
        provider_data,
    )

    assert json.loads(result.raw_data) == provider_data


def test_multiple_lookups_create_history(db_session):
    db, indicator = db_session

    first = sample_provider_data()

    second = sample_provider_data()
    second["abuseConfidenceScore"] = 75
    second["totalReports"] = 30

    save_abuseipdb_enrichment(db, indicator, first)
    save_abuseipdb_enrichment(db, indicator, second)

    records = (
        db.query(IOCEnrichment)
        .filter(IOCEnrichment.indicator_id == indicator.id)
        .order_by(IOCEnrichment.id)
        .all()
    )

    assert len(records) == 2
    assert records[0].abuse_confidence_score == 25
    assert records[1].abuse_confidence_score == 75


def test_invalid_confidence_is_rejected(db_session):
    db, indicator = db_session

    provider_data = sample_provider_data()
    provider_data["abuseConfidenceScore"] = 150

    with pytest.raises(ValueError, match="confidence"):
        save_abuseipdb_enrichment(
            db,
            indicator,
            provider_data,
        )

    assert db.query(IOCEnrichment).count() == 0


def test_mismatched_ip_is_rejected(db_session):
    db, indicator = db_session

    provider_data = sample_provider_data()
    provider_data["ipAddress"] = "1.1.1.1"

    with pytest.raises(ValueError, match="does not match"):
        save_abuseipdb_enrichment(
            db,
            indicator,
            provider_data,
        )

    assert db.query(IOCEnrichment).count() == 0


def test_invalid_report_count_is_rejected(db_session):
    db, indicator = db_session

    provider_data = sample_provider_data()
    provider_data["totalReports"] = -1

    with pytest.raises(ValueError, match="total reports"):
        save_abuseipdb_enrichment(
            db,
            indicator,
            provider_data,
        )

    assert db.query(IOCEnrichment).count() == 0


def test_enrichment_history_cascades_on_ioc_deletion(db_session):
    db, indicator = db_session

    save_abuseipdb_enrichment(
        db,
        indicator,
        sample_provider_data(),
    )

    assert db.query(IOCEnrichment).count() == 1

    db.delete(indicator)
    db.commit()

    assert db.query(IOCEnrichment).count() == 0

def test_enrichment_persists_threat_score(db_session):
    db, indicator = db_session

    provider_data = sample_provider_data()
    provider_data["abuseConfidenceScore"] = 80

    save_abuseipdb_enrichment(
        db,
        indicator,
        provider_data,
    )

    db.refresh(indicator)

    assert indicator.severity_score == 80
    assert indicator.severity == "critical"
    assert indicator.confidence == 80


def test_high_confidence_enrichment_creates_alert(db_session):
    db, indicator = db_session

    provider_data = sample_provider_data()
    provider_data["abuseConfidenceScore"] = 90

    save_abuseipdb_enrichment(
        db,
        indicator,
        provider_data,
    )

    alerts = (
        db.query(IOCAlert)
        .filter(IOCAlert.indicator_id == indicator.id)
        .all()
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "high_threat_score"
    assert alerts[0].severity == "critical"
