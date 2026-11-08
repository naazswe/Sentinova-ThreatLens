
from datetime import datetime

import pytest

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from backend.app.database import (
    Base,
    enable_sqlite_foreign_keys,
)
from backend.app.models import (
    IOCAlert,
    IOCRecord,
    IOCSource,
)
from backend.app.services.alert_service import (
    evaluate_indicator_alerts,
)


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test_alerts.db'}",
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
        severity_score=85,
        severity="critical",
        confidence=85,
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


def test_high_score_creates_alert(db_session):
    db, indicator = db_session

    alerts = evaluate_indicator_alerts(db, indicator)
    db.commit()

    assert len(alerts) == 1
    assert alerts[0].alert_type == "high_threat_score"
    assert alerts[0].severity == "critical"


def test_multiple_sources_create_correlation_alert(db_session):
    db, indicator = db_session

    for source in ["Feed-A", "Feed-B"]:
        db.add(
            IOCSource(
                indicator_id=indicator.id,
                source=source,
                first_seen=datetime(2026, 11, 1),
                last_seen=datetime(2026, 11, 1),
            )
        )

    db.commit()

    alerts = evaluate_indicator_alerts(db, indicator)
    db.commit()

    assert any(
        alert.alert_type == "multiple_sources"
        for alert in alerts
    )


def test_single_source_does_not_create_correlation_alert(db_session):
    db, indicator = db_session

    db.add(
        IOCSource(
            indicator_id=indicator.id,
            source="Feed-A",
            first_seen=datetime(2026, 11, 1),
            last_seen=datetime(2026, 11, 1),
        )
    )

    db.commit()

    indicator.severity_score = 10
    indicator.severity = "low"

    alerts = evaluate_indicator_alerts(db, indicator)
    db.commit()

    assert not any(
        alert.alert_type == "multiple_sources"
        for alert in alerts
    )


def test_repeated_evaluation_does_not_duplicate_alerts(db_session):
    db, indicator = db_session

    evaluate_indicator_alerts(db, indicator)
    db.commit()

    evaluate_indicator_alerts(db, indicator)
    db.commit()

    assert (
        db.query(IOCAlert)
        .filter(
            IOCAlert.indicator_id == indicator.id,
            IOCAlert.alert_type == "high_threat_score",
        )
        .count()
        == 1
    )


def test_repeated_trigger_preserves_resolved_alert(db_session):
    db, indicator = db_session

    evaluate_indicator_alerts(db, indicator)
    db.commit()

    alert = (
        db.query(IOCAlert)
        .filter(
            IOCAlert.indicator_id == indicator.id,
            IOCAlert.alert_type == "high_threat_score",
        )
        .first()
    )

    alert.status = "resolved"
    db.commit()

    evaluate_indicator_alerts(db, indicator)
    db.commit()

    assert alert.status == "resolved"
