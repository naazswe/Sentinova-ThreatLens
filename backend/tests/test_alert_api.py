from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from backend.app.database import (
    Base,
    enable_sqlite_foreign_keys,
    get_db,
)
from backend.app.main import app
from backend.app.models import IOCAlert, IOCRecord, IOCSource


@pytest.fixture
def alert_api_environment(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test_alert_api.db'}",
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

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

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
    indicator_id = indicator.id
    db.close()

    try:
        with TestClient(app) as client:
            yield client, indicator_id, TestingSessionLocal
    finally:
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_get_alerts_returns_empty_list(
    alert_api_environment,
):
    client, _, _ = alert_api_environment

    response = client.get("/alerts")

    assert response.status_code == 200
    assert response.json() == []


def test_evaluate_alerts_creates_high_score_alert(
    alert_api_environment,
):
    client, indicator_id, _ = alert_api_environment

    response = client.post("/alerts/evaluate")

    assert response.status_code == 200
    assert response.json()["evaluated_indicators"] == 1
    assert response.json()["alerts_created_or_updated"] == 1

    alerts_response = client.get("/alerts")

    assert alerts_response.status_code == 200

    alerts = alerts_response.json()

    assert len(alerts) == 1
    assert alerts[0]["indicator_id"] == indicator_id
    assert alerts[0]["alert_type"] == "high_threat_score"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["status"] == "open"


def test_get_indicator_alerts_returns_matching_alerts(
    alert_api_environment,
):
    client, indicator_id, _ = alert_api_environment

    client.post("/alerts/evaluate")

    response = client.get(
        f"/indicators/{indicator_id}/alerts"
    )

    assert response.status_code == 200

    alerts = response.json()

    assert len(alerts) == 1
    assert alerts[0]["indicator_id"] == indicator_id


def test_get_indicator_alerts_returns_404_for_missing_indicator(
    alert_api_environment,
):
    client, _, _ = alert_api_environment

    response = client.get("/indicators/99999/alerts")

    assert response.status_code == 404
    assert response.json()["detail"] == "Indicator not found"


def test_update_alert_status_to_acknowledged(
    alert_api_environment,
):
    client, _, _ = alert_api_environment

    client.post("/alerts/evaluate")

    alerts = client.get("/alerts").json()
    alert_id = alerts[0]["id"]

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "acknowledged"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"


def test_update_alert_status_to_resolved(
    alert_api_environment,
):
    client, _, _ = alert_api_environment

    client.post("/alerts/evaluate")

    alert_id = client.get("/alerts").json()[0]["id"]

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "resolved"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "resolved"


def test_update_alert_rejects_invalid_status(
    alert_api_environment,
):
    client, _, _ = alert_api_environment

    client.post("/alerts/evaluate")

    alert_id = client.get("/alerts").json()[0]["id"]

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "closed"},
    )

    assert response.status_code == 422


def test_update_missing_alert_returns_404(
    alert_api_environment,
):
    client, _, _ = alert_api_environment

    response = client.patch(
        "/alerts/99999/status",
        json={"status": "resolved"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"


def test_multiple_sources_create_correlation_alert(
    alert_api_environment,
):
    client, indicator_id, session_factory = alert_api_environment

    db = session_factory()

    try:
        for source in ["Feed-A", "Feed-B"]:
            db.add(
                IOCSource(
                    indicator_id=indicator_id,
                    source=source,
                    first_seen=datetime(2026, 11, 1),
                    last_seen=datetime(2026, 11, 1),
                )
            )

        db.commit()
    finally:
        db.close()

    response = client.post("/alerts/evaluate")

    assert response.status_code == 200
    assert response.json()["alerts_created_or_updated"] == 2

    alerts = client.get("/alerts").json()

    alert_types = {
        alert["alert_type"]
        for alert in alerts
    }

    assert "high_threat_score" in alert_types
    assert "multiple_sources" in alert_types


def test_repeated_api_evaluation_does_not_duplicate_alerts(
    alert_api_environment,
):
    client, _, session_factory = alert_api_environment

    first_response = client.post("/alerts/evaluate")
    second_response = client.post("/alerts/evaluate")

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    db = session_factory()

    try:
        alert_count = db.query(IOCAlert).count()
    finally:
        db.close()

    assert alert_count == 1
@pytest.mark.parametrize(
    "analyst_status",
    ["acknowledged", "resolved"],
)
def test_reevaluation_preserves_analyst_managed_alert_status(
    alert_api_environment,
    analyst_status,
):
    client, _, _ = alert_api_environment

    # Generate the initial alert.
    client.post("/alerts/evaluate")

    alert_id = client.get("/alerts").json()[0]["id"]

    # Analyst changes the alert status.
    update_response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": analyst_status},
    )

    assert update_response.status_code == 200
    assert update_response.json()["status"] == analyst_status

    # Run evaluation again.
    evaluation_response = client.post("/alerts/evaluate")

    assert evaluation_response.status_code == 200

    # The analyst-managed status must remain unchanged.
    alerts = client.get("/alerts").json()

    matching_alert = next(
        alert for alert in alerts
        if alert["id"] == alert_id
    )

    assert matching_alert["status"] == analyst_status
