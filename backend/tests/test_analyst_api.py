from datetime import datetime
from io import StringIO
import csv

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
from backend.app.models import IOCRecord


@pytest.fixture
def analyst_environment(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test_analyst.db'}",
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

    records = [
        IOCRecord(
            indicator_type="ip",
            value="8.8.8.8",
            source="AbuseIPDB",
            first_seen=datetime(2026, 11, 1),
            last_seen=datetime(2026, 11, 4),
            created_at=datetime(2026, 11, 1),
            severity_score=85,
            severity="critical",
            confidence=90,
        ),
        IOCRecord(
            indicator_type="domain",
            value="malicious.example",
            source="URLhaus",
            first_seen=datetime(2026, 11, 2),
            last_seen=datetime(2026, 11, 4),
            created_at=datetime(2026, 11, 2),
            severity_score=95,
            severity="critical",
            confidence=95,
        ),
        IOCRecord(
            indicator_type="ip",
            value="1.1.1.1",
            source="manual",
            first_seen=datetime(2026, 11, 3),
            last_seen=datetime(2026, 11, 4),
            created_at=datetime(2026, 11, 3),
            severity_score=10,
            severity="low",
            confidence=10,
        ),
        IOCRecord(
            indicator_type="domain",
            value="clean.example",
            source="manual",
            first_seen=datetime(2026, 11, 4),
            last_seen=datetime(2026, 11, 4),
            created_at=datetime(2026, 11, 4),
            severity_score=None,
            severity="unknown",
            confidence=None,
        ),
    ]

    db.add_all(records)
    db.commit()
    db.close()

    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

def test_search_indicators_by_value(analyst_environment):
    response = analyst_environment.get(
        "/indicators?search=8.8.8.8"
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["value"] == "8.8.8.8"


def test_filter_indicators_by_type(analyst_environment):
    response = analyst_environment.get(
        "/indicators?indicator_type=domain"
    )

    assert response.status_code == 200
    assert len(response.json()) == 2
    assert all(
        item["indicator_type"] == "domain"
        for item in response.json()
    )

def test_filter_indicators_by_severity(analyst_environment):
    response = analyst_environment.get(
        "/indicators?severity=critical"
    )

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_filter_indicators_by_source(analyst_environment):
    response = analyst_environment.get(
        "/indicators?source=AbuseIPDB"
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["source"] == "AbuseIPDB"


def test_filter_indicators_by_score_range(analyst_environment):
    response = analyst_environment.get(
        "/indicators?min_score=80&max_score=100"
    )

    assert response.status_code == 200
    assert len(response.json()) == 2

def test_sort_indicators_by_score_descending(
    analyst_environment,
):
    response = analyst_environment.get(
        "/indicators?sort_by=severity_score&sort_order=desc"
    )

    assert response.status_code == 200

    scores = [
        item["severity_score"]
        for item in response.json()
    ]

    assert scores[:3] == [95, 85, 10]


def test_indicator_pagination(analyst_environment):
    response = analyst_environment.get(
        "/indicators?limit=2&offset=1"
    )

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_invalid_score_range_is_rejected(analyst_environment):
    response = analyst_environment.get(
        "/indicators?min_score=90&max_score=20"
    )

    assert response.status_code == 400


def test_invalid_sort_field_is_rejected(analyst_environment):
    response = analyst_environment.get(
        "/indicators?sort_by=password"
    )

    assert response.status_code == 422

def test_export_indicators_to_csv(analyst_environment):
    response = analyst_environment.get(
        "/indicators/export/csv"
    )

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "attachment" in response.headers["content-disposition"]

    rows = list(csv.DictReader(StringIO(response.text)))

    assert len(rows) == 4

    assert rows[0]["indicator_type"] == "ip"
    assert rows[0]["value"] == "8.8.8.8"


def test_export_csv_respects_filters(analyst_environment):
    response = analyst_environment.get(
        "/indicators/export/csv?severity=critical"
    )

    assert response.status_code == 200

    rows = list(csv.DictReader(StringIO(response.text)))

    assert len(rows) == 2
    assert all(
        row["severity"] == "critical"
        for row in rows
    )

def test_indicator_response_includes_database_id(
    analyst_environment,
):
    response = analyst_environment.get("/indicators")

    assert response.status_code == 200

    indicators = response.json()

    assert len(indicators) == 4
    assert all("id" in item for item in indicators)
    assert all(isinstance(item["id"], int) for item in indicators)

    ids = [item["id"] for item in indicators]

    assert len(ids) == len(set(ids))
