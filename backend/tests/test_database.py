
import pytest

from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from backend.app.database import (
    Base,
    enable_sqlite_foreign_keys,
    get_db,
)

from backend.app.main import app
from backend.app.models import IOCRecord


@pytest.fixture
def client(tmp_path):
    database_path = tmp_path / "test_sentinova.db"

    test_engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    event.listen(
    test_engine,
    "connect",
    enable_sqlite_foreign_keys,
    )

    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
    )

    Base.metadata.create_all(bind=test_engine)

    app.state.testing_session_local = TestingSessionLocal

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_db, None)
        del app.state.testing_session_local
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


def test_create_indicator(client):
    payload = {
        "indicator_type": "domain",
        "value": "database-test.example",
        "source": "manual",
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-10T00:00:00Z",
    }

    response = client.post("/indicators", json=payload)

    assert response.status_code == 201

    data = response.json()

    assert data["value"] == "database-test.example"
    assert data["source"] == "manual"


def test_duplicate_indicator_updates_timestamps(client):
    first_payload = {
        "indicator_type": "domain",
        "value": "duplicate-test.example",
        "source": "manual",
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-10T00:00:00Z",
    }

    first_response = client.post(
        "/indicators",
        json=first_payload,
    )

    assert first_response.status_code == 201

    original_created_at = first_response.json()["created_at"]

    second_payload = {
        "indicator_type": "domain",
        "value": "duplicate-test.example",
        "source": "URLhaus",
        "first_seen": "2026-09-20T00:00:00Z",
        "last_seen": "2026-10-15T00:00:00Z",
    }

    second_response = client.post(
        "/indicators",
        json=second_payload,
    )

    assert second_response.status_code == 200

    data = second_response.json()

    assert data["first_seen"] == "2026-09-20T00:00:00Z"
    assert data["last_seen"] == "2026-10-15T00:00:00Z"
    assert data["created_at"] == original_created_at

    records = client.get("/indicators").json()

    matching_records = [
        item for item in records
        if item["value"] == "duplicate-test.example"
    ]

    assert len(matching_records) == 1


def test_integrity_error_recovers_from_concurrent_duplicate(
    client,
    monkeypatch,
):
    original_commit = Session.commit
    conflict_injected = False

    def commit_with_conflict(db_session):
        nonlocal conflict_injected

        if not conflict_injected:
            conflict_injected = True

            # Simulate another request inserting the same IOC.
            competing_session = app.state.testing_session_local()

            try:
                competing_session.add(
                    IOCRecord(
                        indicator_type="domain",
                        value="race-test.example",
                        source="OTX",
                        first_seen=datetime(2026, 10, 1),
                        last_seen=datetime(2026, 10, 10),
                        created_at=datetime(2026, 10, 1),
                    )
                )

                original_commit(competing_session)

            finally:
                competing_session.close()

            # Simulate the unique-constraint conflict.
            raise IntegrityError(
                "INSERT INTO indicators",
                {},
                Exception("Simulated duplicate IOC conflict"),
            )

        return original_commit(db_session)

    monkeypatch.setattr(
        Session,
        "commit",
        commit_with_conflict,
    )

    payload = {
        "indicator_type": "domain",
        "value": "race-test.example",
        "source": "manual",
        "first_seen": "2026-09-20T00:00:00Z",
        "last_seen": "2026-10-15T00:00:00Z",
    }

    response = client.post("/indicators", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert data["value"] == "race-test.example"
    assert data["first_seen"] == "2026-09-20T00:00:00Z"
    assert data["last_seen"] == "2026-10-15T00:00:00Z"

    records = client.get("/indicators").json()

    matching_records = [
        item for item in records
        if item["value"] == "race-test.example"
    ]

    assert len(matching_records) == 1

def test_csv_feed_endpoint_ingests_valid_records(client):
    csv_content = """indicator_type,value
ip,185.220.101.1
domain,csv-test.example
"""

    response = client.post(
        "/feeds/ingest/csv?source=CSVEndpointTest",
        content=csv_content,
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["source"] == "CSVEndpointTest"
    assert data["received"] == 2
    assert data["inserted"] == 2
    assert data["updated"] == 0
    assert data["rejected"] == 0

def test_csv_feed_endpoint_rejects_invalid_ioc(client):
    csv_content = """indicator_type,value
ip,185.220.101.1
domain,invalid_domain
"""

    response = client.post(
        "/feeds/ingest/csv?source=CSVInvalidTest",
        content=csv_content,
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["received"] == 2
    assert data["inserted"] == 1
    assert data["rejected"] == 1
    assert data["rejected_records"][0]["index"] == 1

def test_csv_feed_endpoint_rejects_missing_columns(client):
    csv_content = """type,address
ip,8.8.8.8
"""

    response = client.post(
        "/feeds/ingest/csv",
        content=csv_content,
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 400
    assert "indicator_type and value" in response.json()["detail"]

def test_csv_feed_endpoint_rejects_empty_content(client):
    response = client.post(
        "/feeds/ingest/csv",
        content="",
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 400
    assert "cannot be empty" in response.json()["detail"]

def test_csv_feed_endpoint_records_source(client):
    csv_content = """indicator_type,value
domain,source-test.example
"""

    response = client.post(
        "/feeds/ingest/csv?source=ThreatIntelFeed",
        content=csv_content,
        headers={"Content-Type": "text/csv"},
    )

    assert response.status_code == 200

    indicators = client.get("/indicators").json()

    matching = [
        item for item in indicators
        if item["value"] == "source-test.example"
    ]

    assert len(matching) == 1
    assert matching[0]["source"] == "ThreatIntelFeed"

def test_csv_feed_endpoint_handles_duplicate_records(client):
    csv_content = """indicator_type,value
domain,duplicate-csv.example
"""

    first_response = client.post(
        "/feeds/ingest/csv?source=CSVRepeatTest",
        content=csv_content,
        headers={"Content-Type": "text/csv"},
    )

    second_response = client.post(
        "/feeds/ingest/csv?source=CSVRepeatTest",
        content=csv_content,
        headers={"Content-Type": "text/csv"},
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    assert first_response.json()["inserted"] == 1
    assert second_response.json()["inserted"] == 0
    assert second_response.json()["updated"] == 1

    indicators = client.get("/indicators").json()

    matching = [
        item for item in indicators
        if item["value"] == "duplicate-csv.example"
    ]

    assert len(matching) == 1
