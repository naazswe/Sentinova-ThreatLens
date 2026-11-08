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
from backend.app.models import IOCRecord
from backend.app.services.abuseipdb_client import AbuseIPDBError


@pytest.fixture
def api_environment(tmp_path):
    database_path = tmp_path / "test_api_enrichment.db"

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

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    db = TestingSessionLocal()

    ip_indicator = IOCRecord(
        indicator_type="ip",
        value="8.8.8.8",
        source="manual",
        first_seen=datetime(2026, 11, 1),
        last_seen=datetime(2026, 11, 1),
        created_at=datetime(2026, 11, 1),
    )

    domain_indicator = IOCRecord(
        indicator_type="domain",
        value="example.com",
        source="manual",
        first_seen=datetime(2026, 11, 1),
        last_seen=datetime(2026, 11, 1),
        created_at=datetime(2026, 11, 1),
    )

    db.add_all([ip_indicator, domain_indicator])
    db.commit()

    db.refresh(ip_indicator)
    db.refresh(domain_indicator)

    try:
        yield client, ip_indicator.id, domain_indicator.id, db
    finally:
        db.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

def mock_abuseipdb_response(ip_address):
    return {
        "ipAddress": ip_address,
        "isPublic": True,
        "abuseConfidenceScore": 25,
        "totalReports": 10,
        "numDistinctUsers": 5,
        "lastReportedAt": "2026-11-04T12:30:00+00:00",
    }

def test_enrichment_endpoint_success(
    api_environment,
    monkeypatch,
):
    client, ip_id, _, db = api_environment

    from backend.app import main

    monkeypatch.setattr(
        main,
        "lookup_ip_reputation",
        lambda ip: mock_abuseipdb_response(ip),
    )

    response = client.post(
        f"/indicators/{ip_id}/enrich/abuseipdb"
    )

    assert response.status_code == 201

    data = response.json()

    assert data["indicator_id"] == ip_id
    assert data["provider"] == "AbuseIPDB"
    assert data["abuse_confidence_score"] == 25
    assert data["total_reports"] == 10

def test_enrichment_endpoint_missing_indicator(api_environment):
    client, _, _, _ = api_environment

    response = client.post(
        "/indicators/99999/enrich/abuseipdb"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Indicator not found"

def test_enrichment_endpoint_rejects_domain(api_environment):
    client, _, domain_id, _ = api_environment

    response = client.post(
        f"/indicators/{domain_id}/enrich/abuseipdb"
    )

    assert response.status_code == 400
    assert "requires an IP indicator" in response.json()["detail"]

def test_enrichment_endpoint_provider_failure(
    api_environment,
    monkeypatch,
):
    client, ip_id, _, _ = api_environment

    from backend.app import main

    def failing_lookup(ip):
        raise AbuseIPDBError("Provider unavailable")

    monkeypatch.setattr(
        main,
        "lookup_ip_reputation",
        failing_lookup,
    )

    response = client.post(
        f"/indicators/{ip_id}/enrich/abuseipdb"
    )

    assert response.status_code == 502
    assert "AbuseIPDB lookup failed" in response.json()["detail"]

def test_enrichment_history_endpoint(
    api_environment,
    monkeypatch,
):
    client, ip_id, _, _ = api_environment

    from backend.app import main

    monkeypatch.setattr(
        main,
        "lookup_ip_reputation",
        lambda ip: mock_abuseipdb_response(ip),
    )

    first_response = client.post(
        f"/indicators/{ip_id}/enrich/abuseipdb"
    )

    second_response = client.post(
        f"/indicators/{ip_id}/enrich/abuseipdb"
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    history_response = client.get(
        f"/indicators/{ip_id}/enrichments"
    )

    assert history_response.status_code == 200

    history = history_response.json()

    assert len(history) == 2
    assert all(item["indicator_id"] == ip_id for item in history)
