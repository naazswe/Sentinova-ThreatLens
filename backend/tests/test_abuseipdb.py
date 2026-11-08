
import httpx
import pytest

from backend.app.services.abuseipdb_client import (
    AbuseIPDBError,
    lookup_ip_reputation,
)


def test_invalid_ip_is_rejected():
    with pytest.raises(ValueError):
        lookup_ip_reputation("999.999.999.999")


def test_private_ip_is_rejected():
    with pytest.raises(ValueError):
        lookup_ip_reputation("192.168.1.10")


def test_public_ip_response(monkeypatch):
    class MockResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "ipAddress": "8.8.8.8",
                    "isPublic": True,
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "numDistinctUsers": 0,
                    "lastReportedAt": None,
                }
            }

    class MockClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, url, headers, params):
            assert url.endswith("/check")
            assert params["ipAddress"] == "8.8.8.8"
            assert "Key" in headers
            return MockResponse()

    monkeypatch.setattr(
        httpx,
        "Client",
        MockClient,
    )

    result = lookup_ip_reputation("8.8.8.8")

    assert result["ipAddress"] == "8.8.8.8"
    assert result["abuseConfidenceScore"] == 0


def test_missing_api_key_is_rejected(monkeypatch):
    from backend.app.config import settings

    monkeypatch.setattr(
        settings,
        "abuseipdb_api_key",
        None,
    )

    with pytest.raises(
        AbuseIPDBError,
        match="ABUSEIPDB_API_KEY is not configured",
    ):
        lookup_ip_reputation("8.8.8.8")
