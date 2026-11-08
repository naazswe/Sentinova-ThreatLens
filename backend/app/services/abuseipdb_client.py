import ipaddress

import httpx

from backend.app.config import settings


class AbuseIPDBError(Exception):
    """Raised when an AbuseIPDB lookup fails."""


def lookup_ip_reputation(ip_address: str) -> dict:
    """Retrieve reputation evidence for a public IP address."""

    try:
        parsed_ip = ipaddress.ip_address(ip_address.strip())
    except ValueError as exc:
        raise ValueError("Invalid IP address") from exc

    if not parsed_ip.is_global:
        raise ValueError(
            "AbuseIPDB lookup requires a public IP address"
        )

    api_key = settings.abuseipdb_api_key

    if not isinstance(api_key, str) or not api_key.strip():
        raise AbuseIPDBError(
            "ABUSEIPDB_API_KEY is not configured"
        )

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": str(parsed_ip),
        "maxAgeInDays": settings.abuseipdb_max_age_days,
    }

    try:
        with httpx.Client(
            timeout=settings.abuseipdb_timeout
        ) as client:
            response = client.get(
                f"{settings.abuseipdb_base_url}/check",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            payload = response.json()

    except httpx.HTTPError as exc:
        raise AbuseIPDBError(
            "AbuseIPDB request failed"
        ) from exc

    except ValueError as exc:
        raise AbuseIPDBError(
            "AbuseIPDB returned an invalid response"
        ) from exc

    data = payload.get("data")

    if not isinstance(data, dict):
        raise AbuseIPDBError(
            "AbuseIPDB response is missing reputation data"
        )

    return {
        "ipAddress": data.get("ipAddress"),
        "isPublic": data.get("isPublic"),
        "abuseConfidenceScore": data.get(
            "abuseConfidenceScore"
        ),
        "totalReports": data.get("totalReports"),
        "numDistinctUsers": data.get("numDistinctUsers"),
        "lastReportedAt": data.get("lastReportedAt"),
    }
