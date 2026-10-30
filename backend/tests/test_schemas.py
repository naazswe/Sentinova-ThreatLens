
import pytest
from pydantic import ValidationError

from backend.app.schemas import Indicator, IndicatorType


def test_valid_ip_indicator():
    indicator = Indicator(
        indicator_type="ip",
        value="8.8.8.8",
        source="OTX",
    )

    assert indicator.indicator_type == IndicatorType.IP
    assert indicator.value == "8.8.8.8"
    assert indicator.source == "OTX"


def test_valid_domain_indicator():
    indicator = Indicator(
        indicator_type="domain",
        value="GOOGLE.COM",
        source="URLhaus",
    )

    assert indicator.value == "google.com"


def test_ip_with_whitespace():
    indicator = Indicator(
        indicator_type="ip",
        value=" 8.8.8.8 ",
    )

    assert indicator.value == "8.8.8.8"


def test_invalid_ip_indicator():
    with pytest.raises(ValidationError):
        Indicator(
            indicator_type="ip",
            value="999.1.1.1",
        )


def test_invalid_domain_indicator():
    with pytest.raises(ValidationError):
        Indicator(
            indicator_type="domain",
            value="bad_domain.com",
        )


def test_default_source():
    indicator = Indicator(
        indicator_type="ip",
        value="1.1.1.1",
    )

    assert indicator.source == "manual"


def test_empty_source_rejected():
    with pytest.raises(ValidationError):
        Indicator(
            indicator_type="ip",
            value="1.1.1.1",
            source="   ",
        )


def test_timestamp_order():
    with pytest.raises(ValidationError):
        Indicator(
            indicator_type="ip",
            value="8.8.8.8",
            first_seen="2026-10-20T10:00:00Z",
            last_seen="2026-10-19T10:00:00Z",
        )
