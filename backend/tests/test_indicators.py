
import pytest

from backend.app.indicators import validate_ip


def test_valid_ipv4():
    assert validate_ip("8.8.8.8") == "8.8.8.8"


def test_valid_ipv6():
    assert validate_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"


def test_ip_with_whitespace():
    assert validate_ip(" 8.8.8.8 ") == "8.8.8.8"


def test_invalid_ip():
    with pytest.raises(ValueError, match="Invalid IP address"):
        validate_ip("999.1.1.1")
