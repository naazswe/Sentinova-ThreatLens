
import pytest

from backend.app.indicators import validate_ip, validate_domain


# IP validation tests

def test_valid_ipv4():
    assert validate_ip("8.8.8.8") == "8.8.8.8"


def test_valid_ipv6():
    assert validate_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"


def test_ip_with_whitespace():
    assert validate_ip(" 8.8.8.8 ") == "8.8.8.8"


def test_invalid_ip():
    with pytest.raises(ValueError, match="Invalid IP address"):
        validate_ip("999.1.1.1")


# Domain validation tests

def test_valid_domain():
    assert validate_domain("google.com") == "google.com"


def test_uppercase_domain():
    assert validate_domain("GOOGLE.COM") == "google.com"


def test_domain_with_whitespace():
    assert validate_domain(" google.com ") == "google.com"


def test_invalid_underscore_domain():
    with pytest.raises(ValueError, match="Invalid domain"):
        validate_domain("bad_domain.com")


def test_empty_domain():
    with pytest.raises(ValueError, match="Invalid domain"):
        validate_domain("")


def test_domain_label_too_long():
    domain = "a" * 64 + ".com"
    with pytest.raises(ValueError, match="Invalid domain"):
        validate_domain(domain)


def test_leading_hyphen():
    with pytest.raises(ValueError, match="Invalid domain"):
        validate_domain("-google.com")


def test_trailing_hyphen():
    with pytest.raises(ValueError, match="Invalid domain"):
        validate_domain("google-.com")


def test_missing_tld():
    with pytest.raises(ValueError, match="Invalid domain"):
        validate_domain("google")
