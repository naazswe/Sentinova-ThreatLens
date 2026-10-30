
import ipaddress
import re


def validate_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address and return its normalized form."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def validate_domain(value: str) -> str:
    """Validate a domain name and return its normalized form."""
    domain = value.strip().lower()

    if not domain or len(domain) > 253:
        raise ValueError(f"Invalid domain: {value}")

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError(f"Invalid domain: {value}")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
        ):
            raise ValueError(f"Invalid domain: {value}")

    return domain
