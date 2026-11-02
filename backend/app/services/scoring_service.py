
WEIGHTS = {
    "malicious_ratio": 0.60,
    "abuse_confidence": 0.30,
    "source_trust": 0.10,
}


def validate_percentage(name, value):
    if value is None:
        return

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")

    if not 0 <= value <= 100:
        raise ValueError(f"{name} must be between 0 and 100")


def calculate_severity(score):
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def calculate_threat_score(
    malicious_votes=None,
    total_votes=None,
    abuse_confidence=None,
    source_trust=None,
):
    """
    Calculate a reproducible IOC threat score from 0 to 100.
    Missing evidence is excluded and remaining weights are normalized.
    """

    if (malicious_votes is None) != (total_votes is None):
        raise ValueError(
            "malicious_votes and total_votes must be provided together"
        )

    evidence = {}

    if total_votes is not None:
        if (
            isinstance(malicious_votes, bool)
            or isinstance(total_votes, bool)
            or not isinstance(malicious_votes, int)
            or not isinstance(total_votes, int)
        ):
            raise ValueError("Vote counts must be integers")

        if total_votes <= 0:
            raise ValueError("total_votes must be greater than zero")

        if not 0 <= malicious_votes <= total_votes:
            raise ValueError("Invalid malicious vote count")

        evidence["malicious_ratio"] = (
            malicious_votes / total_votes
        ) * 100

    validate_percentage("abuse_confidence", abuse_confidence)
    validate_percentage("source_trust", source_trust)

    if abuse_confidence is not None:
        evidence["abuse_confidence"] = abuse_confidence

    if source_trust is not None:
        evidence["source_trust"] = source_trust

    if not evidence:
        return {
            "score": 0,
            "severity": "unknown",
            "evidence_available": False,
            "factors": {},
        }

    available_weight = sum(
        WEIGHTS[name] for name in evidence
    )

    weighted_score = sum(
        value * WEIGHTS[name]
        for name, value in evidence.items()
    )

    score = round(weighted_score / available_weight)

    return {
        "score": score,
        "severity": calculate_severity(score),
        "evidence_available": True,
        "factors": {
            name: round(value, 2)
            for name, value in evidence.items()
        },
    }
