
import pytest

from backend.app.services.scoring_service import (
    calculate_threat_score,
)


def test_calculate_complete_threat_score():
    result = calculate_threat_score(
        malicious_votes=8,
        total_votes=10,
        abuse_confidence=90,
        source_trust=80,
    )

    assert result["score"] == 83
    assert result["severity"] == "critical"
    assert result["evidence_available"] is True


def test_calculate_score_with_partial_evidence():
    result = calculate_threat_score(
        abuse_confidence=80,
    )

    assert result["score"] == 80
    assert result["severity"] == "critical"


def test_no_evidence_returns_unknown():
    result = calculate_threat_score()

    assert result["score"] == 0
    assert result["severity"] == "unknown"
    assert result["evidence_available"] is False


@pytest.mark.parametrize(
    "score, expected",
    [
        (10, "low"),
        (25, "medium"),
        (50, "high"),
        (75, "critical"),
    ],
)
def test_severity_thresholds(score, expected):
    from backend.app.services.scoring_service import (
        calculate_severity,
    )

    assert calculate_severity(score) == expected


def test_invalid_vote_count():
    with pytest.raises(ValueError):
        calculate_threat_score(
            malicious_votes=11,
            total_votes=10,
        )


def test_invalid_confidence():
    with pytest.raises(ValueError):
        calculate_threat_score(
            abuse_confidence=110,
        )


def test_missing_vote_pair():
    with pytest.raises(ValueError):
        calculate_threat_score(
            malicious_votes=5,
        )
