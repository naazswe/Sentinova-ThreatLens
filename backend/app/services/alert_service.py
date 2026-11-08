
from sqlalchemy.orm import Session

from backend.app.models import IOCAlert, IOCRecord, IOCSource


def _upsert_alert(
    db: Session,
    indicator: IOCRecord,
    alert_type: str,
    severity: str,
    title: str,
    description: str,
):
    """Create an alert or refresh an existing alert."""

    alert = (
        db.query(IOCAlert)
        .filter(
            IOCAlert.indicator_id == indicator.id,
            IOCAlert.alert_type == alert_type,
        )
        .first()
    )

    if alert is None:
        alert = IOCAlert(
            indicator_id=indicator.id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            status="open",
        )
        db.add(alert)
        return alert

    alert.severity = severity
    alert.title = title
    alert.description = description

    return alert


def evaluate_indicator_alerts(
    db: Session,
    indicator: IOCRecord,
):
    """Evaluate threat-score and multi-source correlation rules."""

    generated_alerts = []

    # Rule 1: High or critical threat score.
    if (
        indicator.severity_score is not None
        and indicator.severity in ("high", "critical")
    ):
        alert = _upsert_alert(
            db=db,
            indicator=indicator,
            alert_type="high_threat_score",
            severity=indicator.severity,
            title="High-risk IOC detected",
            description=(
                f"IOC {indicator.value} has a threat score of "
                f"{indicator.severity_score}/100 and severity "
                f"{indicator.severity}."
            ),
        )
        generated_alerts.append(alert)

    # Rule 2: IOC reported by two or more distinct sources.
    sources = (
        db.query(IOCSource.source)
        .filter(IOCSource.indicator_id == indicator.id)
        .all()
    )

    source_names = sorted({source[0] for source in sources})

    if len(source_names) >= 2:
        correlation_severity = (
            indicator.severity
            if indicator.severity in ("high", "critical")
            else "medium"
        )

        alert = _upsert_alert(
            db=db,
            indicator=indicator,
            alert_type="multiple_sources",
            severity=correlation_severity,
            title="IOC reported by multiple sources",
            description=(
                f"IOC {indicator.value} was reported by "
                f"{len(source_names)} distinct sources: "
                f"{', '.join(source_names)}."
            ),
        )
        generated_alerts.append(alert)

    return generated_alerts


def evaluate_all_indicator_alerts(db: Session):
    """Evaluate alert rules for every stored IOC."""

    indicators = (
        db.query(IOCRecord)
        .order_by(IOCRecord.id)
        .all()
    )

    generated_alerts = []

    for indicator in indicators:
        generated_alerts.extend(
            evaluate_indicator_alerts(db, indicator)
        )

    return len(indicators), generated_alerts
