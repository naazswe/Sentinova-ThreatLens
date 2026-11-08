
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from backend.app.database import Base


class IOCRecord(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)

    indicator_type = Column(String(20), nullable=False)
    value = Column(String(253), nullable=False, index=True)

    source = Column(String(100), nullable=False)

    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)

    severity_score = Column(Integer, nullable=True)

    severity = Column(
        String(20),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )

    confidence = Column(Integer, nullable=True)

    __table_args__ = (
        Index(
            "uq_indicator_type_value",
            "indicator_type",
            "value",
            unique=True,
        ),
        {"sqlite_autoincrement": True},
    )


class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichments"

    id = Column(Integer, primary_key=True, index=True)

    indicator_id = Column(
        Integer,
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    provider = Column(String(50), nullable=False)

    abuse_confidence_score = Column(Integer, nullable=False)

    total_reports = Column(Integer, nullable=True)

    num_distinct_users = Column(Integer, nullable=True)

    last_reported_at = Column(DateTime(timezone=True), nullable=True)

    lookup_at = Column(DateTime(timezone=True), nullable=False)

    raw_data = Column(Text, nullable=False)

    __table_args__ = (
        Index(
            "ix_ioc_enrichments_provider_lookup",
            "provider",
            "lookup_at",
        ),
    )

class IOCSource(Base):
    """Track every feed source that has reported an IOC."""

    __tablename__ = "ioc_sources"

    id = Column(Integer, primary_key=True, index=True)

    indicator_id = Column(
        Integer,
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
    )

    source = Column(String(100), nullable=False)

    first_seen = Column(DateTime(timezone=True), nullable=False)

    last_seen = Column(DateTime(timezone=True), nullable=False)

    indicator = relationship("IOCRecord")

    __table_args__ = (
        Index(
            "uq_ioc_sources_indicator_source",
            "indicator_id",
            "source",
            unique=True,
        ),
    )

class IOCAlert(Base):
    """Persist alerts generated from IOC correlation and threat evidence."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    indicator_id = Column(
        Integer,
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
    )

    alert_type = Column(String(50), nullable=False)

    severity = Column(String(20), nullable=False)

    title = Column(String(200), nullable=False)

    description = Column(Text, nullable=False)

    status = Column(
        String(20),
        nullable=False,
        default="open",
        server_default="open",
    )

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
    )

    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )

    __table_args__ = (
        Index(
            "uq_alerts_indicator_type",
            "indicator_id",
            "alert_type",
            unique=True,
        ),
    )
