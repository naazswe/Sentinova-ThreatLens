
from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    String,
)

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

    __table_args__ = (
        Index(
            "uq_indicator_type_value",
            "indicator_type",
            "value",
            unique=True,
        ),
        {"sqlite_autoincrement": True},
    )
