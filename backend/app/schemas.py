
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.app.indicators import validate_ip, validate_domain


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"


class Indicator(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    indicator_type: IndicatorType
    value: str
    source: str = Field(default="manual", max_length=100)

    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value, info):
        indicator_type = info.data.get("indicator_type")

        if indicator_type == IndicatorType.IP:
            return validate_ip(value)

        if indicator_type == IndicatorType.DOMAIN:
            return validate_domain(value)

        return value

    @field_validator("source")
    @classmethod
    def validate_source(cls, value):
        source = value.strip()

        if not source:
            raise ValueError("Source cannot be empty")

        return source
    @field_validator(
        "first_seen",
        "last_seen",
        "created_at",
    )
    @classmethod
    def normalize_timestamps(cls, value):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)
    @model_validator(mode="after")
    def validate_timestamps(self):
        if self.last_seen < self.first_seen:
            raise ValueError(
                "last_seen cannot be earlier than first_seen"
            )

        return self
