from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    abuseipdb_api_key: str | None = None
    abuseipdb_base_url: str = (
        "https://api.abuseipdb.com/api/v2"
    )
    abuseipdb_timeout: float = 10.0
    abuseipdb_max_age_days: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
