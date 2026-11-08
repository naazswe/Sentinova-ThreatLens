# Sentinova ThreatLens

## 1. Project Overview

Sentinova ThreatLens is a Python-based Cyber Threat Intelligence (CTI)
backend that helps security analysts collect, normalize, enrich, score,
and monitor Indicators of Compromise (IOCs).

The project demonstrates a practical workflow for processing threat
intelligence and generating actionable security alerts.

## 2. Objectives

- Ingest IOC data from JSON and CSV feeds.
- Validate and normalize IOC records.
- Detect and prevent duplicate indicators.
- Maintain IOC source provenance and observation history.
- Enrich IP indicators using AbuseIPDB.
- Calculate explainable threat scores and severity classifications.
- Correlate indicators and generate alerts.
- Provide analyst APIs for searching, filtering, sorting, and pagination.
- Export indicator records to CSV.

## 3. Technology Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite
- Alembic
- Pydantic and Pydantic Settings
- Pytest
- HTTPX
- AbuseIPDB API

## 4. Project Structure

    Sentinova-ThreatLens/
    |-- backend/
    |   |-- app/
    |   |   |-- feeds/
    |   |   |-- services/
    |   |   |-- config.py
    |   |   |-- database.py
    |   |   |-- indicators.py
    |   |   |-- main.py
    |   |   |-- models.py
    |   |   |-- schemas.py
    |   |-- tests/
    |-- migrations/
    |   |-- versions/
    |-- sample-data/
    |   |-- sample_feed.csv
    |   |-- sample_feed.json
    |-- backups/                 # Local database backups; not committed
    |-- demo-data/               # Local demonstration database; not committed
    |-- .env.example
    |-- .gitignore
    |-- alembic.ini
    |-- README.md
    |-- requirements.txt

## 5. Environment Setup

Create a virtual environment:

    python -m venv .venv

Activate it in Windows PowerShell:

    .\.venv\Scripts\Activate.ps1

Install dependencies:

    python -m pip install -r requirements.txt

## 6. Environment Configuration

Copy the example configuration:

    Copy-Item .env.example .env

Set your own AbuseIPDB API key in the local .env file if you intend
to use external enrichment.

Supported settings:

- ABUSEIPDB_API_KEY
- ABUSEIPDB_BASE_URL
- ABUSEIPDB_TIMEOUT
- ABUSEIPDB_MAX_AGE_DAYS

The API key is optional for starting the application and using its
other endpoints. An AbuseIPDB lookup requires a configured key.

Never commit .env files, API keys, or other credentials.

## 7. Database and Migrations

The application uses SQLite for persistence and Alembic for schema
migration management.

The migration baseline in this project represents an existing
database schema. It is not a complete initial schema migration for
an empty database.

### Existing project database

For an existing database already managed by this migration history:

    alembic current

Review the current revision before applying any pending migration:

    alembic upgrade head

Back up the database before applying schema changes.

### New empty database

For a new empty SQLite database, initialize the current ORM schema
once and then mark the migration history at its current head.

Run these commands from the project root:

    python -c "from backend.app.database import Base, engine; from backend.app import models; Base.metadata.create_all(bind=engine)"

    alembic stamp head

This is a one-time database bootstrap procedure. It is not part of
application startup. Do not run it against an existing database.

If using a custom DATABASE_URL, configure it in the environment
before running the bootstrap or Alembic commands.

## 8. Running the Application

Start the FastAPI application:

    uvicorn backend.app.main:app --reload

Open the interactive API documentation:

    http://127.0.0.1:8000/docs

## 9. API Capabilities

| Capability | Endpoint |
|---|---|
| Health check | GET /health |
| Create indicator | POST /indicators |
| List and filter indicators | GET /indicators |
| Export indicators as CSV | GET /indicators/export/csv |
| JSON feed ingestion | POST /feeds/ingest |
| CSV feed ingestion | POST /feeds/ingest/csv |
| AbuseIPDB enrichment | POST /indicators/{indicator_id}/enrich/abuseipdb |
| Enrichment history | GET /indicators/{indicator_id}/enrichments |
| List alerts | GET /alerts |
| Indicator alerts | GET /indicators/{indicator_id}/alerts |
| Evaluate alerts | POST /alerts/evaluate |
| Update alert status | PATCH /alerts/{alert_id}/status |

Refer to the interactive API documentation for request parameters,
schemas, and response details.

## 10. Testing

Run the complete automated test suite:

    python -m pytest -q

Latest verified development result: 94 tests passed.

## 11. Security Considerations

- API credentials are configured through environment variables.
- Local secrets and database files are excluded from Git.
- IOC input is validated through application schemas.
- Database schema changes are managed through Alembic.
- SQLite foreign-key enforcement is enabled for application connections.
- Alert status values are restricted to supported states.
- CSV exports include protection against common spreadsheet formula
  injection prefixes.
- External enrichment depends on provider availability, API credentials,
  and rate limits.

## 12. Current Scope and Limitations

Sentinova ThreatLens is a practical CTI backend MVP and cybersecurity
internship project.

Implemented and tested capabilities include IOC ingestion, validation,
deduplication, enrichment integration, threat scoring, source provenance,
alert generation, analyst APIs, filtering, pagination, and CSV export.

This implementation is not a fully production-hardened enterprise SOC
platform. A complete frontend dashboard, role-based access control,
WebSocket updates, additional enrichment providers, and enterprise
SIEM/EDR integrations remain potential future enhancements.

## 13. Project Status

Core backend functionality and automated tests have been implemented.

The final project review covers functional validation, database integrity,
configuration protection, documentation, and demonstration readiness.
