import json

import pytest

from backend.app.feeds.csv_parser import parse_csv_feed
from backend.app.feeds.parser import parse_feed_payload
from backend.app.models import IOCRecord, IOCSource
from backend.app.services.feed_ingestion import ingest_csv_feed


def test_parse_feed_payload():
    with open("sample-data/sample_feed.json", encoding="utf-8") as file:
        payload = json.load(file)

    accepted, rejected = parse_feed_payload(payload, "TestFeed")

    assert len(accepted) == 3
    assert len(rejected) == 1

    assert all(item.source == "TestFeed" for item in accepted)
    assert rejected[0]["index"] == 2


def test_feed_ingestion_inserts_and_updates(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.app.database import Base
    from backend.app.services.feed_ingestion import ingest_feed_payload

    database_path = tmp_path / "feed_test.db"

    test_engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine,
    )

    Base.metadata.create_all(bind=test_engine)

    try:
        with open(
            "sample-data/sample_feed.json",
            encoding="utf-8",
        ) as file:
            payload = json.load(file)

        with TestingSessionLocal() as db:
            first_result = ingest_feed_payload(
                db, payload, "TestFeed"
            )

            assert first_result["received"] == 4
            assert first_result["inserted"] == 3
            assert first_result["updated"] == 0
            assert first_result["rejected"] == 1

            second_result = ingest_feed_payload(
                db, payload, "TestFeed"
            )

            assert second_result["inserted"] == 0
            assert second_result["updated"] == 3
            assert second_result["rejected"] == 1

            third_result = ingest_feed_payload(
                db,
                payload,
                "SecondFeed",
            )

            assert third_result["inserted"] == 0
            assert third_result["updated"] == 3
            assert third_result["rejected"] == 1

            source_records = db.query(IOCSource).all()

            assert len(source_records) == 6

            recorded_sources = {
                observation.source
                for observation in source_records
            }

            assert recorded_sources == {
                "TestFeed",
                "SecondFeed",
            }

    finally:
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


def test_parse_csv_feed():
    csv_content = """indicator_type,value
ip,185.220.101.1
domain,malicious-example.com
domain,invalid_domain
ip,8.8.8.8
"""

    accepted, rejected, received = parse_csv_feed(
        csv_content,
        "CSVTestFeed",
    )

    assert received == 4
    assert len(accepted) == 3
    assert len(rejected) == 1

    assert all(
        indicator.source == "CSVTestFeed"
        for indicator in accepted
    )

    assert rejected[0]["index"] == 2


def test_parse_csv_feed_rejects_missing_columns():
    csv_content = """type,address
ip,8.8.8.8
"""

    with pytest.raises(ValueError):
        parse_csv_feed(csv_content, "CSVTestFeed")


def test_parse_csv_feed_rejects_empty_content():
    with pytest.raises(ValueError):
        parse_csv_feed("", "CSVTestFeed")


def test_csv_feed_ingestion_persists_source_history(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.app.database import Base

    database_path = tmp_path / "csv_feed_test.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    TestingSession = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )

    Base.metadata.create_all(bind=engine)

    db = TestingSession()

    try:
        csv_content = """indicator_type,value
ip,185.220.101.1
domain,malicious-example.com
domain,invalid_domain
ip,8.8.8.8
"""

        result = ingest_csv_feed(
            db,
            csv_content,
            "CSVTestFeed",
        )

        assert result["received"] == 4
        assert result["inserted"] == 3
        assert result["updated"] == 0
        assert result["rejected"] == 1

        assert db.query(IOCRecord).count() == 3
        assert db.query(IOCSource).count() == 3

    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
