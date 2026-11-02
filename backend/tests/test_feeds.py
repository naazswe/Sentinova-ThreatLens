import json

from backend.app.feeds.parser import parse_feed_payload


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

    finally:
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()