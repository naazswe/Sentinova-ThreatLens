import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker


DATABASE_URL = (
    os.getenv("DATABASE_URL")
    or "sqlite:///./sentinova.db"
)


def enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    """Enable foreign-key enforcement for each SQLite connection."""

    cursor = dbapi_connection.cursor()

    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

event.listen(
    engine,
    "connect",
    enable_sqlite_foreign_keys,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
