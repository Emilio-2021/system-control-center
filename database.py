import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:///database.db"
)

engine_options = {}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}

engine = create_engine(SQLALCHEMY_DATABASE_URL, **engine_options)


def _ensure_sqlite_roles():
    """Add the role column to an existing local SQLite database once."""
    if not SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
        return
    with engine.begin() as connection:
        users_table = connection.execute(text(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        )).scalar()
        if not users_table:
            return
        columns = {row[1] for row in connection.execute(text("PRAGMA table_info(users)"))}
        if "role" not in columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'operator'"
            ))
        connection.execute(text(
            "UPDATE users SET role = 'admin' WHERE username = 'admin' AND role != 'admin'"
        ))


def _ensure_sqlite_refund_tables():
    """Create local refund tables without changing the original order records."""
    if not SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
        return
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS order_refunds (
                id INTEGER PRIMARY KEY,
                order_id INTEGER NOT NULL UNIQUE,
                refunded_by INTEGER,
                reason VARCHAR(255),
                amount NUMERIC(10, 2) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS order_refund_items (
                id INTEGER PRIMARY KEY,
                refund_id INTEGER NOT NULL,
                order_item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price NUMERIC(10, 2) NOT NULL
            )
        """))


_ensure_sqlite_roles()
_ensure_sqlite_refund_tables()
SessionLocal = sessionmaker(autocommit=False,autoflush=False,bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()   
