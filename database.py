import os
import logging
import re
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:///database.db"
)

engine_options = {}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}

engine = create_engine(SQLALCHEMY_DATABASE_URL, **engine_options)


def _configure_database_logger():
    """Create a small support log without recording query parameter values."""
    log_dir = Path(__file__).resolve().parent / "logs"
    log_dir.mkdir(exist_ok=True)

    logger = logging.getLogger("system_control_center.database")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = RotatingFileHandler(
            log_dir / "log.txt",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(handler)

    return logger


database_logger = _configure_database_logger()


def _loggable_statement(statement: str) -> str:
    """Keep SQL readable and bounded; never include bound parameter values."""
    compact = re.sub(r"\s+", " ", statement).strip()
    return compact[:1000] + ("..." if len(compact) > 1000 else "")


def _operation_name(statement: str) -> str:
    match = re.match(r"\s*([A-Za-z]+)", statement)
    return match.group(1).upper() if match else "SQL"


@event.listens_for(engine, "before_cursor_execute")
def _database_operation_started(conn, cursor, statement, parameters, context, executemany):
    conn.info.setdefault("_database_log_starts", []).append(time.perf_counter())


@event.listens_for(engine, "after_cursor_execute")
def _database_operation_finished(conn, cursor, statement, parameters, context, executemany):
    starts = conn.info.get("_database_log_starts", [])
    started_at = starts.pop() if starts else time.perf_counter()
    elapsed_ms = (time.perf_counter() - started_at) * 1000
    database_logger.info(
        "status=success operation=%s duration_ms=%.1f rows=%s sql=%s",
        _operation_name(statement),
        elapsed_ms,
        cursor.rowcount,
        _loggable_statement(statement),
    )


@event.listens_for(engine, "handle_error")
def _database_operation_failed(exception_context):
    conn = exception_context.connection
    starts = conn.info.get("_database_log_starts", [])
    started_at = starts.pop() if starts else time.perf_counter()
    elapsed_ms = (time.perf_counter() - started_at) * 1000
    database_logger.error(
        "status=error operation=%s duration_ms=%.1f error=%s sql=%s",
        _operation_name(exception_context.statement or "SQL"),
        elapsed_ms,
        type(exception_context.original_exception).__name__,
        _loggable_statement(exception_context.statement or ""),
    )


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
