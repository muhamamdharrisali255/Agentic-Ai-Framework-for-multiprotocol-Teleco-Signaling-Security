"""PostgreSQL connection and schema bootstrap."""

from __future__ import annotations

import re
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from app.config.settings import settings

_MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_conn: Any = None


def _import_psycopg():
    try:
        import psycopg
        from psycopg.rows import dict_row

        return psycopg, dict_row
    except ImportError:
        return None, None


def is_available() -> bool:
    psycopg, _ = _import_psycopg()
    if not psycopg or not settings.postgres_dsn:
        return False
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return True
    except Exception:
        return False


@contextmanager
def get_connection() -> Generator[Any, None, None]:
    psycopg, _ = _import_psycopg()
    if not psycopg:
        raise RuntimeError("psycopg not installed")
    conn = psycopg.connect(settings.postgres_dsn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema() -> None:
    if not _MIGRATIONS_DIR.exists():
        return
    for path in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        sql = path.read_text()
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)


def fetch_all(sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    psycopg, dict_row = _import_psycopg()
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())


def fetch_one(sql: str, params: tuple = ()) -> Optional[dict[str, Any]]:
    rows = fetch_all(sql, params)
    return rows[0] if rows else None


def execute(sql: str, params: tuple = ()) -> int:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount


def backend_name() -> str:
    return "postgres" if is_available() else "unavailable"
