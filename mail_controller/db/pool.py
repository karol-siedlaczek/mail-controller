import logging
from contextlib import contextmanager
from typing import cast
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor
from flask import current_app as app, g

log = logging.getLogger(__name__)


class Database:
    def __init__(self, host: str, port: int, dbname: str, user: str, password: str) -> None:
        self._pool = ThreadedConnectionPool(
            minconn=1, maxconn=8,
            host=host, port=port, dbname=dbname, user=user, password=password,
        )

    @contextmanager
    def transaction(self):
        conn = self._pool.getconn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def closeall(self) -> None:
        self._pool.closeall()

    @staticmethod
    def get_from_global_context() -> "Database":
        if "db" not in g:
            g.db = cast("Database", app.extensions["db"])
        return g.db
