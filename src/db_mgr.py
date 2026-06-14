"""SQLite state manager for edo.

Tracks the two pieces of state edo cares about across restarts:
  * peers      — WireGuard clients (the "bound vessels")
  * containers — running challenges (the "reanimated")

All access is funnelled through a single re-entrant lock so concurrent CLI
invocations cannot trample each other's transactions, and every write runs
inside an explicit BEGIN/COMMIT block with ROLLBACK on exception.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path("/var/lib/edo/edo.db")

# Bump when the schema changes; add a matching branch in _migrate(). Tracked
# via SQLite's built-in PRAGMA user_version so no extra bookkeeping table is
# needed.
#   v1: original peers/containers schema (private_key NOT NULL)
#   v2: peers.private_key nullable (client-side key support, S1)
SCHEMA_VERSION = 2


@dataclass
class Peer:
    id: int
    username: str
    ip_address: str
    public_key: str
    # None when the participant generated their own keypair and only gave us
    # the public key — the server never holds their private key in that mode.
    private_key: Optional[str]


@dataclass
class Container:
    id: int
    container_id: str
    challenge_name: str
    source_path: str
    assigned_ip: str
    status: str


class DatabaseManager:
    """Thread-safe SQLite wrapper. One instance per process is fine."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # isolation_level=None puts us in manual-transaction mode; we drive
        # BEGIN/COMMIT/ROLLBACK ourselves so the contextmanager can guarantee
        # rollback on any exception thrown by the caller's block.
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("BEGIN")
            try:
                yield conn
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def _init_schema(self) -> None:
        with self._conn() as c:
            # Fresh installs get the latest schema directly (private_key
            # nullable). Pre-existing installs created these tables with the
            # old constraint; _migrate() upgrades them in place.
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS peers (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    username    TEXT UNIQUE NOT NULL,
                    ip_address  TEXT UNIQUE NOT NULL,
                    public_key  TEXT NOT NULL,
                    private_key TEXT,
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS containers (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    container_id   TEXT UNIQUE NOT NULL,
                    challenge_name TEXT NOT NULL,
                    source_path    TEXT NOT NULL,
                    assigned_ip    TEXT NOT NULL,
                    status         TEXT NOT NULL DEFAULT 'running',
                    deployed_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            self._migrate(c)
            c.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _migrate(self, c: sqlite3.Connection) -> None:
        """Bring a pre-existing DB up to ``SCHEMA_VERSION``.

        Runs inside the same transaction as ``_init_schema``. Each step is
        written to be idempotent so it's safe even if user_version wasn't
        stamped by an older edo (which never set it — those DBs report 0).
        """
        version = c.execute("PRAGMA user_version").fetchone()[0]
        logger.debug("db schema at user_version=%d (target %d)", version, SCHEMA_VERSION)

        # v1 -> v2: drop the NOT NULL on peers.private_key. SQLite can't
        # ALTER a column constraint, so rebuild the table when (and only
        # when) it still carries the old constraint.
        if self._column_notnull(c, "peers", "private_key"):
            logger.info("migrating peers table: private_key -> nullable")
            c.execute(
                """
                CREATE TABLE peers_new (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    username    TEXT UNIQUE NOT NULL,
                    ip_address  TEXT UNIQUE NOT NULL,
                    public_key  TEXT NOT NULL,
                    private_key TEXT,
                    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            c.execute(
                "INSERT INTO peers_new "
                "(id, username, ip_address, public_key, private_key, created_at) "
                "SELECT id, username, ip_address, public_key, private_key, created_at "
                "FROM peers"
            )
            c.execute("DROP TABLE peers")
            c.execute("ALTER TABLE peers_new RENAME TO peers")

    @staticmethod
    def _column_notnull(c: sqlite3.Connection, table: str, column: str) -> bool:
        for row in c.execute(f"PRAGMA table_info({table})"):
            if row["name"] == column:
                return bool(row["notnull"])
        return False

    # ---- peers -----------------------------------------------------------
    def add_peer(
        self,
        username: str,
        ip_address: str,
        public_key: str,
        private_key: Optional[str] = None,
    ) -> Peer:
        try:
            with self._conn() as c:
                cur = c.execute(
                    "INSERT INTO peers (username, ip_address, public_key, private_key)"
                    " VALUES (?, ?, ?, ?)",
                    (username, ip_address, public_key, private_key),
                )
                peer_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as e:
            raise ValueError(f"peer record collision: {e}") from e
        return Peer(
            id=peer_id,
            username=username,
            ip_address=ip_address,
            public_key=public_key,
            private_key=private_key,
        )

    def remove_peer(self, username: str) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM peers WHERE username = ?", (username,))
            return cur.rowcount > 0

    def get_peer(self, username: str) -> Optional[Peer]:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM peers WHERE username = ?", (username,)
            ).fetchone()
        return _row_to_peer(row) if row else None

    def get_all_peers(self) -> List[Peer]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM peers ORDER BY id").fetchall()
        return [_row_to_peer(r) for r in rows]

    def get_used_peer_ips(self) -> List[str]:
        with self._conn() as c:
            rows = c.execute("SELECT ip_address FROM peers").fetchall()
        return [r["ip_address"] for r in rows]

    # ---- containers ------------------------------------------------------
    def add_container(
        self,
        container_id: str,
        challenge_name: str,
        source_path: str,
        assigned_ip: str,
        status: str = "running",
    ) -> Container:
        try:
            with self._conn() as c:
                cur = c.execute(
                    "INSERT INTO containers"
                    " (container_id, challenge_name, source_path, assigned_ip, status)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (container_id, challenge_name, source_path, assigned_ip, status),
                )
                row_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as e:
            raise ValueError(f"container record collision: {e}") from e
        return Container(
            id=row_id,
            container_id=container_id,
            challenge_name=challenge_name,
            source_path=source_path,
            assigned_ip=assigned_ip,
            status=status,
        )

    def remove_container(self, container_id: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM containers WHERE container_id = ?", (container_id,)
            )
            return cur.rowcount > 0

    def get_active_containers(self) -> List[Container]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM containers WHERE status = 'running' ORDER BY id"
            ).fetchall()
        return [_row_to_container(r) for r in rows]

    def get_all_containers(self) -> List[Container]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM containers ORDER BY id").fetchall()
        return [_row_to_container(r) for r in rows]

    def get_used_container_ips(self) -> List[str]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT assigned_ip FROM containers WHERE status = 'running'"
            ).fetchall()
        return [r["assigned_ip"] for r in rows]

    def update_container_status(self, container_id: str, status: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE containers SET status = ? WHERE container_id = ?",
                (status, container_id),
            )
            return cur.rowcount > 0


def _row_to_peer(row: sqlite3.Row) -> Peer:
    return Peer(
        id=row["id"],
        username=row["username"],
        ip_address=row["ip_address"],
        public_key=row["public_key"],
        private_key=row["private_key"],
    )


def _row_to_container(row: sqlite3.Row) -> Container:
    return Container(
        id=row["id"],
        container_id=row["container_id"],
        challenge_name=row["challenge_name"],
        source_path=row["source_path"],
        assigned_ip=row["assigned_ip"],
        status=row["status"],
    )
