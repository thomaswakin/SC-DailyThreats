"""SQLite connection management and schema initialization."""

import sqlite3
import logging
from pathlib import Path

log = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class Database:
    def __init__(self, db_path: str | Path = "data/db/threats.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> "Database":
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()
        log.info("Connected to database: %s", self.db_path)
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Database":
        return self.connect()

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected. Use connect() or context manager.")
        return self._conn

    def _init_schema(self) -> None:
        schema = _SCHEMA_PATH.read_text()
        self.conn.executescript(schema)
        # Migrate existing DBs that predate new columns
        ioc_cols = {row[1] for row in self.conn.execute("PRAGMA table_info(iocs)")}
        if "specificity" not in ioc_cols:
            self.conn.execute("ALTER TABLE iocs ADD COLUMN specificity TEXT DEFAULT 'unknown'")
        if "specificity_note" not in ioc_cols:
            self.conn.execute("ALTER TABLE iocs ADD COLUMN specificity_note TEXT DEFAULT ''")
        if "tags" not in ioc_cols:
            self.conn.execute("ALTER TABLE iocs ADD COLUMN tags TEXT DEFAULT '[]'")

        existing = {row[1] for row in self.conn.execute("PRAGMA table_info(intel_items)")}
        if "detection_artifacts" not in existing:
            self.conn.execute(
                "ALTER TABLE intel_items ADD COLUMN detection_artifacts TEXT DEFAULT '[]'"
            )
        # Migrate: ensure sigma_rule_registry table exists (added in v2)
        tables = {row[0] for row in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if "sigma_rule_registry" not in tables:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS sigma_rule_registry (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    stable_key      TEXT    UNIQUE NOT NULL,
                    rule_id         TEXT    NOT NULL,
                    title           TEXT    NOT NULL,
                    version         INTEGER DEFAULT 1,
                    first_generated TEXT    NOT NULL,
                    last_updated    TEXT    NOT NULL,
                    source_count    INTEGER DEFAULT 1,
                    cluster_id      INTEGER,
                    output_path     TEXT    DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_rule_registry_key ON sigma_rule_registry(stable_key);
                CREATE INDEX IF NOT EXISTS idx_rule_registry_cluster ON sigma_rule_registry(cluster_id);
            """)
        # Migrate: ensure source_candidates table exists (added in v3)
        tables = {row[0] for row in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if "source_candidates" not in tables:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS source_candidates (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    url            TEXT    UNIQUE NOT NULL,
                    domain         TEXT    NOT NULL,
                    name           TEXT    DEFAULT '',
                    status         TEXT    DEFAULT 'pending',
                    discovered_via TEXT    DEFAULT '',
                    citation_count INTEGER DEFAULT 0,
                    llm_verdict    TEXT    DEFAULT '',
                    reliability    TEXT    DEFAULT '',
                    suggested_tags TEXT    DEFAULT '[]',
                    first_seen     TEXT    NOT NULL,
                    evaluated_at   TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_source_candidates_status ON source_candidates(status);
                CREATE INDEX IF NOT EXISTS idx_source_candidates_domain ON source_candidates(domain);
            """)
        self.conn.commit()
