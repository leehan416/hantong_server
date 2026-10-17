import sqlite3

from typing_extensions import override

from app.relay.ports import RefreshStore, StoredGrant, StoredSpent


class SqliteRefreshStore(RefreshStore):
    """Single-file store for the single-process relay.

    ponytail: writes run synchronously on the event loop; they are tiny local commits at
    refresh/login rate. Move them to a thread (or a server DB) if write latency ever shows up.
    """

    def __init__(self, path: str) -> None:
        # Autocommit: every write is its own durable transaction.
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS refresh_grants (digest TEXT PRIMARY KEY,"
            " subject TEXT NOT NULL, email TEXT NOT NULL, installation_id TEXT NOT NULL,"
            " expires_at REAL NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS spent_refresh (digest TEXT PRIMARY KEY, subject TEXT"
            " NOT NULL, installation_id TEXT NOT NULL, expires_at REAL NOT NULL)"
        )

    @override
    def load(self) -> tuple[list[StoredGrant], list[StoredSpent]]:
        grants = [StoredGrant(*row) for row in self.db.execute("SELECT * FROM refresh_grants")]
        spent = [StoredSpent(*row) for row in self.db.execute("SELECT * FROM spent_refresh")]
        return grants, spent

    @override
    def put_grant(self, grant: StoredGrant) -> None:
        self.db.execute("INSERT OR REPLACE INTO refresh_grants VALUES (?, ?, ?, ?, ?)", grant)

    @override
    def put_spent(self, spent: StoredSpent) -> None:
        self.db.execute("INSERT OR REPLACE INTO spent_refresh VALUES (?, ?, ?, ?)", spent)

    @override
    def delete(self, digest: str) -> None:
        self.db.execute("DELETE FROM refresh_grants WHERE digest = ?", (digest,))
        self.db.execute("DELETE FROM spent_refresh WHERE digest = ?", (digest,))

    @override
    def delete_expired(self, now: float) -> None:
        self.db.execute("DELETE FROM refresh_grants WHERE expires_at <= ?", (now,))
        self.db.execute("DELETE FROM spent_refresh WHERE expires_at <= ?", (now,))
