import sqlite3
from typing import Optional

from typing_extensions import override

from app.relay.ports import RefreshStore, StoredGrant, StoredSpent


class SqliteRefreshStore(RefreshStore):
    """Single-file store for the single-process relay.

    ponytail: writes run synchronously on the event loop; they are tiny local commits at
    refresh/login rate. Move them to a thread (or a server DB) if write latency ever shows up.
    """

    def __init__(self, path: str) -> None:
        # Individual mutations commit explicitly so rotation can update both tables atomically.
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS refresh_grants (digest TEXT PRIMARY KEY,"
            " subject TEXT NOT NULL, email TEXT NOT NULL, installation_id TEXT NOT NULL,"
            " expires_at REAL NOT NULL, generation_id TEXT)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS spent_refresh (digest TEXT PRIMARY KEY, subject TEXT"
            " NOT NULL, installation_id TEXT NOT NULL, expires_at REAL NOT NULL,"
            " generation_id TEXT)"
        )
        self._add_generation_column("refresh_grants")
        self._add_generation_column("spent_refresh")

    def _add_generation_column(self, table: str) -> None:
        columns = {row[1] for row in self.db.execute(f"PRAGMA table_info({table})")}
        if "generation_id" not in columns:
            self.db.execute(f"ALTER TABLE {table} ADD COLUMN generation_id TEXT")

    @override
    def load(self) -> tuple[list[StoredGrant], list[StoredSpent]]:
        grants = [
            StoredGrant(*row)
            for row in self.db.execute(
                "SELECT digest, subject, email, installation_id, expires_at, generation_id "
                "FROM refresh_grants"
            )
        ]
        spent = [
            StoredSpent(*row)
            for row in self.db.execute(
                "SELECT digest, subject, installation_id, expires_at, generation_id "
                "FROM spent_refresh"
            )
        ]
        return grants, spent

    @override
    def put_grant(self, grant: StoredGrant) -> None:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO refresh_grants VALUES (?, ?, ?, ?, ?, ?)", grant
            )

    @override
    def put_spent(self, spent: StoredSpent) -> None:
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO spent_refresh VALUES (?, ?, ?, ?, ?)", spent)

    @override
    def rotate(
        self,
        old_digest: str,
        spent: StoredSpent,
        grant: StoredGrant,
        evict_spent_digest: Optional[str] = None,
    ) -> None:
        with self.db:
            if evict_spent_digest:
                self.db.execute("DELETE FROM spent_refresh WHERE digest = ?", (evict_spent_digest,))
            self.db.execute("DELETE FROM refresh_grants WHERE digest = ?", (old_digest,))
            self.db.execute("INSERT OR REPLACE INTO spent_refresh VALUES (?, ?, ?, ?, ?)", spent)
            self.db.execute(
                "INSERT OR REPLACE INTO refresh_grants VALUES (?, ?, ?, ?, ?, ?)", grant
            )

    @override
    def replace_grant(
        self, old_digest: str, grant: StoredGrant, subject: str, installation_id: str
    ) -> None:
        with self.db:
            if old_digest:
                self.db.execute("DELETE FROM refresh_grants WHERE digest = ?", (old_digest,))
            self.db.execute(
                "DELETE FROM spent_refresh WHERE subject = ? AND installation_id = ?",
                (subject, installation_id),
            )
            self.db.execute(
                "INSERT OR REPLACE INTO refresh_grants VALUES (?, ?, ?, ?, ?, ?)", grant
            )

    @override
    def revoke_installation(
        self, old_digest: Optional[str], subject: str, installation_id: str
    ) -> None:
        with self.db:
            if old_digest:
                self.db.execute("DELETE FROM refresh_grants WHERE digest = ?", (old_digest,))
            self.db.execute(
                "DELETE FROM spent_refresh WHERE subject = ? AND installation_id = ?",
                (subject, installation_id),
            )

    @override
    def delete(self, digest: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM refresh_grants WHERE digest = ?", (digest,))
            self.db.execute("DELETE FROM spent_refresh WHERE digest = ?", (digest,))

    @override
    def delete_expired(self, now: float) -> None:
        with self.db:
            self.db.execute("DELETE FROM refresh_grants WHERE expires_at <= ?", (now,))
            self.db.execute("DELETE FROM spent_refresh WHERE expires_at <= ?", (now,))
