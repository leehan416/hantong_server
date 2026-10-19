import os
import sqlite3
import tempfile
import unittest

from app.auth.exceptions import CapacityExceededError, InvalidCredentialsError
from app.relay.adapters.sqlite_refresh_store import SqliteRefreshStore
from app.relay.service import RelayService, digest_of
from tests.fakes import INSTALLATION_ID

OTHER_INSTALLATION_ID = "123e4567-e89b-42d3-a456-426614174001"


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.relay = RelayService(clock=lambda: self.now)

    def test_nonce_is_single_use_and_expires(self):
        nonce = self.relay.create_challenge()
        self.assertTrue(self.relay.consume_challenge(nonce))
        self.assertFalse(self.relay.consume_challenge(nonce))
        nonce = self.relay.create_challenge()
        self.now += 301
        self.assertFalse(self.relay.consume_challenge(nonce))

    def test_session_token_is_stored_as_hash_only(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        self.assertNotIn(issued.access_token, repr(list(self.relay.sessions)))
        self.assertEqual(issued.expires_in, 1000)

    def test_session_lifetime_is_capped(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 1_000_000)
        self.assertEqual(issued.expires_in, RelayService.SESSION_TTL_SECONDS)

    def test_mailbox_fanout_coalesces_and_deduplicates(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        session = self.relay.authenticate(issued.access_token)
        self.relay.publish("x", "A@gmail.com", "123")
        self.relay.publish("y", "a@gmail.com", "124")
        self.assertEqual(session.queue.get_nowait(), "124")
        self.assertFalse(self.relay.publish("y", "a@gmail.com", "125"))

    def test_expired_session_is_rejected(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 1100)
        self.now = 1101
        with self.assertRaises(InvalidCredentialsError):
            self.relay.authenticate(issued.access_token)

    def test_login_from_same_installation_replaces_prior_session(self):
        one = self.relay.create_session("s1", "a@gmail.com", INSTALLATION_ID, 2000)
        two = self.relay.create_session("s2", "b@gmail.com", OTHER_INSTALLATION_ID, 2000)
        rotated = self.relay.create_session("s1", "a@gmail.com", INSTALLATION_ID, 2000)
        with self.assertRaises(InvalidCredentialsError):
            self.relay.authenticate(one.access_token)
        self.relay.publish("m1", "a@gmail.com", "123")
        self.assertEqual(self.relay.authenticate(rotated.access_token).queue.get_nowait(), "123")
        self.assertTrue(self.relay.authenticate(two.access_token).queue.empty())

    def test_close_revokes_sessions_and_signals_streams(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        session = self.relay.authenticate(issued.access_token)
        self.relay.close()
        self.assertTrue(session.revoked)
        self.assertIsNone(session.queue.get_nowait())
        with self.assertRaises(InvalidCredentialsError):
            self.relay.authenticate(issued.access_token)

    def test_per_subject_session_limit(self):
        for index in range(RelayService.MAX_SESSIONS_PER_SUBJECT):
            installation_id = f"123e4567-e89b-42d3-a456-4266141740{index:02x}"
            self.relay.create_session("s", "a@gmail.com", installation_id, 2000)
        with self.assertRaises(CapacityExceededError):
            self.relay.create_session(
                "s", "a@gmail.com", "123e4567-e89b-42d3-a456-426614174099", 2000
            )

    def test_per_subject_refresh_grant_limit_is_eight(self):
        self.relay.MAX_SESSIONS_PER_SUBJECT = 100
        for index in range(RelayService.MAX_REFRESH_GRANTS_PER_SUBJECT):
            installation_id = f"123e4567-e89b-42d3-a456-4266141740{index:02x}"
            self.relay.create_session("s", "a@gmail.com", installation_id, 2000)

        with self.assertRaises(CapacityExceededError):
            self.relay.create_session(
                "s", "a@gmail.com", "123e4567-e89b-42d3-a456-426614174099", 2000
            )

    def test_refresh_rotates_into_a_new_session_and_is_single_use(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 1100)
        self.assertNotIn(issued.refresh_token, repr(list(self.relay.refresh_grants)))
        self.now = 1200  # past the ID-token-bound session, inside the refresh lifetime
        refreshed = self.relay.refresh(issued.refresh_token)
        self.assertEqual(refreshed.expires_in, RelayService.SESSION_TTL_SECONDS)
        self.assertNotEqual(refreshed.refresh_token, issued.refresh_token)
        session = self.relay.authenticate(refreshed.access_token)
        self.relay.publish("m1", "a@gmail.com", "123")
        self.assertEqual(session.queue.get_nowait(), "123")

    def test_replayed_refresh_revokes_the_installation(self):
        # Reuse of a rotated credential means it leaked: end both the thief's and the owner's chain.
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        rotated = self.relay.refresh(issued.refresh_token)
        with self.assertRaises(InvalidCredentialsError):
            self.relay.refresh(issued.refresh_token)
        with self.assertRaises(InvalidCredentialsError):
            self.relay.authenticate(rotated.access_token)
        with self.assertRaises(InvalidCredentialsError):
            self.relay.refresh(rotated.refresh_token)

    def test_capacity_failure_does_not_consume_refresh_or_revoke_session(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        other = self.relay.create_session("other", "b@gmail.com", OTHER_INSTALLATION_ID, 2000)
        self.relay.MAX_SESSIONS = 1

        with self.assertRaises(CapacityExceededError):
            self.relay.refresh(issued.refresh_token)

        self.relay.authenticate(issued.access_token)
        self.relay.revoke(self.relay.authenticate(other.access_token))
        self.assertNotEqual(
            self.relay.refresh(issued.refresh_token).refresh_token, issued.refresh_token
        )

    def test_old_rotated_refresh_after_logout_and_login_does_not_revoke_new_session(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        rotated = self.relay.refresh(issued.refresh_token)
        self.relay.revoke(self.relay.authenticate(rotated.access_token))
        current = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)

        with self.assertRaises(InvalidCredentialsError):
            self.relay.refresh(rotated.refresh_token)
        self.relay.authenticate(current.access_token)

    def test_old_rotated_refresh_after_fresh_login_does_not_revoke_new_session(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        self.relay.refresh(issued.refresh_token)
        current = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)

        with self.assertRaises(InvalidCredentialsError):
            self.relay.refresh(issued.refresh_token)
        self.relay.authenticate(current.access_token)

    def test_refresh_expires_and_unknown_tokens_are_rejected(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        with self.assertRaises(InvalidCredentialsError):
            self.relay.refresh("unknown")
        self.now += RelayService.REFRESH_TTL_SECONDS
        with self.assertRaises(InvalidCredentialsError):
            self.relay.refresh(issued.refresh_token)

    def test_logout_revokes_the_refresh_credential(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        self.relay.revoke(self.relay.authenticate(issued.access_token))
        with self.assertRaises(InvalidCredentialsError):
            self.relay.refresh(issued.refresh_token)

    def test_fresh_login_supersedes_old_refresh_without_revoking_the_new_session(self):
        old = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        new = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        with self.assertRaises(InvalidCredentialsError):
            self.relay.refresh(old.refresh_token)
        self.relay.authenticate(new.access_token)
        self.relay.refresh(new.refresh_token)

    def test_session_expiry_keeps_the_refresh_credential(self):
        issued = self.relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 1100)
        self.now = 1101
        with self.assertRaises(InvalidCredentialsError):
            self.relay.authenticate(issued.access_token)
        self.relay.refresh(issued.refresh_token)


class SqliteRefreshPersistenceTests(unittest.TestCase):
    """Refresh grants must outlive a server restart; sessions deliberately do not."""

    def setUp(self):
        self.now = 1000.0
        self.directory = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.directory.name, "relay.sqlite3")

    def tearDown(self):
        self.directory.cleanup()

    def restart(self):
        return RelayService(lambda: self.now, SqliteRefreshStore(self.path))

    def test_refresh_token_survives_a_restart_but_the_session_does_not(self):
        relay = self.restart()
        issued = relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        relay.close()
        relay = self.restart()
        with self.assertRaises(InvalidCredentialsError):
            relay.authenticate(issued.access_token)
        refreshed = relay.refresh(issued.refresh_token)
        relay.publish("m1", "a@gmail.com", "123")
        self.assertEqual(relay.authenticate(refreshed.access_token).queue.get_nowait(), "123")

    def test_replay_detection_and_logout_survive_a_restart(self):
        relay = self.restart()
        issued = relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        rotated = relay.refresh(issued.refresh_token)
        relay = self.restart()
        with self.assertRaises(InvalidCredentialsError):
            relay.refresh(issued.refresh_token)
        with self.assertRaises(InvalidCredentialsError):
            relay.refresh(rotated.refresh_token)
        relay = self.restart()
        again = relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        relay.revoke(relay.authenticate(again.access_token))
        with self.assertRaises(InvalidCredentialsError):
            self.restart().refresh(again.refresh_token)

    def test_failed_rotation_write_rolls_back_all_refresh_state(self):
        relay = self.restart()
        issued = relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        old_digest = relay.refresh_by_installation[("s", INSTALLATION_ID)]
        store = relay.refresh_store
        store.db.execute(
            "CREATE TRIGGER reject_successor BEFORE INSERT ON refresh_grants "
            f"WHEN NEW.digest != '{old_digest}' BEGIN SELECT RAISE(ABORT, 'blocked'); END"
        )

        with self.assertRaises(sqlite3.IntegrityError):
            relay.refresh(issued.refresh_token)

        relay.authenticate(issued.access_token)
        grants, spent = store.load()
        self.assertEqual([grant.digest for grant in grants], [old_digest])
        self.assertEqual(spent, [])
        store.db.execute("DROP TRIGGER reject_successor")
        self.assertNotEqual(relay.refresh(issued.refresh_token).refresh_token, issued.refresh_token)

    def test_legacy_spent_marker_cannot_revoke_a_new_generation(self):
        db = sqlite3.connect(self.path)
        db.execute(
            "CREATE TABLE refresh_grants (digest TEXT PRIMARY KEY, subject TEXT NOT NULL,"
            " email TEXT NOT NULL, installation_id TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        db.execute(
            "CREATE TABLE spent_refresh (digest TEXT PRIMARY KEY, subject TEXT NOT NULL,"
            " installation_id TEXT NOT NULL, expires_at REAL NOT NULL)"
        )
        db.execute(
            "INSERT INTO refresh_grants VALUES (?, ?, ?, ?, ?)",
            (digest_of("current"), "s", "a@gmail.com", INSTALLATION_ID, 2000),
        )
        db.execute(
            "INSERT INTO spent_refresh VALUES (?, ?, ?, ?)",
            (digest_of("legacy-stale"), "s", INSTALLATION_ID, 2000),
        )
        db.commit()
        db.close()

        relay = self.restart()
        current = relay.refresh("current")
        with self.assertRaises(InvalidCredentialsError):
            relay.refresh("legacy-stale")
        relay.authenticate(current.access_token)

    def test_only_digests_are_stored_and_expired_grants_are_purged(self):
        relay = self.restart()
        issued = relay.create_session("s", "a@gmail.com", INSTALLATION_ID, 2000)
        with open(self.path, "rb") as file:
            self.assertNotIn(issued.refresh_token.encode(), file.read())
        self.now += RelayService.REFRESH_TTL_SECONDS
        relay.create_challenge()  # any call runs the expiry sweep
        self.assertEqual(SqliteRefreshStore(self.path).load(), ([], []))
