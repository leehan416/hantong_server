import asyncio
import base64
import json
import unittest

from app.api.exception.exceptions import ConflictError
from app.core.rate_limit import SlidingLimit
from app.core.settings import Settings
from app.main import create_app
from tests.fakes import (
    INSTALLATION_ID,
    NOW,
    SETTINGS,
    FakeIdentityTokenVerifier,
    push_claims,
    user_claims,
)
from tests.helpers import json_body, request

API = "/api/v1"
PUSH_TOKEN = "push-token-12345678901234567890"
JSON = {"content-type": "application/json"}


def envelope(message_id, notification, subscription=SETTINGS.PUBSUB_SUBSCRIPTION):
    data = base64.b64encode(json.dumps(notification).encode()).decode()
    return {"subscription": subscription, "message": {"messageId": message_id, "data": data}}


class ApiTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = [NOW]
        self.verifier = FakeIdentityTokenVerifier()
        self.verifier.tokens[PUSH_TOKEN] = push_claims()
        self.app = create_app(SETTINGS, self.verifier, clock=lambda: self.now[0])

    async def challenge(self):
        status, _, data, _ = await request(self.app, "POST", API + "/auth/challenge")
        self.assertEqual(status, 200)
        return json_body(data)["nonce"]

    async def post_session(self, id_token, nonce, installation_id=INSTALLATION_ID):
        body = {"id_token": id_token, "nonce": nonce, "installation_id": installation_id}
        return await request(
            self.app, "POST", API + "/auth/session", headers=JSON, body=json.dumps(body).encode()
        )

    async def login(self, id_token="good", **claims):
        nonce = await self.challenge()
        self.verifier.tokens[id_token] = user_claims(nonce, **claims)
        status, _, data, _ = await self.post_session(id_token, nonce)
        self.assertEqual(status, 200)
        return json_body(data)["access_token"]

    async def push(self, body, token=PUSH_TOKEN):
        headers = {"authorization": "Bearer " + token}
        return await request(
            self.app, "POST", API + "/pubsub/gmail", headers=headers, body=json.dumps(body).encode()
        )


class AuthAndRelayTests(ApiTestCase):
    async def test_session_token_is_bearer_only(self):
        token = await self.login()
        status, _, data, _ = await request(self.app, "GET", API + "/events?token=" + token)
        self.assertEqual(status, 401)
        self.assertEqual(json_body(data)["code"], "AUTH_401")

    async def test_pubsub_delivers_once_without_leaking_email(self):
        token = await self.login()
        first = envelope("m1", {"emailAddress": "a@gmail.com", "historyId": "123"})
        self.assertEqual((await self.push(first))[0], 204)
        redelivery = envelope("m1", {"emailAddress": "a@gmail.com", "historyId": "124"})
        self.assertEqual((await self.push(redelivery))[0], 204)
        headers = {"authorization": "Bearer " + token}
        status, _, data, _ = await request(
            self.app, "GET", API + "/events", headers=headers, disconnect_after=2
        )
        self.assertEqual(status, 200)
        self.assertIn(b'"historyId":"123"', data)
        self.assertNotIn(b"124", data)
        self.assertNotIn(b"a@gmail.com", data)

    async def test_pubsub_rejects_bad_subscription_base64_and_history(self):
        bad_base64 = envelope("m", {})
        bad_base64["message"]["data"] = "%%%"
        for body in (
            envelope("m", {}, subscription="wrong"),
            bad_base64,
            envelope("m", {"emailAddress": "a@gmail.com", "historyId": "0"}),
        ):
            status, _, data, _ = await self.push(body)
            self.assertEqual(status, 400)
            self.assertEqual(json_body(data), {"code": "GMAIL_400", "message": "Invalid request"})

    async def test_pubsub_rejects_other_signer(self):
        self.verifier.tokens[PUSH_TOKEN] = push_claims(email="attacker@example.com")
        status, _, data, _ = await self.push(envelope("m", {}))
        self.assertEqual(status, 401)
        self.assertEqual(json_body(data)["code"], "AUTH_401")

    async def test_long_google_jwt_is_accepted_for_push(self):
        jwt = "a." + "b" * 1200 + ".c"
        self.verifier.tokens[jwt] = push_claims()
        body = envelope("longjwt", {"emailAddress": "x@gmail.com", "historyId": "1"})
        self.assertEqual((await self.push(body, token=jwt))[0], 204)

    async def test_installation_id_must_be_canonical_uuid4(self):
        nonce = await self.challenge()
        self.verifier.tokens["good"] = user_claims(nonce)
        for installation_id in (
            "123e4567-e89b-12d3-a456-426614174000",
            "123E4567-E89B-42D3-A456-426614174000",
        ):
            status, _, _, _ = await self.post_session("good", nonce, installation_id)
            self.assertEqual(status, 422)

    async def test_bad_claims_replay_and_short_lived_tokens_are_generic(self):
        # More requests than the per-IP auth limit allows in one window.
        self.app.state.auth_limiter = SlidingLimit(100)
        for key, value in (
            ("aud", "other"),
            ("iss", "forged"),
            ("exp", 999),
            ("exp", NOW + 0.5),
            ("exp", True),
            ("nonce", "wrong"),
            ("nonce", "\U0001f600"),
            ("email", "a@example.com"),
            ("email_verified", False),
        ):
            nonce = await self.challenge()
            claims = user_claims(nonce)
            claims[key] = value
            self.verifier.tokens["candidate"] = claims
            status, _, data, _ = await self.post_session("candidate", nonce)
            self.assertEqual(status, 401, key)
            self.assertNotIn(b"candidate", data)
        nonce = await self.challenge()
        self.verifier.tokens["good"] = user_claims(nonce)
        self.assertEqual((await self.post_session("good", nonce))[0], 200)
        self.assertEqual((await self.post_session("good", nonce))[0], 401)

    async def test_workspace_account_needs_matching_hosted_domain(self):
        await self.login("workspace", email="a@corp.example", hd="corp.example")
        nonce = await self.challenge()
        self.verifier.tokens["spoofed"] = user_claims(nonce, email="a@corp.example", hd="other")
        self.assertEqual((await self.post_session("spoofed", nonce))[0], 401)

    async def test_expired_session_cannot_be_revoked(self):
        token = await self.login(exp=1001)
        self.now[0] = 1002
        headers = {"authorization": "Bearer " + token}
        status, _, _, _ = await request(self.app, "DELETE", API + "/auth/session", headers=headers)
        self.assertEqual(status, 401)

    async def test_logout_revokes_session(self):
        token = await self.login()
        headers = {"authorization": "Bearer " + token}
        status, _, _, _ = await request(self.app, "DELETE", API + "/auth/session", headers=headers)
        self.assertEqual(status, 204)
        self.assertEqual((await request(self.app, "GET", API + "/events", headers=headers))[0], 401)

    async def test_refresh_endpoint_rotates_tokens_and_rejects_reuse(self):
        nonce = await self.challenge()
        self.verifier.tokens["good"] = user_claims(nonce)
        _, _, data, _ = await self.post_session("good", nonce)
        refresh_token = json_body(data)["refresh_token"]
        body = json.dumps({"refresh_token": refresh_token}).encode()
        status, _, data, _ = await request(
            self.app, "POST", API + "/auth/refresh", headers=JSON, body=body
        )
        self.assertEqual(status, 200)
        refreshed = json_body(data)
        self.assertEqual(refreshed["token_type"], "Bearer")
        self.assertNotEqual(refreshed["refresh_token"], refresh_token)
        status, _, data, _ = await request(
            self.app, "POST", API + "/auth/refresh", headers=JSON, body=body
        )
        self.assertEqual((status, json_body(data)["code"]), (401, "AUTH_401"))

    async def test_lifespan_shutdown_closes_sessions(self):
        token = await self.login()
        session = self.app.state.relay.authenticate(token)
        async with self.app.router.lifespan_context(self.app):
            self.assertFalse(session.revoked)
        self.assertTrue(session.revoked)

    async def test_failed_stream_start_releases_slot(self):
        headers = {"authorization": "Bearer " + await self.login()}
        await request(self.app, "GET", API + "/events", headers=headers, fail_on_start=True)
        status, _, _, _ = await request(
            self.app, "GET", API + "/events", headers=headers, disconnect_after=1
        )
        self.assertEqual(status, 200)

    async def test_live_stream_conflict_and_expiry(self):
        headers = {"authorization": "Bearer " + await self.login(exp=1002)}
        started = asyncio.Event()
        captured = []
        live = asyncio.create_task(
            request(
                self.app,
                "GET",
                API + "/events",
                headers=headers,
                started_event=started,
                capture=captured,
            )
        )
        await asyncio.wait_for(started.wait(), 1)
        status, _, data, _ = await request(self.app, "GET", API + "/events", headers=headers)
        self.assertEqual(status, 409)
        self.assertEqual(json_body(data)["code"], "RELAY_409")
        self.now[0] = 1003
        self.app.state.relay.publish("expiry-message", "a@gmail.com", "123")
        status, _, _, _ = await asyncio.wait_for(live, 1)
        self.assertEqual(status, 200)
        stream = b"".join(m.get("body", b"") for m in captured if m["type"] == "http.response.body")
        self.assertIn(b"event: ready", stream)
        self.assertNotIn(b"mailbox_changed", stream)
        status, _, _, _ = await request(
            self.app, "GET", API + "/events", headers=headers, disconnect_after=1
        )
        self.assertEqual(status, 401)

    async def test_ip_rate_limit(self):
        for index in range(21):
            status, _, data, _ = await request(self.app, "POST", API + "/auth/challenge")
            if index < 20:
                self.assertEqual(status, 200)
        self.assertEqual(status, 429)
        self.assertEqual(json_body(data)["code"], "COMMON_429")

    async def test_missing_configuration_fails_closed(self):
        app = create_app(Settings(), self.verifier, clock=lambda: NOW)
        _, _, data, _ = await request(app, "GET", API + "/health/live")
        self.assertEqual(json_body(data), {"status": "ok", "configured": False})
        status, _, data, _ = await request(app, "POST", API + "/auth/challenge")
        self.assertEqual(status, 503)
        self.assertEqual(json_body(data)["code"], "COMMON_503")

    async def test_unavailable_verifier_is_503(self):
        nonce = await self.challenge()
        self.verifier.unavailable = True
        status, _, data, _ = await self.post_session("candidate-token", nonce)
        self.assertEqual(status, 503)
        self.assertEqual(json_body(data)["code"], "AUTH_503")


class ErrorContractTests(ApiTestCase):
    def setUp(self):
        super().setUp()

        @self.app.get("/boom/application")
        async def application_error():
            raise ConflictError("already there")

        @self.app.get("/boom/unhandled")
        async def unhandled_error():
            raise RuntimeError("secret internals")

    async def test_application_error(self):
        status, _, data, _ = await request(self.app, "GET", "/boom/application")
        self.assertEqual(status, 409)
        self.assertEqual(json_body(data), {"code": "COMMON_409", "message": "already there"})

    async def test_validation_error_hides_details(self):
        status, _, data, _ = await request(
            self.app,
            "POST",
            API + "/auth/session",
            headers=JSON,
            body=b'{"id_token":"secret-token-value"}',
        )
        self.assertEqual(status, 422)
        self.assertEqual(
            json_body(data), {"code": "COMMON_422", "message": "Request validation failed"}
        )

    async def test_http_exceptions_map_to_common_codes(self):
        status, _, data, _ = await request(self.app, "GET", "/nowhere")
        self.assertEqual(status, 404)
        self.assertEqual(json_body(data)["code"], "COMMON_404")
        status, _, data, _ = await request(self.app, "PUT", API + "/auth/challenge")
        self.assertEqual(status, 405)
        self.assertEqual(json_body(data)["code"], "COMMON_405")

    async def test_body_guard_uses_error_contract(self):
        status, _, data, _ = await request(
            self.app, "POST", API + "/pubsub/gmail", body=b"x" * 33000
        )
        self.assertEqual(status, 413)
        self.assertEqual(json_body(data), {"code": "COMMON_413", "message": "Request too large"})

    async def test_unhandled_error_hides_internals(self):
        captured = []
        # Starlette re-raises after sending the 500 so the server can log it too.
        with self.assertLogs("hantong", "ERROR"), self.assertRaises(RuntimeError):
            await request(self.app, "GET", "/boom/unhandled", capture=captured)
        self.assertEqual(captured[0]["status"], 500)
        data = b"".join(m.get("body", b"") for m in captured if m["type"] == "http.response.body")
        self.assertEqual(
            json_body(data), {"code": "COMMON_500", "message": "Internal Server Error"}
        )
        self.assertNotIn(b"secret internals", data)
