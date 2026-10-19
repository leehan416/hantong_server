import asyncio
import sys
import threading
import types
import unittest
from unittest.mock import patch

from app.auth.adapters.google import token_verifier
from app.auth.adapters.google.token_verifier import (
    CERTS_URL,
    CertificateCache,
    GoogleIdentityTokenVerifier,
    verify_google_token,
)
from app.auth.exceptions import IdentityVerifierUnavailableError, InvalidCredentialsError
from tests.fakes import user_claims


def fake_google_modules(transport_request, verify_oauth2_token):
    google = types.ModuleType("google")
    google.__path__ = []
    oauth2 = types.ModuleType("google.oauth2")
    oauth2.__path__ = []
    id_token = types.ModuleType("google.oauth2.id_token")
    id_token.verify_oauth2_token = verify_oauth2_token
    auth = types.ModuleType("google.auth")
    auth.__path__ = []
    exceptions = types.ModuleType("google.auth.exceptions")
    exceptions.TransportError = type("TransportError", (Exception,), {})
    exceptions.TimeoutError = type("TimeoutError", (Exception,), {})
    exceptions.ResponseError = type("ResponseError", (Exception,), {})
    transport = types.ModuleType("google.auth.transport")
    transport.__path__ = []
    requests = types.ModuleType("google.auth.transport.requests")
    requests.Request = transport_request
    oauth2.id_token = id_token
    transport.requests = requests
    auth.transport = transport
    auth.exceptions = exceptions
    google.oauth2 = oauth2
    google.auth = auth
    return {
        "google": google,
        "google.oauth2": oauth2,
        "google.oauth2.id_token": id_token,
        "google.auth": auth,
        "google.auth.exceptions": exceptions,
        "google.auth.transport": transport,
        "google.auth.transport.requests": requests,
    }


class GoogleTokenFunctionTests(unittest.TestCase):
    def test_missing_dependency_fails_closed_without_network(self):
        real_import = __import__

        def no_google(name, *args, **kwargs):
            if name.startswith("google.oauth2") or name.startswith("google.auth"):
                raise ImportError
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=no_google):
            with self.assertRaises(IdentityVerifierUnavailableError):
                verify_google_token("token", "aud", CertificateCache())

    def test_certificate_response_is_cached_and_timeout_is_bounded(self):
        calls = []

        class FakeResponse:
            status = 200
            headers = {"cache-control": "max-age=300"}
            data = b"{}"

        class Request:
            def __call__(self, url, **kwargs):
                calls.append((url, kwargs.get("timeout")))
                return FakeResponse()

        def verify(token, request, audience):
            request(CERTS_URL)
            return {"aud": audience}

        cache = CertificateCache()
        modules = fake_google_modules(Request, verify)
        clock = patch.object(
            token_verifier.time, "monotonic", side_effect=[100, 101, 102, 500, 501]
        )
        with patch.dict(sys.modules, modules), clock:
            for token in ("one", "two", "three"):
                verify_google_token(token, "aud", cache)
        self.assertEqual(calls, [(CERTS_URL, 5), (CERTS_URL, 5)])

    def test_library_rejection_is_translated(self):
        def reject(token, request, audience):
            raise ValueError("Token expired")

        with patch.dict(sys.modules, fake_google_modules(lambda: None, reject)):
            with self.assertRaises(InvalidCredentialsError):
                verify_google_token("token", "aud", CertificateCache())

    def test_google_transport_failure_is_unavailable(self):
        modules = fake_google_modules(lambda: None, lambda *args, **kwargs: None)
        transport_error = modules["google.auth.exceptions"].TransportError("offline")

        def unavailable(token, request, audience):
            raise transport_error

        modules["google.oauth2.id_token"].verify_oauth2_token = unavailable
        with patch.dict(sys.modules, modules):
            with self.assertRaises(IdentityVerifierUnavailableError):
                verify_google_token("token", "aud", CertificateCache())


class BlockingVerifier(GoogleIdentityTokenVerifier):
    def __init__(self, claims):
        super().__init__(max_concurrency=4)
        self.claims = claims
        self.entered = threading.Semaphore(0)
        self.release = threading.Event()

    def verify_token(self, token, audience):
        self.entered.release()
        self.release.wait(3)
        return self.claims


class GoogleVerifierAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_payload_is_validated_into_claims(self):
        verifier = BlockingVerifier(user_claims("nonce"))
        verifier.release.set()
        claims = await verifier.verify("token", "client")
        self.assertEqual(claims.sub, "s")
        verifier.claims = user_claims("nonce", exp=float("inf"))
        with self.assertRaises(InvalidCredentialsError):
            await verifier.verify("token", "client")

    async def test_cancelled_request_keeps_slot_until_thread_finishes(self):
        verifier = BlockingVerifier(user_claims("nonce"))
        calls = []
        for _ in range(4):
            calls.append(asyncio.create_task(verifier.verify("token", "client")))
        for _ in range(4):
            self.assertTrue(await asyncio.to_thread(verifier.entered.acquire, True, 2))
        for call in calls:
            call.cancel()
        await asyncio.gather(*calls, return_exceptions=True)
        with self.assertRaises(IdentityVerifierUnavailableError):
            await verifier.verify("token", "client")
        verifier.release.set()
