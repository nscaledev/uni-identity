from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any, Callable

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from passport_exchange_client import (
    CacheConfig,
    EditExchangeRequestError,
    HttpStatusError,
    Options,
    PassportExchangeClient,
    RetryConfig,
    SourceTokenRequiredError,
    UnauthorizedError,
)


@dataclass
class StubResponse:
    status_code: int
    payload: dict[str, Any]

    def json(self) -> dict[str, Any]:
        return self.payload


class StubSession:
    def __init__(self, handler: Callable[[int, dict[str, Any]], StubResponse]):
        self.handler = handler
        self.calls = 0

    def post(self, **kwargs: Any) -> StubResponse:
        self.calls += 1
        return self.handler(self.calls, kwargs)


def test_exchange_success() -> None:
    def handler(_calls: int, kwargs: dict[str, Any]) -> StubResponse:
        assert kwargs["data"]["organizationId"] == "org-1"
        assert kwargs["data"]["projectId"] == "project-1"
        assert kwargs["headers"]["Authorization"] == "Bearer source-token"
        return StubResponse(200, {"passport": "passport-jwt", "expires_in": 120})

    session = StubSession(handler)
    client = PassportExchangeClient(Options(base_url="https://identity.example.com", session=session))

    response = client.exchange("source-token").organization_id("org-1").project_id("project-1").send()

    assert response.passport == "passport-jwt"
    assert response.expires_in == 120
    assert response.cached is False
    assert session.calls == 1


def test_cache_hit_on_second_call() -> None:
    session = StubSession(lambda _calls, _kwargs: StubResponse(200, {"passport": "cached", "expires_in": 60}))
    client = PassportExchangeClient(
        Options(base_url="https://identity.example.com", session=session, cache=CacheConfig(enabled=True))
    )

    first = client.exchange("source-token").send()
    second = client.exchange("source-token").send()

    assert first.cached is False
    assert second.cached is True
    assert session.calls == 1


def test_unauthorized_error() -> None:
    session = StubSession(
        lambda _calls, _kwargs: StubResponse(
            401,
            {"error": "access_denied", "error_description": "token invalid"},
        )
    )
    client = PassportExchangeClient(Options(base_url="https://identity.example.com", session=session))

    with pytest.raises(UnauthorizedError):
        client.exchange("source-token").send()


def test_does_not_retry_400() -> None:
    session = StubSession(
        lambda _calls, _kwargs: StubResponse(
            400,
            {"error": "invalid_request", "error_description": "bad request"},
        )
    )
    client = PassportExchangeClient(Options(base_url="https://identity.example.com", session=session))

    with pytest.raises(HttpStatusError):
        client.exchange("source-token").send()

    assert session.calls == 1


def test_retries_503_by_default() -> None:
    def handler(calls: int, _kwargs: dict[str, Any]) -> StubResponse:
        if calls == 1:
            return StubResponse(503, {"error": "server_error", "error_description": "temporary"})
        return StubResponse(200, {"passport": "retried-passport", "expires_in": 60})

    session = StubSession(handler)
    client = PassportExchangeClient(Options(base_url="https://identity.example.com", session=session))

    response = client.exchange("source-token").send()
    assert response.passport == "retried-passport"
    assert session.calls == 2


def test_does_not_retry_500_by_default() -> None:
    session = StubSession(
        lambda _calls, _kwargs: StubResponse(
            500,
            {"error": "server_error", "error_description": "unknown"},
        )
    )
    client = PassportExchangeClient(Options(base_url="https://identity.example.com", session=session))

    with pytest.raises(HttpStatusError):
        client.exchange("source-token").send()

    assert session.calls == 1


def test_retries_500_when_configured() -> None:
    def handler(calls: int, _kwargs: dict[str, Any]) -> StubResponse:
        if calls == 1:
            return StubResponse(500, {"error": "server_error", "error_description": "retry"})
        return StubResponse(200, {"passport": "configured-retry", "expires_in": 60})

    session = StubSession(handler)
    client = PassportExchangeClient(
        Options(
            base_url="https://identity.example.com",
            session=session,
            retry=RetryConfig(retryable_status_codes=(500, 503)),
        )
    )

    response = client.exchange("source-token").send()
    assert response.passport == "configured-retry"
    assert session.calls == 2


def test_timeout_forwarded_to_request() -> None:
    def handler(_calls: int, kwargs: dict[str, Any]) -> StubResponse:
        assert kwargs["timeout"] == 0.25
        return StubResponse(200, {"passport": "timed", "expires_in": 60})

    session = StubSession(handler)
    client = PassportExchangeClient(Options(base_url="https://identity.example.com", session=session))

    response = client.exchange("source-token").timeout(0.25).send()

    assert response.passport == "timed"
    assert session.calls == 1


def test_transport_errors_retry_once_by_default() -> None:
    def handler(calls: int, _kwargs: dict[str, Any]) -> StubResponse:
        if calls == 1:
            raise requests.ConnectionError("network unavailable")
        return StubResponse(200, {"passport": "after-transport-retry", "expires_in": 60})

    session = StubSession(handler)
    client = PassportExchangeClient(Options(base_url="https://identity.example.com", session=session))

    response = client.exchange("source-token").send()

    assert response.passport == "after-transport-retry"
    assert session.calls == 2


def test_request_editor_errors_not_retried() -> None:
    editor_calls = 0

    def editor(_request: dict[str, object]) -> None:
        nonlocal editor_calls
        editor_calls += 1
        raise RuntimeError("editor failure")

    session = StubSession(lambda _calls, _kwargs: StubResponse(200, {"passport": "unused", "expires_in": 1}))
    client = PassportExchangeClient(
        Options(
            base_url="https://identity.example.com",
            session=session,
            request_editors=[editor],
        )
    )

    with pytest.raises(EditExchangeRequestError):
        client.exchange("source-token").send()

    assert editor_calls == 1
    assert session.calls == 0


def test_empty_source_token_rejected() -> None:
    client = PassportExchangeClient(Options(base_url="https://identity.example.com"))

    with pytest.raises(SourceTokenRequiredError):
        client.exchange(" ").send()
