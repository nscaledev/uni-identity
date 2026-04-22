from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from time import monotonic, sleep
from typing import Callable, Dict, Optional

import requests

EXCHANGE_PATH = "/oauth2/v2/exchange"

RequestEditor = Callable[[Dict[str, object]], None]


@dataclass(slots=True)
class ExchangeRequest:
    organization_id: Optional[str] = None
    project_id: Optional[str] = None


@dataclass(slots=True)
class ExchangeResponse:
    passport: str
    expires_in: int
    cached: bool = False


@dataclass(slots=True)
class RetryConfig:
    max_attempts: int = 2
    retryable_status_codes: tuple[int, ...] = (502, 503, 504)
    retry_network_errors: bool = True
    min_backoff_seconds: float = 0.05
    max_backoff_seconds: float = 0.2


@dataclass(slots=True)
class CacheConfig:
    enabled: bool = False
    default_ttl_seconds: float = 60.0


@dataclass(slots=True)
class MetricsHooks:
    inc_total: Optional[Callable[[str], None]] = None
    observe_duration: Optional[Callable[[float], None]] = None


class SourceTokenRequiredError(ValueError):
    pass


class BaseUrlRequiredError(ValueError):
    pass


class BuildExchangeRequestError(RuntimeError):
    pass


class EditExchangeRequestError(RuntimeError):
    pass


class MissingPassportError(RuntimeError):
    pass


class TransportError(RuntimeError):
    def __init__(self, cause: Exception):
        self.cause = cause
        super().__init__(f"passport exchange transport failure: {cause}")


class UnauthorizedError(RuntimeError):
    def __init__(self, status_code: int, error_code: Optional[str], description: str):
        self.status_code = status_code
        self.error_code = error_code
        self.description = description
        super().__init__(f"passport exchange unauthorized: {description}")


class HttpStatusError(RuntimeError):
    def __init__(self, status_code: int, error_code: Optional[str], description: str):
        self.status_code = status_code
        self.error_code = error_code
        self.description = description
        super().__init__(f"passport exchange failed with status {status_code}: {description}")


class RetryClass(Enum):
    NONE = 0
    TRANSPORT = 1
    STATUS = 2


@dataclass(slots=True)
class _CacheEntry:
    response: ExchangeResponse
    expires_at: float


@dataclass(slots=True)
class Options:
    base_url: str
    session: Optional[requests.Session] = None
    retry: RetryConfig = field(default_factory=RetryConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    request_editors: list[RequestEditor] = field(default_factory=list)
    metrics: MetricsHooks = field(default_factory=MetricsHooks)
    headers: Dict[str, str] = field(default_factory=dict)


class PassportExchangeClient:
    def __init__(self, options: Options):
        if not options.base_url.strip():
            raise BaseUrlRequiredError("base URL is required")

        self._base_url = options.base_url.rstrip("/")
        self._session = options.session or requests.Session()
        self._retry = options.retry
        self._cache_config = options.cache
        self._request_editors = options.request_editors
        self._metrics = options.metrics
        self._headers = options.headers
        self._cache: Dict[str, _CacheEntry] = {}

    def exchange(self, source_token: str) -> "ExchangeCallBuilder":
        return ExchangeCallBuilder(self, source_token)

    def _exchange_with_request(
        self,
        source_token: str,
        request: ExchangeRequest,
        timeout_seconds: Optional[float],
    ) -> ExchangeResponse:
        if not source_token.strip():
            raise SourceTokenRequiredError("source token is required")

        started = monotonic()
        cache_key = _exchange_cache_key(source_token, request)
        cached = self._get_cached(cache_key)
        if cached is not None:
            self._inc_total("cached")
            return ExchangeResponse(cached.passport, cached.expires_in, cached=True)

        attempt = 1
        while True:
            result, retry_class, error = self._perform_attempt(source_token, request, timeout_seconds)
            if result is not None:
                self._set_cached(cache_key, result)
                self._inc_total("success")
                self._observe_duration(monotonic() - started)
                return result

            if error is None:
                raise RuntimeError("unexpected exchange state")

            if isinstance(error, UnauthorizedError):
                self._inc_total("unauthorized")
                self._observe_duration(monotonic() - started)
                raise error

            if self._should_retry(attempt, retry_class):
                attempt += 1
                sleep(_backoff_duration(self._retry.min_backoff_seconds, self._retry.max_backoff_seconds))
                continue

            self._inc_total("error")
            self._observe_duration(monotonic() - started)
            raise error

    def _perform_attempt(
        self,
        source_token: str,
        request: ExchangeRequest,
        timeout_seconds: Optional[float],
    ) -> tuple[Optional[ExchangeResponse], RetryClass, Optional[Exception]]:
        try:
            request_kwargs = self._build_exchange_request(source_token, request, timeout_seconds)
        except Exception as error:  # noqa: BLE001
            return None, RetryClass.NONE, error

        try:
            response = self._session.post(**request_kwargs)
        except requests.RequestException as error:
            return None, RetryClass.TRANSPORT, TransportError(error)

        return self._parse_exchange_response(response)

    def _build_exchange_request(
        self,
        source_token: str,
        request: ExchangeRequest,
        timeout_seconds: Optional[float],
    ) -> Dict[str, object]:
        url = f"{self._base_url}{EXCHANGE_PATH}"
        if not url.startswith(("http://", "https://")):
            raise BuildExchangeRequestError("invalid base URL")

        data: Dict[str, str] = {}
        if request.organization_id:
            data["organizationId"] = request.organization_id
        if request.project_id:
            data["projectId"] = request.project_id

        request_kwargs: Dict[str, object] = {
            "url": url,
            "headers": {
                "Authorization": f"Bearer {source_token}",
                "Content-Type": "application/x-www-form-urlencoded",
                **self._headers,
            },
            "data": data,
        }

        if timeout_seconds is not None:
            request_kwargs["timeout"] = timeout_seconds

        for editor in self._request_editors:
            try:
                editor(request_kwargs)
            except Exception as error:  # noqa: BLE001
                raise EditExchangeRequestError(str(error)) from error

        return request_kwargs

    def _parse_exchange_response(
        self,
        response: requests.Response,
    ) -> tuple[Optional[ExchangeResponse], RetryClass, Optional[Exception]]:
        if 200 <= response.status_code < 300:
            payload = response.json()
            passport = str(payload.get("passport", "")).strip()
            if not passport:
                return None, RetryClass.NONE, MissingPassportError("exchange response missing passport field")

            expires_in = int(payload.get("expires_in", 0))
            return ExchangeResponse(passport=passport, expires_in=expires_in, cached=False), RetryClass.NONE, None

        oauth_error = _parse_oauth_error(response)
        description = oauth_error.get("error_description") or "exchange request failed"

        if response.status_code == 401:
            return (
                None,
                RetryClass.NONE,
                UnauthorizedError(response.status_code, oauth_error.get("error"), description),
            )

        status_error = HttpStatusError(response.status_code, oauth_error.get("error"), description)
        if response.status_code >= 500 and response.status_code in self._retry.retryable_status_codes:
            return None, RetryClass.STATUS, status_error

        return None, RetryClass.NONE, status_error

    def _should_retry(self, attempt: int, retry_class: RetryClass) -> bool:
        if attempt >= self._retry.max_attempts:
            return False
        if retry_class is RetryClass.TRANSPORT:
            return self._retry.retry_network_errors
        if retry_class is RetryClass.STATUS:
            return True
        return False

    def _get_cached(self, key: str) -> Optional[ExchangeResponse]:
        if not self._cache_config.enabled:
            return None

        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry.expires_at <= monotonic():
            self._cache.pop(key, None)
            return None
        return entry.response

    def _set_cached(self, key: str, response: ExchangeResponse) -> None:
        if not self._cache_config.enabled:
            return
        ttl_seconds = response.expires_in if response.expires_in > 0 else self._cache_config.default_ttl_seconds
        if ttl_seconds <= 0:
            return
        self._cache[key] = _CacheEntry(response=response, expires_at=monotonic() + ttl_seconds)

    def _inc_total(self, result: str) -> None:
        if self._metrics.inc_total is not None:
            self._metrics.inc_total(result)

    def _observe_duration(self, duration_seconds: float) -> None:
        if self._metrics.observe_duration is not None:
            self._metrics.observe_duration(duration_seconds)


class ExchangeCallBuilder:
    def __init__(self, client: PassportExchangeClient, source_token: str):
        self._client = client
        self._source_token = source_token
        self._request = ExchangeRequest()
        self._timeout_seconds: Optional[float] = None

    def organization_id(self, organization_id: str) -> "ExchangeCallBuilder":
        self._request.organization_id = organization_id
        return self

    def project_id(self, project_id: str) -> "ExchangeCallBuilder":
        self._request.project_id = project_id
        return self

    def timeout(self, timeout_seconds: float) -> "ExchangeCallBuilder":
        self._timeout_seconds = timeout_seconds
        return self

    def send(self) -> ExchangeResponse:
        return self._client._exchange_with_request(
            source_token=self._source_token,
            request=self._request,
            timeout_seconds=self._timeout_seconds,
        )


def _backoff_duration(min_backoff_seconds: float, max_backoff_seconds: float) -> float:
    if max_backoff_seconds <= min_backoff_seconds:
        return min_backoff_seconds
    return min_backoff_seconds + ((max_backoff_seconds - min_backoff_seconds) / 2)


def _exchange_cache_key(source_token: str, request: ExchangeRequest) -> str:
    digest = sha256()
    digest.update(source_token.encode("utf-8"))
    digest.update(b"|")
    digest.update((request.organization_id or "").encode("utf-8"))
    digest.update(b"|")
    digest.update((request.project_id or "").encode("utf-8"))
    return digest.hexdigest()


def _parse_oauth_error(response: requests.Response) -> Dict[str, Optional[str]]:
    try:
        payload = response.json()
    except ValueError:
        return {"error": None, "error_description": None}

    return {
        "error": payload.get("error"),
        "error_description": payload.get("error_description"),
    }
