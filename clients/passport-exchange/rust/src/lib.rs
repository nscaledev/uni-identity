use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{RequestBuilder, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;

pub const EXCHANGE_PATH: &str = "/oauth2/v2/exchange";

pub type RequestEditor = Arc<dyn Fn(RequestBuilder) -> RequestBuilder + Send + Sync>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExchangeRequest {
    #[serde(skip_serializing_if = "Option::is_none", rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "projectId")]
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeResponse {
    pub passport: String,
    #[serde(rename = "expires_in")]
    pub expires_in: u64,
    #[serde(skip)]
    pub cached: bool,
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: usize,
    pub retryable_status_codes: Vec<StatusCode>,
    pub retry_network_errors: bool,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            retryable_status_codes: vec![
                StatusCode::BAD_GATEWAY,
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::GATEWAY_TIMEOUT,
            ],
            retry_network_errors: true,
            min_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_millis(200),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub enabled: bool,
    pub default_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_ttl: Duration::from_secs(60),
        }
    }
}

pub trait MetricsSink: Send + Sync {
    fn inc_total(&self, _result: &'static str) {}

    fn observe_duration(&self, _duration: Duration) {}
}

#[derive(Default)]
pub struct NoopMetricsSink;

impl MetricsSink for NoopMetricsSink {}

#[derive(Clone)]
pub struct Options {
    pub base_url: String,
    pub http_client: Option<reqwest::Client>,
    pub retry: RetryConfig,
    pub cache: CacheConfig,
    pub request_editors: Vec<RequestEditor>,
    pub metrics: Arc<dyn MetricsSink>,
    pub headers: HeaderMap,
}

impl Options {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http_client: None,
            retry: RetryConfig::default(),
            cache: CacheConfig::default(),
            request_editors: vec![],
            metrics: Arc::new(NoopMetricsSink),
            headers: HeaderMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    response: ExchangeResponse,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct ResponseCache {
    entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorPayload {
    error: Option<String>,
    #[serde(rename = "error_description")]
    error_description: Option<String>,
}

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("source token is required")]
    SourceTokenRequired,
    #[error("base URL is required")]
    BaseUrlRequired,
    #[error("invalid base URL: {0}")]
    InvalidBaseUrl(String),
    #[error("failed to build exchange request: {0}")]
    BuildExchangeRequest(String),
    #[error("exchange unauthorized (status {status_code}): {description}")]
    Unauthorized {
        status_code: u16,
        error_code: Option<String>,
        description: String,
    },
    #[error("exchange failed with status {status_code}: {description}")]
    HttpStatus {
        status_code: u16,
        error_code: Option<String>,
        description: String,
    },
    #[error("exchange transport failure: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("exchange response missing passport field")]
    MissingPassport,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum RetryClass {
    None,
    Transport,
    Status,
}

pub struct Client {
    base_url: Url,
    http_client: reqwest::Client,
    retry: RetryConfig,
    cache_config: CacheConfig,
    cache: RwLock<ResponseCache>,
    request_editors: Vec<RequestEditor>,
    metrics: Arc<dyn MetricsSink>,
    headers: HeaderMap,
}

pub struct ExchangeCallBuilder<'a> {
    client: &'a Client,
    source_token: String,
    request: ExchangeRequest,
    request_timeout: Option<Duration>,
}

impl<'a> ExchangeCallBuilder<'a> {
    pub fn organization_id(mut self, organization_id: impl Into<String>) -> Self {
        self.request.organization_id = Some(organization_id.into());
        self
    }

    pub fn project_id(mut self, project_id: impl Into<String>) -> Self {
        self.request.project_id = Some(project_id.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    pub async fn send(self) -> Result<ExchangeResponse, ExchangeError> {
        self.client
            .exchange_with_request(&self.source_token, self.request, self.request_timeout)
            .await
    }
}

impl Client {
    pub fn new(options: Options) -> Result<Self, ExchangeError> {
        if options.base_url.trim().is_empty() {
            return Err(ExchangeError::BaseUrlRequired);
        }

        let base_url = Url::parse(options.base_url.trim())
            .map_err(|err| ExchangeError::InvalidBaseUrl(err.to_string()))?;

        let http_client = match options.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .build()
                .map_err(ExchangeError::Transport)?,
        };

        Ok(Self {
            base_url,
            http_client,
            retry: options.retry,
            cache_config: options.cache,
            cache: RwLock::new(ResponseCache::default()),
            request_editors: options.request_editors,
            metrics: options.metrics,
            headers: options.headers,
        })
    }

    pub fn exchange(&self, source_token: impl Into<String>) -> ExchangeCallBuilder<'_> {
        ExchangeCallBuilder {
            client: self,
            source_token: source_token.into(),
            request: ExchangeRequest::default(),
            request_timeout: None,
        }
    }

    async fn exchange_with_request(
        &self,
        source_token: &str,
        request: ExchangeRequest,
        request_timeout: Option<Duration>,
    ) -> Result<ExchangeResponse, ExchangeError> {
        if source_token.trim().is_empty() {
            return Err(ExchangeError::SourceTokenRequired);
        }

        let started = Instant::now();
        let cache_key = exchange_cache_key(source_token, &request);

        if let Some(mut cached) = self.get_cached(&cache_key).await {
            cached.cached = true;
            self.inc_total("cached");

            return Ok(cached);
        }

        let mut attempt = 1usize;

        loop {
            let result = self
                .perform_attempt(source_token, &request, request_timeout)
                .await;

            match result {
                Ok(mut response) => {
                    response.cached = false;
                    self.set_cached(&cache_key, response.clone()).await;
                    self.inc_total("success");
                    self.observe_duration(started.elapsed());

                    return Ok(response);
                }
                Err((decision, err)) => {
                    if is_unauthorized(&err) {
                        self.inc_total("unauthorized");
                        self.observe_duration(started.elapsed());

                        return Err(err);
                    }

                    if self.should_retry(attempt, decision) {
                        attempt += 1;
                        self.sleep_backoff().await;
                        continue;
                    }

                    self.inc_total("error");
                    self.observe_duration(started.elapsed());

                    return Err(err);
                }
            }
        }
    }

    async fn perform_attempt(
        &self,
        source_token: &str,
        request: &ExchangeRequest,
        request_timeout: Option<Duration>,
    ) -> Result<ExchangeResponse, (RetryClass, ExchangeError)> {
        let request_builder = self
            .build_exchange_request(source_token, request, request_timeout)
            .map_err(|err| (RetryClass::None, err))?;

        let response = request_builder
            .send()
            .await
            .map_err(|err| (RetryClass::Transport, ExchangeError::Transport(err)))?;

        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|err| (RetryClass::Transport, ExchangeError::Transport(err)))?;

        self.parse_exchange_response(status, &body)
    }

    fn build_exchange_request(
        &self,
        source_token: &str,
        request: &ExchangeRequest,
        request_timeout: Option<Duration>,
    ) -> Result<RequestBuilder, ExchangeError> {
        let exchange_url = self
            .base_url
            .join(EXCHANGE_PATH.trim_start_matches('/'))
            .map_err(|err| ExchangeError::BuildExchangeRequest(err.to_string()))?;

        let mut form = HashMap::new();
        if let Some(organization_id) = request.organization_id.as_ref() {
            form.insert("organizationId", organization_id.clone());
        }

        if let Some(project_id) = request.project_id.as_ref() {
            form.insert("projectId", project_id.clone());
        }

        let mut request_builder = self
            .http_client
            .post(exchange_url)
            .header(AUTHORIZATION, format!("Bearer {source_token}"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .headers(self.headers.clone())
            .form(&form);

        if let Some(timeout) = request_timeout {
            request_builder = request_builder.timeout(timeout);
        }

        for editor in &self.request_editors {
            request_builder = editor(request_builder);
        }

        Ok(request_builder)
    }

    fn parse_exchange_response(
        &self,
        status: StatusCode,
        body: &[u8],
    ) -> Result<ExchangeResponse, (RetryClass, ExchangeError)> {
        if status.is_success() {
            let mut response: ExchangeResponse = serde_json::from_slice(body).map_err(|err| {
                (
                    RetryClass::None,
                    ExchangeError::BuildExchangeRequest(err.to_string()),
                )
            })?;

            if response.passport.trim().is_empty() {
                return Err((RetryClass::None, ExchangeError::MissingPassport));
            }

            response.cached = false;

            return Ok(response);
        }

        let oauth_error = parse_oauth_error(body);
        let description = oauth_error
            .error_description
            .unwrap_or_else(|| "exchange request failed".to_string());

        if status == StatusCode::UNAUTHORIZED {
            return Err((
                RetryClass::None,
                ExchangeError::Unauthorized {
                    status_code: status.as_u16(),
                    error_code: oauth_error.error,
                    description,
                },
            ));
        }

        if status.is_server_error() {
            let decision = if self.retry.retryable_status_codes.contains(&status) {
                RetryClass::Status
            } else {
                RetryClass::None
            };

            return Err((
                decision,
                ExchangeError::HttpStatus {
                    status_code: status.as_u16(),
                    error_code: oauth_error.error,
                    description,
                },
            ));
        }

        Err((
            RetryClass::None,
            ExchangeError::HttpStatus {
                status_code: status.as_u16(),
                error_code: oauth_error.error,
                description,
            },
        ))
    }

    fn should_retry(&self, attempt: usize, decision: RetryClass) -> bool {
        if attempt >= self.retry.max_attempts {
            return false;
        }

        match decision {
            RetryClass::None => false,
            RetryClass::Transport => self.retry.retry_network_errors,
            RetryClass::Status => true,
        }
    }

    async fn sleep_backoff(&self) {
        let duration = backoff_duration(self.retry.min_backoff, self.retry.max_backoff);
        if duration.is_zero() {
            return;
        }

        tokio::time::sleep(duration).await;
    }

    async fn get_cached(&self, key: &str) -> Option<ExchangeResponse> {
        if !self.cache_config.enabled {
            return None;
        }

        let now = Instant::now();
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.entries.get(key) {
                if entry.expires_at > now {
                    return Some(entry.response.clone());
                }
            }
        }

        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.entries.get(key) {
            if entry.expires_at <= now {
                cache.entries.remove(key);
            }
        }

        None
    }

    async fn set_cached(&self, key: &str, response: ExchangeResponse) {
        if !self.cache_config.enabled {
            return;
        }

        let ttl = if response.expires_in > 0 {
            Duration::from_secs(response.expires_in)
        } else {
            self.cache_config.default_ttl
        };

        if ttl.is_zero() {
            return;
        }

        let mut cache = self.cache.write().await;
        cache.entries.insert(
            key.to_string(),
            CacheEntry {
                response,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    fn inc_total(&self, result: &'static str) {
        self.metrics.inc_total(result);
    }

    fn observe_duration(&self, duration: Duration) {
        self.metrics.observe_duration(duration);
    }
}

fn parse_oauth_error(body: &[u8]) -> OAuthErrorPayload {
    serde_json::from_slice(body).unwrap_or(OAuthErrorPayload {
        error: None,
        error_description: None,
    })
}

fn is_unauthorized(err: &ExchangeError) -> bool {
    matches!(err, ExchangeError::Unauthorized { .. })
}

fn backoff_duration(min_backoff: Duration, max_backoff: Duration) -> Duration {
    if max_backoff <= min_backoff {
        return min_backoff;
    }

    min_backoff + ((max_backoff - min_backoff) / 2)
}

fn exchange_cache_key(source_token: &str, request: &ExchangeRequest) -> String {
    let mut hash = Sha256::new();
    hash.update(source_token.as_bytes());
    hash.update(b"|");
    hash.update(
        request
            .organization_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hash.update(b"|");
    hash.update(request.project_id.as_deref().unwrap_or_default().as_bytes());

    hex::encode(hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingMetricsSink {
        success: Arc<AtomicUsize>,
        duration: Arc<AtomicUsize>,
    }

    impl MetricsSink for CountingMetricsSink {
        fn inc_total(&self, result: &'static str) {
            if result == "success" {
                self.success.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn observe_duration(&self, _duration: Duration) {
            self.duration.fetch_add(1, Ordering::Relaxed);
        }
    }

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn default_options(base_url: String) -> Options {
        Options::new(base_url)
    }

    #[tokio::test]
    async fn exchange_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "passport": "passport-jwt",
                "expires_in": 120
            })))
            .mount(&server)
            .await;

        let client = Client::new(default_options(server.uri())).unwrap();
        let response = client.exchange("source-token").send().await.unwrap();

        assert_eq!(response.passport, "passport-jwt");
        assert_eq!(response.expires_in, 120);
        assert!(!response.cached);
    }

    #[tokio::test]
    async fn exchange_cache_hit() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "passport": "cached-passport",
                "expires_in": 120
            })))
            .mount(&server)
            .await;

        let mut options = default_options(server.uri());
        options.cache.enabled = true;

        let client = Client::new(options).unwrap();

        let first = client.exchange("source-token").send().await.unwrap();
        assert!(!first.cached);

        let second = client.exchange("source-token").send().await.unwrap();
        assert!(second.cached);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn exchange_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": "access_denied",
                "error_description": "token invalid"
            })))
            .mount(&server)
            .await;

        let client = Client::new(default_options(server.uri())).unwrap();
        let err = client.exchange("source-token").send().await.unwrap_err();

        match err {
            ExchangeError::Unauthorized { status_code, .. } => {
                assert_eq!(status_code, 401);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn exchange_does_not_retry_400() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_request",
                "error_description": "bad request"
            })))
            .mount(&server)
            .await;

        let client = Client::new(default_options(server.uri())).unwrap();
        let err = client.exchange("source-token").send().await.unwrap_err();

        match err {
            ExchangeError::HttpStatus { status_code, .. } => {
                assert_eq!(status_code, 400);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn exchange_retries_503_by_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(503).set_body_json(json!({
                "error": "server_error",
                "error_description": "temporary"
            })))
            .mount(&server)
            .await;

        let client = Client::new(default_options(server.uri())).unwrap();
        let _ = client.exchange("source-token").send().await.unwrap_err();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
    }

    #[tokio::test]
    async fn exchange_does_not_retry_500_by_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": "server_error",
                "error_description": "unknown"
            })))
            .mount(&server)
            .await;

        let client = Client::new(default_options(server.uri())).unwrap();
        let _ = client.exchange("source-token").send().await.unwrap_err();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn exchange_can_retry_500_when_configured() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": "server_error",
                "error_description": "configured retry"
            })))
            .mount(&server)
            .await;

        let mut options = default_options(server.uri());
        options.retry.retryable_status_codes = vec![StatusCode::INTERNAL_SERVER_ERROR];

        let client = Client::new(options).unwrap();
        let _ = client.exchange("source-token").send().await.unwrap_err();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
    }

    #[tokio::test]
    async fn exchange_metrics_sink() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "passport": "metric-passport",
                "expires_in": 120
            })))
            .mount(&server)
            .await;

        let success = Arc::new(AtomicUsize::new(0));
        let duration = Arc::new(AtomicUsize::new(0));

        let success_ref = Arc::clone(&success);
        let duration_ref = Arc::clone(&duration);

        let mut options = default_options(server.uri());
        options.metrics = Arc::new(CountingMetricsSink {
            success: success_ref,
            duration: duration_ref,
        });

        let client = Client::new(options).unwrap();
        let _ = client.exchange("source-token").send().await.unwrap();

        assert_eq!(success.load(Ordering::Relaxed), 1);
        assert_eq!(duration.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn exchange_builder_applies_request_options() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "passport": "builder-passport",
                "expires_in": 120
            })))
            .mount(&server)
            .await;

        let client = Client::new(default_options(server.uri())).unwrap();
        let _ = client
            .exchange("source-token")
            .organization_id("org-1")
            .project_id("project-1")
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let body = String::from_utf8(requests[0].body.clone()).unwrap();

        assert!(body.contains("organizationId=org-1"));
        assert!(body.contains("projectId=project-1"));
    }

    #[tokio::test]
    async fn exchange_builder_timeout_applies_to_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(EXCHANGE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(80))
                    .set_body_json(json!({"passport": "slow-passport", "expires_in": 120})),
            )
            .mount(&server)
            .await;

        let mut options = default_options(server.uri());
        options.retry.retry_network_errors = false;

        let client = Client::new(options).unwrap();
        let err = client
            .exchange("source-token")
            .timeout(Duration::from_millis(10))
            .send()
            .await
            .unwrap_err();

        match err {
            ExchangeError::Transport(err) => assert!(err.is_timeout()),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
