//! Network boundary for TheStandard.
//!
//! REST and JSON-RPC adapters share one execution path so they always produce
//! reports with the same core version and capability metadata.

use axum::{
    Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, FromRequestParts, State, connect_info::MockConnectInfo,
    },
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use the_standard::{
    CoreApiError, CoreBuildInfo, CoreError, CoreRuleBundle, CoreRuleRuntimeHealth,
    CoreRuntimeEngineHealth, CoreRuntimeHealth, CoreRuntimeRuleHealth, CoreRuntimeServiceHealth,
    CoreRuntimeTransportHealth, CoreServiceHealth, CoreUiManifest, DemoTransport,
    DetectionJobSnapshot, DetectionJobStatus, DetectionReport, DetectionRuntimeEvent, Engine,
    EngineConfig, HttpTransport, HttpTransportConfig, JSON_RPC_VERSION, JsonRpcRequest,
    JsonRpcResponse, ProbeRequest, ProbeTransport, RPC_METHOD_CORE_DETECT, RPC_METHOD_CORE_INFO,
    RPC_METHOD_CORE_MANIFEST, RuleRepositoryClient, RuleRepositoryConfig, RuleRepositoryProvenance,
    RuntimeEventStatus, RuntimeObserver, core_build_info, core_ui_manifest,
};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tower_http::cors::{AllowOrigin, CorsLayer};
use ulid::Ulid;
use url::Url;

const DEFAULT_CONFIG_PATH: &str = "the-standard.toml";
const MAX_RETAINED_DETECTION_JOBS: usize = 256;
/// Fixed window of the per-IP detection limiter. A minute matches the
/// `per_ip_detect_requests_per_minute` setting, so the configured number is
/// exactly the number of requests one client gets per window.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// Upper bound accepted for `per_ip_detect_requests_per_minute` (1000/s). A
/// larger value is a configuration mistake, not a limit, so it is rejected
/// instead of being clamped.
const MAX_PER_IP_DETECT_REQUESTS_PER_MINUTE: usize = 60_000;
/// Upper bound accepted for `rate_limit_max_entries`; the default is 4096 and
/// one entry is a small inline struct, so a million entries is still bounded
/// (tens of MiB) while anything beyond it is rejected.
const MAX_RATE_LIMIT_ENTRIES: usize = 1_048_576;

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    service: ServiceFileConfig,
    #[serde(default)]
    engine: EngineFileConfig,
    #[serde(default)]
    transport: TransportFileConfig,
    #[serde(default)]
    rules: RuleFileConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
struct ServiceFileConfig {
    host: IpAddr,
    port: u16,
    require_auth: bool,
    allow_private_targets: bool,
    allowed_origins: Vec<String>,
    demo_targets: Vec<String>,
    #[serde(default = "default_max_inflight_detections")]
    max_inflight_detections: usize,
    #[serde(default = "default_max_request_body_bytes")]
    max_request_body_bytes: usize,
    #[serde(default = "default_shutdown_grace_seconds")]
    shutdown_grace_seconds: u64,
    #[serde(default = "default_target_dns_timeout_seconds")]
    target_dns_timeout_seconds: u64,
    /// Detect requests per client address per minute; `0` disables the limit.
    #[serde(default = "default_per_ip_detect_requests_per_minute")]
    per_ip_detect_requests_per_minute: usize,
    /// Hard cap on the number of tracked client addresses.
    #[serde(default = "default_rate_limit_max_entries")]
    rate_limit_max_entries: usize,
}

fn default_max_inflight_detections() -> usize {
    8
}

fn default_max_request_body_bytes() -> usize {
    2 * 1024 * 1024
}

fn default_shutdown_grace_seconds() -> u64 {
    30
}

fn default_per_ip_detect_requests_per_minute() -> usize {
    0
}

fn default_rate_limit_max_entries() -> usize {
    4096
}

fn default_target_dns_timeout_seconds() -> u64 {
    5
}

impl Default for ServiceFileConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 8081,
            require_auth: false,
            allow_private_targets: false,
            allowed_origins: vec![
                "http://localhost:5174".into(),
                "http://127.0.0.1:5174".into(),
            ],
            demo_targets: Vec::new(),
            max_inflight_detections: 8,
            max_request_body_bytes: 2 * 1024 * 1024,
            shutdown_grace_seconds: 30,
            target_dns_timeout_seconds: 5,
            per_ip_detect_requests_per_minute: 0,
            rate_limit_max_entries: 4096,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
struct EngineFileConfig {
    request_timeout_seconds: u64,
    max_retries: usize,
    retry_backoff_milliseconds: u64,
    max_concurrent: usize,
    quick_timeout_seconds: u64,
    standard_timeout_seconds: u64,
    full_timeout_seconds: u64,
}

impl Default for EngineFileConfig {
    fn default() -> Self {
        Self {
            request_timeout_seconds: 30,
            max_retries: 3,
            retry_backoff_milliseconds: 1_000,
            max_concurrent: 3,
            quick_timeout_seconds: 60,
            standard_timeout_seconds: 120,
            full_timeout_seconds: 180,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
struct TransportFileConfig {
    max_response_bytes: usize,
    max_stream_bytes: usize,
    max_stream_events: usize,
}

impl Default for TransportFileConfig {
    fn default() -> Self {
        let defaults = HttpTransportConfig::default();
        Self {
            max_response_bytes: defaults.max_response_bytes,
            max_stream_bytes: defaults.max_stream_bytes,
            max_stream_events: defaults.max_stream_events,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
struct RuleFileConfig {
    manifest_url: String,
    fallback_directory: Option<PathBuf>,
    source_revision: Option<String>,
    allow_insecure_http: bool,
    refresh_seconds: u64,
    request_timeout_seconds: u64,
    max_manifest_bytes: usize,
    max_document_bytes: usize,
}

impl Default for RuleFileConfig {
    fn default() -> Self {
        Self {
            manifest_url: "https://raw.githubusercontent.com/MoBalance/SanBiao/main/manifest.json"
                .into(),
            fallback_directory: None,
            source_revision: None,
            allow_insecure_http: false,
            refresh_seconds: 300,
            request_timeout_seconds: 5,
            max_manifest_bytes: 256 * 1024,
            max_document_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreServiceConfig {
    pub host: IpAddr,
    pub port: u16,
    pub auth_token: Option<String>,
    pub require_auth: bool,
    pub allow_private_targets: bool,
    pub allowed_origins: Vec<String>,
    pub demo_targets: Vec<String>,
    pub max_inflight_detections: usize,
    pub max_request_body_bytes: usize,
    pub shutdown_grace_period: Duration,
    pub target_dns_timeout: Duration,
    /// Detect requests allowed per client IP per minute; `0` disables the limit.
    pub per_ip_detect_requests_per_minute: usize,
    /// Hard cap on the number of tracked client IPs in the rate-limit map.
    pub rate_limit_max_entries: usize,
    pub engine_config: EngineConfig,
    pub transport_config: HttpTransportConfig,
    pub rule_repository: Option<RuleRepositoryConfig>,
    pub rule_fallback_directory: Option<PathBuf>,
    pub rule_refresh_interval: Duration,
    pub rule_bundle: Option<Arc<CoreRuleBundle>>,
}

impl CoreServiceConfig {
    pub fn load() -> anyhow::Result<Self> {
        let explicit_path = env::var("THE_STANDARD_CONFIG_FILE")
            .ok()
            .map(|value| PathBuf::from(value.trim()))
            .filter(|path| !path.as_os_str().is_empty());
        let path = explicit_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        Self::load_path(&path, explicit_path.is_none())
    }

    /// Loads the configuration from an explicit file path.
    ///
    /// Embedding processes (the GhostReveal desktop application) use this to
    /// point at a packaged `the-standard.toml` without mutating the process
    /// environment. Environment overrides are applied exactly like
    /// [`Self::load`]; the only difference is that a missing file is an error
    /// instead of the implicit `the-standard.toml` default of [`Self::load`].
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        Self::load_path(path, false)
    }

    fn load_path(path: &Path, allow_missing: bool) -> anyhow::Result<Self> {
        let file = match fs::read_to_string(path) {
            Ok(source) => toml::from_str::<FileConfig>(&source).map_err(|error| {
                anyhow::anyhow!(
                    "invalid TheStandard configuration {}: {error}",
                    path.display()
                )
            })?,
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
                FileConfig::default()
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to read TheStandard configuration {}: {error}",
                    path.display()
                ));
            }
        };
        Self::resolve(file, |name| env::var(name).ok())
    }

    fn resolve(
        file: FileConfig,
        env_value: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Self> {
        let host = env_value("THE_STANDARD_HOST")
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(file.service.host);
        let port = env_value("THE_STANDARD_PORT")
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(file.service.port);
        let auth_token = env_value("THE_STANDARD_AUTH_TOKEN")
            .map(|token| token.trim().to_owned())
            .filter(|token| !token.is_empty());
        let require_auth =
            env_bool(&env_value, "THE_STANDARD_REQUIRE_AUTH")?.unwrap_or(file.service.require_auth);
        if require_auth && auth_token.is_none() {
            anyhow::bail!(
                "THE_STANDARD_AUTH_TOKEN is required when THE_STANDARD_REQUIRE_AUTH is enabled"
            );
        }
        let allowed_origins = match env_value("THE_STANDARD_ALLOWED_ORIGINS") {
            Some(value) => parse_allowed_origins(&value)?,
            None => parse_allowed_origins(&file.service.allowed_origins.join(","))?,
        };
        let demo_targets = match env_value("THE_STANDARD_DEMO_TARGETS") {
            Some(value) => parse_allowed_origins(&value)?,
            None => parse_allowed_origins(&file.service.demo_targets.join(","))?,
        };
        let max_inflight_detections = env_usize(
            &env_value,
            "THE_STANDARD_SERVICE_MAX_INFLIGHT_DETECTIONS",
            file.service.max_inflight_detections,
        )?;
        if !(1..=1024).contains(&max_inflight_detections) {
            anyhow::bail!(
                "THE_STANDARD_SERVICE_MAX_INFLIGHT_DETECTIONS must be between 1 and 1024"
            );
        }
        let max_request_body_bytes = env_usize(
            &env_value,
            "THE_STANDARD_SERVICE_MAX_REQUEST_BODY_BYTES",
            file.service.max_request_body_bytes,
        )?;
        if !(4 * 1024..=16 * 1024 * 1024).contains(&max_request_body_bytes) {
            anyhow::bail!(
                "THE_STANDARD_SERVICE_MAX_REQUEST_BODY_BYTES must be between 4096 and 16777216"
            );
        }
        let shutdown_grace_seconds = env_u64(
            &env_value,
            "THE_STANDARD_SERVICE_SHUTDOWN_GRACE_SECONDS",
            file.service.shutdown_grace_seconds,
        )?;
        if !(1..=300).contains(&shutdown_grace_seconds) {
            anyhow::bail!("THE_STANDARD_SERVICE_SHUTDOWN_GRACE_SECONDS must be between 1 and 300");
        }
        let target_dns_timeout_seconds = env_u64(
            &env_value,
            "THE_STANDARD_SERVICE_TARGET_DNS_TIMEOUT_SECONDS",
            file.service.target_dns_timeout_seconds,
        )?;
        if !(1..=30).contains(&target_dns_timeout_seconds) {
            anyhow::bail!(
                "THE_STANDARD_SERVICE_TARGET_DNS_TIMEOUT_SECONDS must be between 1 and 30"
            );
        }
        let per_ip_detect_requests_per_minute = env_usize(
            &env_value,
            "THE_STANDARD_SERVICE_PER_IP_DETECT_REQUESTS_PER_MINUTE",
            file.service.per_ip_detect_requests_per_minute,
        )?;
        if per_ip_detect_requests_per_minute > MAX_PER_IP_DETECT_REQUESTS_PER_MINUTE {
            anyhow::bail!(
                "THE_STANDARD_SERVICE_PER_IP_DETECT_REQUESTS_PER_MINUTE must be between 0 and {MAX_PER_IP_DETECT_REQUESTS_PER_MINUTE}"
            );
        }
        let rate_limit_max_entries = env_usize(
            &env_value,
            "THE_STANDARD_SERVICE_RATE_LIMIT_MAX_ENTRIES",
            file.service.rate_limit_max_entries,
        )?;
        if !(1..=MAX_RATE_LIMIT_ENTRIES).contains(&rate_limit_max_entries) {
            anyhow::bail!(
                "THE_STANDARD_SERVICE_RATE_LIMIT_MAX_ENTRIES must be between 1 and {MAX_RATE_LIMIT_ENTRIES}"
            );
        }
        let manifest_url =
            env_value("THE_STANDARD_RULE_MANIFEST_URL").unwrap_or(file.rules.manifest_url);
        let rule_fallback_directory = env_value("THE_STANDARD_RULE_FALLBACK_DIRECTORY")
            .map(PathBuf::from)
            .or(file.rules.fallback_directory);
        let source_revision = env_value("THE_STANDARD_RULE_SOURCE_REVISION")
            .or(file.rules.source_revision)
            .map(|revision| revision.trim().to_owned())
            .filter(|revision| !revision.is_empty());
        let allow_insecure_http =
            env_bool(&env_value, "THE_STANDARD_RULE_SOURCE_ALLOW_INSECURE_HTTP")?
                .unwrap_or(file.rules.allow_insecure_http);
        let rule_request_timeout_seconds = env_u64(
            &env_value,
            "THE_STANDARD_RULE_REQUEST_TIMEOUT_SECONDS",
            file.rules.request_timeout_seconds,
        )?;
        let max_manifest_bytes = env_usize(
            &env_value,
            "THE_STANDARD_RULE_MAX_MANIFEST_BYTES",
            file.rules.max_manifest_bytes,
        )?;
        let max_document_bytes = env_usize(
            &env_value,
            "THE_STANDARD_RULE_MAX_DOCUMENT_BYTES",
            file.rules.max_document_bytes,
        )?;
        let rule_repository = Some(
            RuleRepositoryConfig::new(
                &manifest_url,
                source_revision.as_deref(),
                allow_insecure_http,
            )
            .and_then(|config| {
                config.with_limits(
                    Duration::from_secs(rule_request_timeout_seconds),
                    max_manifest_bytes,
                    max_document_bytes,
                )
            })
            .map(|config| config.with_fallback_directory(rule_fallback_directory.clone()))
            .map_err(anyhow::Error::msg)?,
        );
        let refresh_seconds = env_u64(
            &env_value,
            "THE_STANDARD_RULE_REFRESH_SECONDS",
            file.rules.refresh_seconds,
        )?;
        if !(30..=86_400).contains(&refresh_seconds) {
            anyhow::bail!("THE_STANDARD_RULE_REFRESH_SECONDS must be between 30 and 86400");
        }
        let engine_config = EngineConfig {
            request_timeout: Duration::from_secs(env_u64(
                &env_value,
                "THE_STANDARD_ENGINE_REQUEST_TIMEOUT_SECONDS",
                file.engine.request_timeout_seconds,
            )?),
            max_retries: env_usize(
                &env_value,
                "THE_STANDARD_ENGINE_MAX_RETRIES",
                file.engine.max_retries,
            )?,
            retry_backoff: Duration::from_millis(env_u64(
                &env_value,
                "THE_STANDARD_ENGINE_RETRY_BACKOFF_MILLISECONDS",
                file.engine.retry_backoff_milliseconds,
            )?),
            max_concurrent: env_usize(
                &env_value,
                "THE_STANDARD_ENGINE_MAX_CONCURRENT",
                file.engine.max_concurrent,
            )?,
            quick_timeout: Duration::from_secs(env_u64(
                &env_value,
                "THE_STANDARD_ENGINE_QUICK_TIMEOUT_SECONDS",
                file.engine.quick_timeout_seconds,
            )?),
            standard_timeout: Duration::from_secs(env_u64(
                &env_value,
                "THE_STANDARD_ENGINE_STANDARD_TIMEOUT_SECONDS",
                file.engine.standard_timeout_seconds,
            )?),
            full_timeout: Duration::from_secs(env_u64(
                &env_value,
                "THE_STANDARD_ENGINE_FULL_TIMEOUT_SECONDS",
                file.engine.full_timeout_seconds,
            )?),
            rule_repository: rule_repository.clone(),
            rule_bundle: None,
        };
        engine_config.validate().map_err(anyhow::Error::msg)?;
        let transport_config = HttpTransportConfig {
            max_response_bytes: env_usize(
                &env_value,
                "THE_STANDARD_TRANSPORT_MAX_RESPONSE_BYTES",
                file.transport.max_response_bytes,
            )?,
            max_stream_bytes: env_usize(
                &env_value,
                "THE_STANDARD_TRANSPORT_MAX_STREAM_BYTES",
                file.transport.max_stream_bytes,
            )?,
            max_stream_events: env_usize(
                &env_value,
                "THE_STANDARD_TRANSPORT_MAX_STREAM_EVENTS",
                file.transport.max_stream_events,
            )?,
        };
        transport_config.validate().map_err(anyhow::Error::msg)?;
        let allow_private_targets = env_bool(&env_value, "THE_STANDARD_ALLOW_PRIVATE_TARGETS")?
            .unwrap_or(file.service.allow_private_targets);
        Ok(Self {
            host,
            port,
            auth_token,
            require_auth,
            allow_private_targets,
            allowed_origins,
            demo_targets,
            max_inflight_detections,
            max_request_body_bytes,
            shutdown_grace_period: Duration::from_secs(shutdown_grace_seconds),
            target_dns_timeout: Duration::from_secs(target_dns_timeout_seconds),
            per_ip_detect_requests_per_minute,
            rate_limit_max_entries,
            engine_config,
            transport_config,
            rule_repository,
            rule_fallback_directory,
            rule_refresh_interval: Duration::from_secs(refresh_seconds),
            rule_bundle: None,
        })
    }

    pub fn address(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

impl Default for CoreServiceConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8081,
            auth_token: None,
            require_auth: false,
            allow_private_targets: false,
            allowed_origins: vec![
                "http://localhost:5174".into(),
                "http://127.0.0.1:5174".into(),
            ],
            demo_targets: default_test_demo_targets(),
            per_ip_detect_requests_per_minute: 0,
            rate_limit_max_entries: 4096,
            max_inflight_detections: 8,
            max_request_body_bytes: 2 * 1024 * 1024,
            shutdown_grace_period: Duration::from_secs(30),
            target_dns_timeout: Duration::from_secs(5),
            engine_config: EngineConfig::default(),
            transport_config: HttpTransportConfig::default(),
            rule_repository: None,
            rule_fallback_directory: None,
            rule_refresh_interval: Duration::from_secs(300),
            rule_bundle: default_test_rule_bundle(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    engine_config: EngineConfig,
    rule_loader: Option<RuleBundleLoader>,
    static_rule_bundle: Option<Arc<CoreRuleBundle>>,
    rule_refresh_interval: Duration,
    live_transport: HttpTransport,
    auth_token: Option<String>,
    require_auth: bool,
    allow_private_targets: bool,
    demo_targets: Vec<String>,
    detection_slots: Arc<Semaphore>,
    max_inflight_detections: usize,
    max_request_body_bytes: usize,
    shutdown_grace_period: Duration,
    target_dns_timeout: Duration,
    rate_limiter: Arc<PerIpRateLimiter>,
    jobs: Arc<StdMutex<BTreeMap<String, DetectionJobSnapshot>>>,
}

impl From<CoreServiceConfig> for AppState {
    fn from(config: CoreServiceConfig) -> Self {
        let rule_loader = config
            .rule_repository
            .clone()
            .map(|repository| RuleBundleLoader::new(repository, config.rule_refresh_interval));
        let mut engine_config = config.engine_config;
        engine_config.rule_repository = config.rule_repository;
        Self {
            engine_config,
            rule_loader,
            static_rule_bundle: config.rule_bundle,
            rule_refresh_interval: config.rule_refresh_interval,
            live_transport: HttpTransport::with_config(config.transport_config)
                .expect("service transport configuration is validated before app construction"),
            auth_token: config.auth_token,
            require_auth: config.require_auth,
            allow_private_targets: config.allow_private_targets,
            demo_targets: config.demo_targets,
            detection_slots: Arc::new(Semaphore::new(config.max_inflight_detections)),
            max_inflight_detections: config.max_inflight_detections,
            max_request_body_bytes: config.max_request_body_bytes,
            shutdown_grace_period: config.shutdown_grace_period,
            target_dns_timeout: config.target_dns_timeout,
            rate_limiter: Arc::new(PerIpRateLimiter::new(
                config.per_ip_detect_requests_per_minute,
                config.rate_limit_max_entries,
                RATE_LIMIT_WINDOW,
            )),
            jobs: Arc::new(StdMutex::new(BTreeMap::new())),
        }
    }
}

/// Outcome of one per-IP rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateLimitDecision {
    Allowed,
    Limited { retry_after_seconds: u64 },
}

/// One fixed-window counter, keyed by client IP.
#[derive(Debug, Clone, Copy)]
struct RateLimitWindow {
    started_at: Instant,
    requests: usize,
}

/// Fixed-window, per-client limiter for the detection entry points.
///
/// The key is the peer IP of the accepted TCP connection (`SocketAddr::ip()`).
/// The port is deliberately dropped because it changes with every connection,
/// and forwarded headers such as `X-Forwarded-For` are caller-controlled, so
/// neither identifies a client.
///
/// One mutex guards one small map. The critical section only touches the map
/// and never awaits, so it costs a few hundred nanoseconds per request; sharded
/// or lock-free counters would add far more complexity (especially for the
/// bounded-size eviction) than the contention they would remove at this scale.
struct PerIpRateLimiter {
    requests_per_window: usize,
    max_entries: usize,
    window: Duration,
    entries: StdMutex<BTreeMap<IpAddr, RateLimitWindow>>,
}

impl PerIpRateLimiter {
    fn new(requests_per_window: usize, max_entries: usize, window: Duration) -> Self {
        Self {
            requests_per_window,
            max_entries: max_entries.max(1),
            window,
            entries: StdMutex::new(BTreeMap::new()),
        }
    }

    fn requests_per_window(&self) -> usize {
        self.requests_per_window
    }

    fn max_entries(&self) -> usize {
        self.max_entries
    }

    fn window(&self) -> Duration {
        self.window
    }

    /// Counts one detect attempt of `peer` at `now` and reports whether it is
    /// inside the budget. `now` is a parameter so window rollover can be tested
    /// without sleeping.
    fn check(&self, peer: IpAddr, now: Instant) -> RateLimitDecision {
        if self.requests_per_window == 0 {
            return RateLimitDecision::Allowed;
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&peer) {
            let elapsed = now.saturating_duration_since(entry.started_at);
            if elapsed >= self.window {
                // The window rolled over: this request opens the next one.
                entry.started_at = now;
                entry.requests = 1;
                return RateLimitDecision::Allowed;
            }
            if entry.requests >= self.requests_per_window {
                let remaining = self.window.saturating_sub(elapsed);
                let retry_after = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
                return RateLimitDecision::Limited {
                    retry_after_seconds: retry_after.max(1),
                };
            }
            entry.requests += 1;
            return RateLimitDecision::Allowed;
        }
        // Unknown key: make room first so the map can never exceed
        // `max_entries` no matter how many distinct source IPs appear.
        if entries.len() >= self.max_entries {
            Self::evict_one(&mut entries);
        }
        entries.insert(
            peer,
            RateLimitWindow {
                started_at: now,
                requests: 1,
            },
        );
        RateLimitDecision::Allowed
    }

    /// Drops the least recently started window. Because windows are fixed
    /// length, expired entries are always the oldest ones, so they are reclaimed
    /// before any live entry and a spoofed-IP flood rotates the map instead of
    /// growing it. The trade-off is that such a flood can reset the counter of
    /// an honest client whose window happens to be the oldest: bounded memory
    /// wins over exact fairness.
    fn evict_one(entries: &mut BTreeMap<IpAddr, RateLimitWindow>) {
        let oldest = entries
            .iter()
            .min_by_key(|(_, window)| window.started_at)
            .map(|(peer, _)| *peer);
        if let Some(oldest) = oldest {
            entries.remove(&oldest);
        }
    }

    /// Applies the limit to an already resolved peer address.
    fn check_peer(&self, peer: Option<SocketAddr>) -> Result<(), ServiceError> {
        let Some(peer) = peer else {
            // Only reachable when the router runs without
            // `into_make_service_with_connect_info`; the serve path always
            // supplies the address. An unknown peer is never charged.
            return Ok(());
        };
        match self.check(peer.ip(), Instant::now()) {
            RateLimitDecision::Allowed => Ok(()),
            RateLimitDecision::Limited {
                retry_after_seconds,
            } => Err(ServiceError::RateLimited {
                retry_after_seconds,
            }),
        }
    }

    /// Number of tracked client addresses; used by the eviction test.
    #[cfg(test)]
    fn tracked_entries(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// Peer address of the TCP connection that delivered the request.
///
/// Populated by `Router::into_make_service_with_connect_info::<SocketAddr>()`
/// in the serve path. Forwarded headers (`X-Forwarded-For`, `Forwarded`, …) are
/// deliberately ignored: they are caller-controlled, so honouring them would let
/// one client rotate keys and bypass the limit. A deployment behind a proxy must
/// terminate connections at the proxy and rate-limit on that side.
struct PeerAddr(Option<SocketAddr>);

impl FromRequestParts<AppState> for PeerAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0)
            .or_else(|| {
                parts
                    .extensions
                    .get::<MockConnectInfo<SocketAddr>>()
                    .map(|info| info.0)
            });
        Ok(Self(peer))
    }
}

#[derive(Clone)]
struct RuleBundleLoader {
    client: RuleRepositoryClient,
    refresh_interval: Duration,
    cached: Arc<RwLock<Option<CachedRuleBundle>>>,
    refresh_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct CachedRuleBundle {
    bundle: Arc<CoreRuleBundle>,
    refreshed_at: Instant,
}

impl RuleBundleLoader {
    fn new(config: RuleRepositoryConfig, refresh_interval: Duration) -> Self {
        let client = RuleRepositoryClient::new(
            config,
            concat!("the-standard-service/", env!("CARGO_PKG_VERSION")),
        )
        .expect("rule repository HTTP client configuration is valid");
        Self {
            client,
            refresh_interval,
            cached: Arc::new(RwLock::new(None)),
            refresh_lock: Arc::new(Mutex::new(())),
        }
    }

    async fn resolve(&self) -> Option<Arc<CoreRuleBundle>> {
        if let Some(cached) = self.cached.read().await.as_ref()
            && cached.refreshed_at.elapsed() < self.refresh_interval
        {
            return Some(Arc::clone(&cached.bundle));
        }
        let _refresh_guard = self.refresh_lock.lock().await;
        if let Some(cached) = self.cached.read().await.as_ref()
            && cached.refreshed_at.elapsed() < self.refresh_interval
        {
            return Some(Arc::clone(&cached.bundle));
        }
        match self.fetch().await {
            Ok(bundle) => {
                let bundle = Arc::new(bundle);
                *self.cached.write().await = Some(CachedRuleBundle {
                    bundle: Arc::clone(&bundle),
                    refreshed_at: Instant::now(),
                });
                Some(bundle)
            }
            Err(error) => {
                tracing::warn!(%error, "Core rule bundle refresh failed");
                self.cached
                    .read()
                    .await
                    .as_ref()
                    .map(|cached| Arc::clone(&cached.bundle))
            }
        }
    }

    async fn fetch(&self) -> Result<CoreRuleBundle, String> {
        let manifest = self
            .client
            .fetch_manifest_with_source()
            .await
            .map_err(|error| error.to_string())?;
        let document = self
            .client
            .fetch_document_with_source(&manifest.value.core_rules)
            .await
            .map_err(|error| error.to_string())?;
        CoreRuleBundle::from_repository_document(
            &document.value,
            &manifest.value.core_rules,
            self.client.config().source_revision.clone(),
            RuleRepositoryProvenance {
                release: manifest.value.release,
                manifest_source: manifest.source,
                document_source: document.source,
            },
        )
        .map_err(|error| error.to_string())
    }
}

/// One HTTP route served by the service.
///
/// [`build_app`] registers exactly these routes and [`openapi_document`]
/// documents exactly these routes, so a new endpoint cannot silently miss the
/// published machine-readable contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServiceRoute {
    method: &'static str,
    path: &'static str,
    summary: &'static str,
}

const SERVICE_ROUTES: &[ServiceRoute] = &[
    ServiceRoute {
        method: "get",
        path: "/health",
        summary: "Service, rule and Core runtime health",
    },
    ServiceRoute {
        method: "get",
        path: "/health/live",
        summary: "Liveness probe with Core build information",
    },
    ServiceRoute {
        method: "get",
        path: "/health/ready",
        summary: "Readiness probe gated on an active rule bundle",
    },
    ServiceRoute {
        method: "get",
        path: "/v1/core",
        summary: "Core build information and capability profile",
    },
    ServiceRoute {
        method: "get",
        path: "/v1/manifest",
        summary: "Self-describing UI manifest for the detection request form",
    },
    ServiceRoute {
        method: "post",
        path: "/v1/detect",
        summary: "Run a detection synchronously and return the report",
    },
    ServiceRoute {
        method: "post",
        path: "/v1/detect/jobs",
        summary: "Queue a detection job and return its snapshot",
    },
    ServiceRoute {
        method: "get",
        path: "/v1/detect/jobs/{job_id}",
        summary: "Read the current snapshot of a detection job",
    },
    ServiceRoute {
        method: "post",
        path: "/rpc",
        summary: "JSON-RPC 2.0 entry point (core.info, core.manifest, core.detect)",
    },
    ServiceRoute {
        method: "get",
        path: "/openapi.json",
        summary: "This OpenAPI 3.1 document",
    },
];

fn route_method_router(route: &ServiceRoute) -> MethodRouter<AppState> {
    match (route.method, route.path) {
        ("get", "/health") => get(health),
        ("get", "/health/live") => get(liveness),
        ("get", "/health/ready") => get(readiness),
        ("get", "/v1/core") => get(core_info),
        ("get", "/v1/manifest") => get(core_manifest),
        ("post", "/v1/detect") => post(detect),
        ("post", "/v1/detect/jobs") => post(create_detection_job),
        ("get", "/v1/detect/jobs/{job_id}") => get(get_detection_job),
        ("post", "/rpc") => post(rpc),
        ("get", "/openapi.json") => get(openapi_json),
        _ => panic!(
            "service route {} {} is declared without a handler",
            route.method, route.path
        ),
    }
}

pub fn build_app(config: CoreServiceConfig) -> Router {
    let cors = cors_layer(&config.allowed_origins);
    let max_request_body_bytes = config.max_request_body_bytes;
    let mut router: Router<AppState> = Router::new();
    for route in SERVICE_ROUTES {
        router = router.route(route.path, route_method_router(route));
    }
    router
        .with_state(AppState::from(config))
        .layer(DefaultBodyLimit::max(max_request_body_bytes))
        .layer(cors)
        .layer(middleware::from_fn(request_context))
}

/// OpenAPI 3.1 document describing every route the service serves.
///
/// It is generated in process from [`SERVICE_ROUTES`], so the published
/// contract cannot drift from the router, and it needs no authorization.
pub fn openapi_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "TheStandard Core API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "REST and JSON-RPC surface of the TheStandard detection service. Both adapters share one execution path, so they always return the same core version, capability metadata and report shape.",
            "license": {
                "name": "AGPL-3.0-only",
                "identifier": "AGPL-3.0-only",
            },
        },
        "servers": [{"url": "/", "description": "This service"}],
        "tags": [
            {"name": "health", "description": "Unauthenticated liveness and readiness probes"},
            {"name": "core", "description": "Core build information and the UI manifest"},
            {"name": "detect", "description": "Synchronous and asynchronous detection"},
            {"name": "rpc", "description": "JSON-RPC 2.0 adapter"},
            {"name": "meta", "description": "Machine-readable API contract"},
        ],
        "paths": openapi_paths(),
        "components": {
            "schemas": openapi_schemas(),
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Required only when the service is configured with THE_STANDARD_AUTH_TOKEN (THE_STANDARD_REQUIRE_AUTH). Health endpoints and this document are always public.",
                },
            },
            "headers": {
                "RequestId": {
                    "description": "Server generated ULID correlation id, also returned as the x-request-id response header.",
                    "schema": {"type": "string"},
                },
            },
        },
    })
}

fn openapi_paths() -> Value {
    let mut paths = Map::new();
    for route in SERVICE_ROUTES {
        let entry = paths
            .entry(route.path.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(operations) = entry {
            operations.insert(route.method.to_owned(), openapi_operation(route));
        }
    }
    Value::Object(paths)
}

fn openapi_json_response(schema: &str, description: &str) -> Value {
    let reference = format!("#/components/schemas/{schema}");
    json!({
        "description": description,
        "headers": {"x-request-id": {"$ref": "#/components/headers/RequestId"}},
        "content": {"application/json": {"schema": {"$ref": reference}}},
    })
}

fn openapi_request_body(schema: &str, description: &str) -> Value {
    let reference = format!("#/components/schemas/{schema}");
    json!({
        "required": true,
        "description": description,
        "content": {"application/json": {"schema": {"$ref": reference}}},
    })
}

fn openapi_operation(route: &ServiceRoute) -> Value {
    match (route.method, route.path) {
        ("get", "/health") => json!({
            "tags": ["health"],
            "summary": route.summary,
            "description": "Returns the service version, Core build information, the active rule bundle provenance and the effective runtime limits. Always readable without authorization; status is degraded when no validated rule bundle is available.",
            "operationId": "getServiceHealth",
            "security": [],
            "responses": {
                "200": openapi_json_response("CoreServiceHealth", "Service health snapshot."),
            },
        }),
        ("get", "/health/live") => json!({
            "tags": ["health"],
            "summary": route.summary,
            "description": "Liveness probe. Does not depend on rule-repository readiness and never fails on a missing rule bundle.",
            "operationId": "getServiceLiveness",
            "security": [],
            "responses": {
                "200": openapi_json_response("CoreBuildInfo", "Core build information."),
            },
        }),
        ("get", "/health/ready") => json!({
            "tags": ["health"],
            "summary": route.summary,
            "description": "Readiness probe. Returns 503 until a validated Core rule bundle is available, so load balancers keep traffic away from an unready instance.",
            "operationId": "getServiceReadiness",
            "security": [],
            "responses": {
                "200": openapi_json_response("CoreServiceHealth", "Rule bundle active; the instance can serve detections."),
                "503": openapi_json_response("CoreServiceHealth", "No validated rule bundle is available."),
            },
        }),
        ("get", "/v1/core") => json!({
            "tags": ["core"],
            "summary": route.summary,
            "description": "Core build information shared by the REST and JSON-RPC adapters.",
            "operationId": "getCoreInfo",
            "security": [{"bearerAuth": []}],
            "responses": {
                "200": openapi_json_response("CoreBuildInfo", "Core build information."),
                "401": openapi_json_response("CoreApiError", "Missing or invalid service authorization."),
            },
        }),
        ("get", "/v1/manifest") => json!({
            "tags": ["core"],
            "summary": route.summary,
            "description": "Self-describing UI manifest: request fields, sections, layouts and presentation formats.",
            "operationId": "getCoreManifest",
            "security": [{"bearerAuth": []}],
            "responses": {
                "200": openapi_json_response("CoreUiManifest", "UI manifest; identical to the core.manifest JSON-RPC result."),
                "401": openapi_json_response("CoreApiError", "Missing or invalid service authorization."),
            },
        }),
        ("post", "/v1/detect") => json!({
            "tags": ["detect"],
            "summary": route.summary,
            "description": "Runs a detection and returns the full report. Returns service_overloaded with Retry-After when detection capacity is full.",
            "operationId": "detectSynchronously",
            "security": [{"bearerAuth": []}],
            "requestBody": openapi_request_body("ProbeRequest", "Detection request."),
            "responses": {
                "200": openapi_json_response("DetectionReport", "Versioned detection report."),
                "400": openapi_json_response("CoreApiError", "invalid_request: malformed request, invalid target or unknown detection section."),
                "401": openapi_json_response("CoreApiError", "unauthorized: missing or invalid service authorization."),
                "429": openapi_json_response("CoreApiError", "service_overloaded: detection capacity is full; or rate_limited: the per-IP detection limit for this window is exhausted. Both send Retry-After with the seconds to wait."),
                "502": openapi_json_response("CoreApiError", "upstream_unavailable, upstream_invalid_response, target_resolution_failed or target_resolution_timeout."),
                "503": openapi_json_response("CoreApiError", "rules_unavailable: no validated Core rule bundle is currently available."),
                "504": openapi_json_response("CoreApiError", "detection_timeout: the detection exceeded its configured overall timeout."),
            },
        }),
        ("post", "/v1/detect/jobs") => json!({
            "tags": ["detect"],
            "summary": route.summary,
            "description": "Queues a detection job and returns 202 with the initial snapshot. Only the newest 256 snapshots are retained.",
            "operationId": "createDetectionJob",
            "security": [{"bearerAuth": []}],
            "requestBody": openapi_request_body("ProbeRequest", "Detection request."),
            "responses": {
                "202": openapi_json_response("DetectionJobSnapshot", "Job accepted; poll GET /v1/detect/jobs/{job_id} until the status is completed or failed."),
                "400": openapi_json_response("CoreApiError", "invalid_request: malformed request or unknown detection section."),
                "401": openapi_json_response("CoreApiError", "unauthorized: missing or invalid service authorization."),
                "429": openapi_json_response("CoreApiError", "service_overloaded: detection capacity is full; or rate_limited: the per-IP detection limit for this window is exhausted. Both send Retry-After with the seconds to wait."),
            },
        }),
        ("get", "/v1/detect/jobs/{job_id}") => json!({
            "tags": ["detect"],
            "summary": route.summary,
            "description": "Returns the current snapshot, including the redacted runtime event log and the report once the job completed.",
            "operationId": "getDetectionJob",
            "security": [{"bearerAuth": []}],
            "parameters": [
                {
                    "name": "job_id",
                    "in": "path",
                    "required": true,
                    "description": "ULID of the job returned by POST /v1/detect/jobs.",
                    "schema": {"type": "string"},
                },
            ],
            "responses": {
                "200": openapi_json_response("DetectionJobSnapshot", "Current job snapshot."),
                "401": openapi_json_response("CoreApiError", "unauthorized: missing or invalid service authorization."),
                "404": openapi_json_response("CoreApiError", "job_not_found: the job was not found or has expired."),
            },
        }),
        ("post", "/rpc") => json!({
            "tags": ["rpc"],
            "summary": route.summary,
            "description": "JSON-RPC 2.0 entry point. core.info, core.manifest and core.detect return exactly the same payloads as the REST routes; transport-level failures are reported as JSON-RPC errors with the CoreApiError code in error.data.code.",
            "operationId": "postJsonRpc",
            "security": [{"bearerAuth": []}],
            "requestBody": openapi_request_body("JsonRpcRequest", "JSON-RPC 2.0 request."),
            "responses": {
                "200": openapi_json_response("JsonRpcResponse", "JSON-RPC 2.0 response carrying either a result or an error."),
                "401": openapi_json_response("CoreApiError", "unauthorized: missing or invalid service authorization."),
                "429": openapi_json_response("CoreApiError", "rate_limited: the per-IP core.detect limit for this window is exhausted; Retry-After carries the seconds to wait. core.info and core.manifest are never limited."),
            },
        }),
        ("get", "/openapi.json") => json!({
            "tags": ["meta"],
            "summary": route.summary,
            "description": "This OpenAPI 3.1 document, readable without authorization like the health endpoints.",
            "operationId": "getOpenApiDocument",
            "security": [],
            "responses": {
                "200": openapi_json_response("OpenApiDocument", "The service OpenAPI 3.1 document."),
            },
        }),
        _ => panic!(
            "service route {} {} has no OpenAPI operation",
            route.method, route.path
        ),
    }
}

fn openapi_schemas() -> Value {
    // Each schema is a separate `json!` invocation so the macro expansion stays
    // shallow; the collection itself is a plain array of pairs.
    let entries: [(&str, Value); 41] = [
        (
            "Protocol",
            json!({
                "type": "string",
                "description": "Provider wire protocol of the detection target.",
                "enum": ["anthropic", "openai", "gemini"],
            }),
        ),
        (
            "ProbeMode",
            json!({
                "type": "string",
                "description": "Detection depth.",
                "enum": ["quick", "standard", "full"],
                "default": "standard",
            }),
        ),
        (
            "ProbeRequest",
            json!({
                "type": "object",
                "description": "Detection request accepted by POST /v1/detect, POST /v1/detect/jobs and the core.detect JSON-RPC method.",
                "required": ["baseUrl", "apiKey", "model", "protocol"],
                "properties": {
                    "baseUrl": {"type": "string", "description": "Target provider base URL; surrounding whitespace and trailing slashes are trimmed."},
                    "apiKey": {"type": "string", "description": "Target provider credential. Never echoed in reports."},
                    "model": {"type": "string", "description": "Target model identifier."},
                    "protocol": {"$ref": "#/components/schemas/Protocol"},
                    "mode": {"$ref": "#/components/schemas/ProbeMode"},
                    "parameters": {"type": "object", "additionalProperties": true, "description": "Extra provider parameters forwarded to the target API."},
                    "sections": {"type": "array", "items": {"type": "string"}, "description": "Optional detection-section selection. Empty selects every default-enabled section."},
                },
            }),
        ),
        (
            "CoreBuildInfo",
            json!({
                "type": "object",
                "description": "Build and capability metadata of the Core detection library.",
                "required": ["name", "version", "reportSchemaVersion", "capabilityProfile", "capabilities", "supportedProtocols"],
                "properties": {
                    "name": {"type": "string", "examples": ["TheStandard"]},
                    "version": {"type": "string", "description": "Core version. Do not compare it against a hardcoded string."},
                    "reportSchemaVersion": {"type": "integer", "description": "Wire schema version of DetectionReport."},
                    "capabilityProfile": {"type": "string", "description": "Scores are only comparable inside one capability profile."},
                    "capabilities": {"type": "array", "items": {"type": "string"}},
                    "supportedProtocols": {"type": "array", "items": {"$ref": "#/components/schemas/Protocol"}},
                },
            }),
        ),
        (
            "RuleRepositoryProvenance",
            json!({
                "type": "object",
                "description": "Where the rule manifest and the rule document came from.",
                "required": ["release", "manifestSource", "documentSource"],
                "properties": {
                    "release": {"type": "string"},
                    "manifestSource": {"type": "string", "enum": ["remote", "local_fallback"]},
                    "documentSource": {"type": "string", "enum": ["remote", "local_fallback"]},
                },
            }),
        ),
        (
            "RuleBundleProvenance",
            json!({
                "type": "object",
                "description": "Identity, version and digest of the rule bundle used for a report.",
                "required": ["id", "version", "channel", "publishedAt", "digest"],
                "properties": {
                    "id": {"type": "string"},
                    "version": {"type": "string"},
                    "channel": {"type": "string"},
                    "publishedAt": {"type": "string", "format": "date-time"},
                    "digest": {"type": "string", "description": "Canonical JSON digest of the rule document."},
                    "sourceRevision": {"type": "string"},
                    "repository": {"$ref": "#/components/schemas/RuleRepositoryProvenance"},
                },
            }),
        ),
        (
            "DetectionTarget",
            json!({
                "type": "object",
                "description": "Redacted description of the detected target.",
                "required": ["baseUrl", "apiKeyMasked", "model", "protocol"],
                "properties": {
                    "baseUrl": {"type": "string"},
                    "apiKeyMasked": {"type": "string", "description": "Masked credential; the raw API key never appears in a report."},
                    "model": {"type": "string"},
                    "protocol": {"$ref": "#/components/schemas/Protocol"},
                },
            }),
        ),
        (
            "UsageMetrics",
            json!({
                "type": "object",
                "required": ["inputTokens", "outputTokens"],
                "properties": {
                    "inputTokens": {"type": "integer"},
                    "outputTokens": {"type": "integer"},
                    "cacheReadInputTokens": {"type": "integer"},
                    "cacheCreationInputTokens": {"type": "integer"},
                    "providerExtensions": {"type": "object", "additionalProperties": true},
                },
            }),
        ),
        (
            "PerformanceMetrics",
            json!({
                "type": "object",
                "required": ["requestCount", "totalLatencyMs", "averageLatencyMs", "ttftMs", "tokensPerSecond", "retryCount", "backoffCount", "usage"],
                "properties": {
                    "requestCount": {"type": "integer"},
                    "totalLatencyMs": {"type": "integer"},
                    "averageLatencyMs": {"type": "integer"},
                    "ttftMs": {"type": ["integer", "null"]},
                    "tokensPerSecond": {"type": ["number", "null"]},
                    "retryCount": {"type": "integer"},
                    "backoffCount": {"type": "integer"},
                    "usage": {"$ref": "#/components/schemas/UsageMetrics"},
                },
            }),
        ),
        (
            "DetectorEvidence",
            json!({
                "type": "object",
                "description": "One weighted evidence item. A skip or error status means the detector could not verify anything and only lowers coverage.",
                "required": ["name", "displayName", "category", "status", "severity", "score", "weight", "summary"],
                "properties": {
                    "name": {"type": "string"},
                    "displayName": {"type": "string"},
                    "category": {"type": "string", "enum": ["authenticity", "capability", "protocol"]},
                    "status": {"type": "string", "enum": ["pass", "warn", "fail", "error", "skip"]},
                    "severity": {"type": "string", "enum": ["info", "minor", "major", "critical"]},
                    "basis": {"type": "string", "enum": ["observed", "inferred", "unsupported"], "default": "inferred"},
                    "confidence": {"type": ["number", "null"]},
                    "score": {"type": "number"},
                    "weight": {"type": "number"},
                    "summary": {"type": "string"},
                    "details": {"type": "object", "additionalProperties": true},
                },
            }),
        ),
        (
            "ReportSectionSelection",
            json!({
                "type": "object",
                "description": "Detection sections explicitly requested by the caller and the default-enabled sections that were therefore not run.",
                "required": ["requested", "notSelected"],
                "properties": {
                    "requested": {"type": "array", "items": {"type": "string"}},
                    "notSelected": {"type": "array", "items": {"type": "string"}},
                },
            }),
        ),
        (
            "PresentationField",
            json!({
                "type": "object",
                "required": ["key", "label", "value", "format"],
                "properties": {
                    "key": {"type": "string"},
                    "label": {"type": "string"},
                    "value": {},
                    "format": {"type": "string"},
                    "unit": {"type": "string"},
                    "description": {"type": "string"},
                    "status": {"type": "string"},
                },
            }),
        ),
        (
            "PresentationRow",
            json!({
                "type": "object",
                "required": ["id", "fields"],
                "properties": {
                    "id": {"type": "string"},
                    "status": {"type": "string"},
                    "fields": {"type": "array", "items": {"$ref": "#/components/schemas/PresentationField"}},
                },
            }),
        ),
        (
            "PresentationSection",
            json!({
                "type": "object",
                "required": ["id", "title", "layout"],
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "layout": {"type": "string"},
                    "fields": {"type": "array", "items": {"$ref": "#/components/schemas/PresentationField"}},
                    "rows": {"type": "array", "items": {"$ref": "#/components/schemas/PresentationRow"}},
                },
            }),
        ),
        (
            "PresentationView",
            json!({
                "type": "object",
                "required": ["id", "label", "sections"],
                "properties": {
                    "id": {"type": "string"},
                    "label": {"type": "string"},
                    "description": {"type": "string"},
                    "sections": {"type": "array", "items": {"$ref": "#/components/schemas/PresentationSection"}},
                },
            }),
        ),
        (
            "ReportPresentation",
            json!({
                "type": "object",
                "description": "Self-describing renderable projection of the report.",
                "required": ["schemaVersion", "language", "views"],
                "properties": {
                    "schemaVersion": {"type": "integer"},
                    "language": {"type": "string"},
                    "views": {"type": "array", "items": {"$ref": "#/components/schemas/PresentationView"}},
                },
            }),
        ),
        (
            "ContextAuditSample",
            json!({
                "type": "object",
                "properties": {
                    "level": {"type": "integer"},
                    "controlledUnits": {"type": "integer"},
                    "controlledBytes": {"type": "integer"},
                    "visibleInputTokenEstimate": {"type": "integer"},
                    "reportedInputTokens": {"type": ["integer", "null"]},
                    "estimatedInputOverheadTokens": {"type": ["integer", "null"]},
                    "exactEchoRequested": {"type": "boolean"},
                    "requestBodyBytes": {"type": "integer"},
                    "messageCount": {"type": "integer"},
                    "requestFingerprint": {"type": "string"},
                    "independentRequest": {"type": "boolean"},
                    "cacheReadInputTokens": {"type": "integer"},
                    "cacheCreationInputTokens": {"type": "integer"},
                },
            }),
        ),
        (
            "ContextAuditSummary",
            json!({
                "type": "object",
                "description": "Controlled context-overhead audit summary.",
                "required": ["sampleCount", "samples", "usageAvailable", "overheadAssessment", "finalEchoStatus", "controlledContextConfirmed", "independentRequests", "uniqueRequestFingerprints", "cacheHitObserved", "accountingInterpretation"],
                "properties": {
                    "sampleCount": {"type": "integer"},
                    "samples": {"type": "array", "items": {"$ref": "#/components/schemas/ContextAuditSample"}},
                    "usageAvailable": {"type": "boolean"},
                    "monotonicGrowth": {"type": ["boolean", "null"]},
                    "growthRatio": {"type": ["number", "null"]},
                    "fitConfidence": {"type": ["number", "null"]},
                    "estimatedFixedOverheadTokens": {"type": ["integer", "null"]},
                    "overheadAssessment": {"type": "string", "enum": ["expected", "elevated", "high", "unknown"]},
                    "finalEchoStatus": {"type": "string", "enum": ["exact", "mismatch", "unavailable"]},
                    "controlledContextConfirmed": {"type": "boolean"},
                    "independentRequests": {"type": "boolean"},
                    "uniqueRequestFingerprints": {"type": "boolean"},
                    "cumulativeHistorySuspected": {"type": ["boolean", "null"]},
                    "cacheHitObserved": {"type": "boolean"},
                    "accountingInterpretation": {"type": "string"},
                },
            }),
        ),
        (
            "DetectionReport",
            json!({
                "type": "object",
                "description": "Versioned detection report returned by POST /v1/detect and the core.detect JSON-RPC method.",
                "required": ["id", "createdAt", "core", "rules", "target", "mode", "totalScore", "verdict", "tier", "tierMessage", "evidence", "performance", "coverage"],
                "properties": {
                    "id": {"type": "string"},
                    "createdAt": {"type": "string", "format": "date-time"},
                    "core": {"$ref": "#/components/schemas/CoreBuildInfo"},
                    "rules": {"$ref": "#/components/schemas/RuleBundleProvenance"},
                    "target": {"$ref": "#/components/schemas/DetectionTarget"},
                    "mode": {"$ref": "#/components/schemas/ProbeMode"},
                    "totalScore": {"type": "number"},
                    "verdict": {"type": "string", "enum": ["verified", "inconclusive", "rejected"]},
                    "tier": {"type": "string", "enum": ["cryptographic", "protocol", "behavioral"]},
                    "tierMessage": {"type": "string"},
                    "evidence": {"type": "array", "items": {"$ref": "#/components/schemas/DetectorEvidence"}},
                    "performance": {"$ref": "#/components/schemas/PerformanceMetrics"},
                    "contextAudit": {"$ref": "#/components/schemas/ContextAuditSummary"},
                    "presentation": {"$ref": "#/components/schemas/ReportPresentation"},
                    "sectionSelection": {"$ref": "#/components/schemas/ReportSectionSelection"},
                    "coverage": {"$ref": "#/components/schemas/ReportCoverage"},
                },
            }),
        ),
        (
            "ReportCoverage",
            json!({
                "type": "object",
                "description": "How much of the applicable evidence weight the detectors could verify. Unknown detectors only lower the ratio; it never changes totalScore.",
                "required": ["verifiedWeight", "applicableWeight", "ratio", "unverifiedCount"],
                "properties": {
                    "verifiedWeight": {"type": "number"},
                    "applicableWeight": {"type": "number"},
                    "ratio": {"type": "number"},
                    "unverifiedCount": {"type": "integer"},
                },
            }),
        ),
        (
            "RuntimeEventStatus",
            json!({
                "type": "string",
                "enum": ["info", "running", "success", "warning", "error"],
            }),
        ),
        (
            "DetectionRuntimeEvent",
            json!({
                "type": "object",
                "description": "Redacted runtime progress event of a detection job.",
                "required": ["sequence", "elapsedMs", "stage", "event", "status", "message"],
                "properties": {
                    "sequence": {"type": "integer"},
                    "elapsedMs": {"type": "integer"},
                    "stage": {"type": "string"},
                    "event": {"type": "string"},
                    "status": {"$ref": "#/components/schemas/RuntimeEventStatus"},
                    "message": {"type": "string"},
                    "details": {"type": "object", "additionalProperties": true},
                },
            }),
        ),
        (
            "DetectionJobStatus",
            json!({
                "type": "string",
                "enum": ["queued", "running", "completed", "failed"],
            }),
        ),
        (
            "DetectionJobSnapshot",
            json!({
                "type": "object",
                "description": "Snapshot of an asynchronous detection job.",
                "required": ["id", "status", "createdAt", "model", "protocol", "mode", "events"],
                "properties": {
                    "id": {"type": "string"},
                    "status": {"$ref": "#/components/schemas/DetectionJobStatus"},
                    "createdAt": {"type": "string", "format": "date-time"},
                    "model": {"type": "string"},
                    "protocol": {"$ref": "#/components/schemas/Protocol"},
                    "mode": {"$ref": "#/components/schemas/ProbeMode"},
                    "events": {"type": "array", "items": {"$ref": "#/components/schemas/DetectionRuntimeEvent"}},
                    "report": {"$ref": "#/components/schemas/DetectionReport"},
                    "error": {"$ref": "#/components/schemas/CoreApiError"},
                },
            }),
        ),
        (
            "CoreApiError",
            json!({
                "type": "object",
                "description": "Stable error envelope of every REST failure.",
                "required": ["code", "message"],
                "properties": {
                    "code": {"type": "string", "description": "Stable machine-readable code, for example invalid_request, unauthorized, job_not_found, service_overloaded, rate_limited, rules_unavailable or detection_timeout."},
                    "message": {"type": "string"},
                },
            }),
        ),
        (
            "CoreRuntimeServiceHealth",
            json!({
                "type": "object",
                "required": ["maxInflightDetections", "maxRequestBodyBytes", "shutdownGraceSeconds", "targetDnsTimeoutSeconds", "rateLimit"],
                "properties": {
                    "maxInflightDetections": {"type": "integer"},
                    "maxRequestBodyBytes": {"type": "integer"},
                    "shutdownGraceSeconds": {"type": "integer"},
                    "targetDnsTimeoutSeconds": {"type": "integer"},
                    "rateLimit": {
                        "type": "object",
                        "description": "Effective per-IP detection limit of this instance. Only configuration is published; no per-client counter state is ever exposed.",
                        "required": ["perIpDetectRequestsPerMinute", "maxEntries", "windowSeconds"],
                        "properties": {
                            "perIpDetectRequestsPerMinute": {"type": "integer", "description": "Detect requests allowed per client IP per window; 0 disables the limit."},
                            "maxEntries": {"type": "integer", "description": "Hard cap on tracked client IPs; the least recently active entry is retired first."},
                            "windowSeconds": {"type": "integer", "description": "Length of the fixed counting window."},
                        },
                    },
                },
            }),
        ),
        (
            "CoreRuntimeEngineHealth",
            json!({
                "type": "object",
                "required": ["requestTimeoutMs", "maxRetries", "retryBackoffMs", "maxConcurrent", "quickTimeoutMs", "standardTimeoutMs", "fullTimeoutMs"],
                "properties": {
                    "requestTimeoutMs": {"type": "integer"},
                    "maxRetries": {"type": "integer"},
                    "retryBackoffMs": {"type": "integer"},
                    "maxConcurrent": {"type": "integer"},
                    "quickTimeoutMs": {"type": "integer"},
                    "standardTimeoutMs": {"type": "integer"},
                    "fullTimeoutMs": {"type": "integer"},
                },
            }),
        ),
        (
            "CoreRuntimeTransportHealth",
            json!({
                "type": "object",
                "required": ["maxResponseBytes", "maxStreamBytes", "maxStreamEvents"],
                "properties": {
                    "maxResponseBytes": {"type": "integer"},
                    "maxStreamBytes": {"type": "integer"},
                    "maxStreamEvents": {"type": "integer"},
                },
            }),
        ),
        (
            "CoreRuntimeRuleHealth",
            json!({
                "type": "object",
                "required": ["refreshIntervalSeconds", "requestTimeoutMs", "maxManifestBytes", "maxDocumentBytes"],
                "properties": {
                    "refreshIntervalSeconds": {"type": "integer"},
                    "requestTimeoutMs": {"type": "integer"},
                    "maxManifestBytes": {"type": "integer"},
                    "maxDocumentBytes": {"type": "integer"},
                },
            }),
        ),
        (
            "CoreRuntimeHealth",
            json!({
                "type": "object",
                "required": ["service", "engine", "transport", "rules"],
                "properties": {
                    "service": {"$ref": "#/components/schemas/CoreRuntimeServiceHealth"},
                    "engine": {"$ref": "#/components/schemas/CoreRuntimeEngineHealth"},
                    "transport": {"$ref": "#/components/schemas/CoreRuntimeTransportHealth"},
                    "rules": {"$ref": "#/components/schemas/CoreRuntimeRuleHealth"},
                },
            }),
        ),
        (
            "CoreRuleRuntimeHealth",
            json!({
                "type": "object",
                "required": ["status"],
                "properties": {
                    "status": {"type": "string", "enum": ["active", "unavailable"]},
                    "bundle": {"$ref": "#/components/schemas/RuleBundleProvenance"},
                },
            }),
        ),
        (
            "CoreServiceHealth",
            json!({
                "type": "object",
                "description": "Health document served by /health and /health/ready.",
                "required": ["status", "service", "serviceVersion", "core", "rules", "runtime", "transports"],
                "properties": {
                    "status": {"type": "string", "enum": ["ok", "degraded"]},
                    "service": {"type": "string"},
                    "serviceVersion": {"type": "string"},
                    "core": {"$ref": "#/components/schemas/CoreBuildInfo"},
                    "rules": {"$ref": "#/components/schemas/CoreRuleRuntimeHealth"},
                    "runtime": {"$ref": "#/components/schemas/CoreRuntimeHealth"},
                    "transports": {"type": "array", "items": {"type": "string"}},
                },
            }),
        ),
        (
            "ProbeInputOption",
            json!({
                "type": "object",
                "required": ["value", "label"],
                "properties": {
                    "value": {},
                    "label": {"type": "string"},
                    "description": {"type": "string"},
                },
            }),
        ),
        (
            "ProbeInputField",
            json!({
                "type": "object",
                "description": "One field of the detection request form.",
                "required": ["id", "jsonPointer", "label", "control", "required", "sensitive", "defaultValue"],
                "properties": {
                    "id": {"type": "string"},
                    "jsonPointer": {"type": "string"},
                    "label": {"type": "string"},
                    "description": {"type": "string"},
                    "control": {"type": "string"},
                    "required": {"type": "boolean"},
                    "sensitive": {"type": "boolean"},
                    "placeholder": {"type": "string"},
                    "defaultValue": {},
                    "options": {"type": "array", "items": {"$ref": "#/components/schemas/ProbeInputOption"}},
                },
            }),
        ),
        (
            "ProbeRequestManifest",
            json!({
                "type": "object",
                "required": ["submitLabel", "fields"],
                "properties": {
                    "submitLabel": {"type": "string"},
                    "fields": {"type": "array", "items": {"$ref": "#/components/schemas/ProbeInputField"}},
                },
            }),
        ),
        (
            "PresentationContract",
            json!({
                "type": "object",
                "required": ["schemaVersion", "supportedLayouts", "supportedFormats", "unknownHintFallback"],
                "properties": {
                    "schemaVersion": {"type": "integer"},
                    "supportedLayouts": {"type": "array", "items": {"type": "string"}},
                    "supportedFormats": {"type": "array", "items": {"type": "string"}},
                    "unknownHintFallback": {"type": "string"},
                },
            }),
        ),
        (
            "CoreUiManifest",
            json!({
                "type": "object",
                "description": "Self-describing UI manifest served by /v1/manifest and core.manifest.",
                "required": ["schemaVersion", "language", "request", "presentation"],
                "properties": {
                    "schemaVersion": {"type": "integer"},
                    "language": {"type": "string"},
                    "request": {"$ref": "#/components/schemas/ProbeRequestManifest"},
                    "presentation": {"$ref": "#/components/schemas/PresentationContract"},
                },
            }),
        ),
        (
            "JsonRpcRequest",
            json!({
                "type": "object",
                "required": ["jsonrpc", "id", "method"],
                "properties": {
                    "jsonrpc": {"type": "string", "const": "2.0"},
                    "id": {},
                    "method": {"type": "string", "enum": ["core.info", "core.manifest", "core.detect"]},
                    "params": {},
                },
            }),
        ),
        (
            "JsonRpcError",
            json!({
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": {"type": "integer"},
                    "message": {"type": "string"},
                    "data": {},
                },
            }),
        ),
        (
            "JsonRpcResponse",
            json!({
                "type": "object",
                "required": ["jsonrpc", "id"],
                "properties": {
                    "jsonrpc": {"type": "string", "const": "2.0"},
                    "id": {},
                    "result": {},
                    "error": {"$ref": "#/components/schemas/JsonRpcError"},
                },
            }),
        ),
        (
            "OpenApiDocument",
            json!({
                "type": "object",
                "description": "OpenAPI 3.1 document describing this service.",
                "additionalProperties": true,
            }),
        ),
    ];
    Value::Object(
        entries
            .into_iter()
            .map(|(name, schema)| (name.to_owned(), schema))
            .collect(),
    )
}

async fn request_context(request: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let request_id = Ulid::new().to_string();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = Instant::now();
    let mut response = next.run(request).await;
    let status = response.status();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    tracing::info!(
        request_id = %request_id,
        %method,
        %path,
        status = status.as_u16(),
        latency_ms = started.elapsed().as_millis() as u64,
        "request completed"
    );
    response
}

fn env_bool(
    env_value: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> anyhow::Result<Option<bool>> {
    let Some(value) = env_value(name) else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => anyhow::bail!("{name} must be a boolean"),
    }
}

fn env_u64(
    env_value: &impl Fn(&str) -> Option<String>,
    name: &str,
    fallback: u64,
) -> anyhow::Result<u64> {
    env_value(name)
        .map(|value| {
            value
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("{name} must be an unsigned integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(fallback))
}

fn env_usize(
    env_value: &impl Fn(&str) -> Option<String>,
    name: &str,
    fallback: usize,
) -> anyhow::Result<usize> {
    env_value(name)
        .map(|value| {
            value
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("{name} must be an unsigned integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(fallback))
}

fn parse_allowed_origins(value: &str) -> anyhow::Result<Vec<String>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(|origin| {
            let url = Url::parse(origin)?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                anyhow::bail!("core allowed origins must be http(s) origins without a path");
            }
            HeaderValue::from_str(origin)?;
            Ok(origin.trim_end_matches('/').to_owned())
        })
        .collect()
}

fn cors_layer(origins: &[String]) -> CorsLayer {
    let origins = origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin).expect("allowed origins are validated by configuration")
        })
        .collect::<Vec<_>>();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .expose_headers([HeaderName::from_static("x-request-id")])
}

async fn health_document(state: &AppState) -> Value {
    let rule_bundle = match &state.rule_loader {
        Some(loader) => loader.resolve().await,
        None => state.static_rule_bundle.clone(),
    };
    let rules_available = rule_bundle.is_some();
    let health = CoreServiceHealth {
        status: if rules_available { "ok" } else { "degraded" }.into(),
        service: env!("CARGO_PKG_NAME").into(),
        service_version: env!("CARGO_PKG_VERSION").into(),
        core: core_build_info(),
        rules: CoreRuleRuntimeHealth {
            status: if rules_available {
                "active"
            } else {
                "unavailable"
            }
            .into(),
            bundle: rule_bundle.map(|bundle| bundle.provenance.clone()),
        },
        runtime: CoreRuntimeHealth {
            service: CoreRuntimeServiceHealth {
                max_inflight_detections: state.max_inflight_detections,
                max_request_body_bytes: state.max_request_body_bytes,
                shutdown_grace_seconds: state.shutdown_grace_period.as_secs(),
                target_dns_timeout_seconds: state.target_dns_timeout.as_secs(),
            },
            engine: CoreRuntimeEngineHealth {
                request_timeout_ms: duration_millis(state.engine_config.request_timeout),
                max_retries: state.engine_config.max_retries,
                retry_backoff_ms: duration_millis(state.engine_config.retry_backoff),
                max_concurrent: state.engine_config.max_concurrent,
                quick_timeout_ms: duration_millis(state.engine_config.quick_timeout),
                standard_timeout_ms: duration_millis(state.engine_config.standard_timeout),
                full_timeout_ms: duration_millis(state.engine_config.full_timeout),
            },
            transport: CoreRuntimeTransportHealth {
                max_response_bytes: state.live_transport.config().max_response_bytes,
                max_stream_bytes: state.live_transport.config().max_stream_bytes,
                max_stream_events: state.live_transport.config().max_stream_events,
            },
            rules: CoreRuntimeRuleHealth {
                refresh_interval_seconds: state.rule_refresh_interval.as_secs(),
                request_timeout_ms: state
                    .engine_config
                    .rule_repository
                    .as_ref()
                    .map_or(0, |repository| duration_millis(repository.request_timeout)),
                max_manifest_bytes: state
                    .engine_config
                    .rule_repository
                    .as_ref()
                    .map_or(0, |repository| repository.max_manifest_bytes),
                max_document_bytes: state
                    .engine_config
                    .rule_repository
                    .as_ref()
                    .map_or(0, |repository| repository.max_document_bytes),
            },
        },
        transports: vec!["api".into(), "rpc".into()],
    };
    let mut document = serde_json::to_value(health).expect("service health is serializable");
    // `CoreRuntimeServiceHealth` is part of the shared wire contract, so the
    // service-owned rate-limit limits are added to the runtime section here
    // instead of widening that struct. Only effective configuration values are
    // published; no per-IP counter state is ever exposed.
    if let Some(service) = document
        .get_mut("runtime")
        .and_then(|runtime| runtime.get_mut("service"))
        .and_then(Value::as_object_mut)
    {
        service.insert(
            "rateLimit".into(),
            json!({
                "perIpDetectRequestsPerMinute": state.rate_limiter.requests_per_window(),
                "maxEntries": state.rate_limiter.max_entries(),
                "windowSeconds": state.rate_limiter.window().as_secs(),
            }),
        );
    }
    document
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(health_document(&state).await)
}

async fn liveness() -> Json<CoreBuildInfo> {
    Json(core_build_info())
}

async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let health = health_document(&state).await;
    let status = if health["status"] == "ok" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(health))
}

/// Serves the machine-readable contract. Like the health endpoints it is
/// intentionally readable without authorization.
async fn openapi_json() -> Json<Value> {
    Json(openapi_document())
}

async fn core_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CoreBuildInfo>, ServiceError> {
    authorize(&headers, state.auth_token.as_deref(), state.require_auth)?;
    Ok(Json(core_build_info()))
}

async fn core_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CoreUiManifest>, ServiceError> {
    authorize(&headers, state.auth_token.as_deref(), state.require_auth)?;
    let sections = resolve_rule_bundle(&state)
        .await
        .and_then(|bundle| bundle.rules.sections.clone());
    Ok(Json(core_ui_manifest(
        state.demo_targets.first().map(String::as_str),
        sections.as_ref(),
    )))
}

async fn resolve_rule_bundle(state: &AppState) -> Option<Arc<CoreRuleBundle>> {
    match &state.rule_loader {
        Some(loader) => loader.resolve().await,
        None => state.static_rule_bundle.clone(),
    }
}

async fn detect(
    State(state): State<AppState>,
    peer: PeerAddr,
    headers: HeaderMap,
    Json(request): Json<ProbeRequest>,
) -> Result<Json<DetectionReport>, ServiceError> {
    authorize(&headers, state.auth_token.as_deref(), state.require_auth)?;
    state.rate_limiter.check_peer(peer.0)?;
    execute_detection(&state, request).await.map(Json)
}

async fn create_detection_job(
    State(state): State<AppState>,
    peer: PeerAddr,
    headers: HeaderMap,
    Json(request): Json<ProbeRequest>,
) -> Result<(StatusCode, Json<DetectionJobSnapshot>), ServiceError> {
    authorize(&headers, state.auth_token.as_deref(), state.require_auth)?;
    state.rate_limiter.check_peer(peer.0)?;
    let job_id = Ulid::new().to_string();
    let snapshot = DetectionJobSnapshot {
        id: job_id.clone(),
        status: DetectionJobStatus::Queued,
        created_at: Utc::now(),
        model: request.model.trim().to_owned(),
        protocol: request.protocol,
        mode: request.mode,
        events: Vec::new(),
        report: None,
        error: None,
    };
    insert_job(&state.jobs, snapshot.clone());
    let jobs = Arc::clone(&state.jobs);
    tokio::spawn(async move {
        let observer = Arc::new(JobRuntimeObserver {
            job_id: job_id.clone(),
            started: Instant::now(),
            jobs: Arc::clone(&jobs),
        });
        set_job_status(&jobs, &job_id, DetectionJobStatus::Running, None, None);
        observer.emit(
            "service",
            "job_started",
            RuntimeEventStatus::Running,
            "Detection job started",
            BTreeMap::new(),
        );
        match execute_detection_observed(&state, request, Some(observer.clone())).await {
            Ok(report) => {
                observer.emit(
                    "service",
                    "job_completed",
                    RuntimeEventStatus::Success,
                    "Detection job completed",
                    BTreeMap::from([
                        ("reportId".into(), json!(report.id)),
                        ("verdict".into(), json!(report.verdict)),
                    ]),
                );
                set_job_status(
                    &jobs,
                    &job_id,
                    DetectionJobStatus::Completed,
                    Some(report),
                    None,
                );
            }
            Err(error) => {
                observer.emit(
                    "service",
                    "job_failed",
                    RuntimeEventStatus::Error,
                    "Detection job failed",
                    BTreeMap::from([(String::from("code"), json!(error.code()))]),
                );
                set_job_status(
                    &jobs,
                    &job_id,
                    DetectionJobStatus::Failed,
                    None,
                    Some(CoreApiError {
                        code: error.code().into(),
                        message: error.public_message(),
                    }),
                );
            }
        }
    });
    Ok((StatusCode::ACCEPTED, Json(snapshot)))
}

async fn get_detection_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> Result<Json<DetectionJobSnapshot>, ServiceError> {
    authorize(&headers, state.auth_token.as_deref(), state.require_auth)?;
    let snapshot = state
        .jobs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&job_id)
        .cloned()
        .ok_or(ServiceError::JobNotFound)?;
    Ok(Json(snapshot))
}

struct JobRuntimeObserver {
    job_id: String,
    started: Instant,
    jobs: Arc<StdMutex<BTreeMap<String, DetectionJobSnapshot>>>,
}

impl RuntimeObserver for JobRuntimeObserver {
    fn emit(
        &self,
        stage: &str,
        event: &str,
        status: RuntimeEventStatus,
        message: &str,
        details: BTreeMap<String, serde_json::Value>,
    ) {
        let mut jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(snapshot) = jobs.get_mut(&self.job_id) else {
            return;
        };
        let sequence = snapshot.events.last().map_or(1, |event| event.sequence + 1);
        snapshot.events.push(DetectionRuntimeEvent {
            sequence,
            elapsed_ms: self.started.elapsed().as_millis() as u64,
            stage: stage.into(),
            event: event.into(),
            status,
            message: message.into(),
            details,
        });
        if snapshot.events.len() > 2048 {
            let excess = snapshot.events.len() - 2048;
            snapshot.events.drain(..excess);
        }
    }
}

fn insert_job(
    jobs: &Arc<StdMutex<BTreeMap<String, DetectionJobSnapshot>>>,
    snapshot: DetectionJobSnapshot,
) {
    let mut jobs = jobs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while jobs.len() >= MAX_RETAINED_DETECTION_JOBS {
        let Some(oldest) = jobs.keys().next().cloned() else {
            break;
        };
        jobs.remove(&oldest);
    }
    jobs.insert(snapshot.id.clone(), snapshot);
}

fn set_job_status(
    jobs: &Arc<StdMutex<BTreeMap<String, DetectionJobSnapshot>>>,
    job_id: &str,
    status: DetectionJobStatus,
    report: Option<DetectionReport>,
    error: Option<CoreApiError>,
) {
    let mut jobs = jobs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(snapshot) = jobs.get_mut(job_id) {
        snapshot.status = status;
        snapshot.report = report;
        snapshot.error = error;
    }
}

async fn rpc(
    State(state): State<AppState>,
    peer: PeerAddr,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Result<Json<JsonRpcResponse>, ServiceError> {
    authorize(&headers, state.auth_token.as_deref(), state.require_auth)?;
    let id = request.id;
    if request.jsonrpc != JSON_RPC_VERSION {
        return Ok(Json(JsonRpcResponse::error(
            id,
            -32600,
            "invalid JSON-RPC version",
            None,
        )));
    }

    let response = match request.method.as_str() {
        RPC_METHOD_CORE_INFO => JsonRpcResponse::success(
            id,
            serde_json::to_value(core_build_info()).expect("core build info is serializable"),
        ),
        RPC_METHOD_CORE_MANIFEST => {
            let sections = resolve_rule_bundle(&state)
                .await
                .and_then(|bundle| bundle.rules.sections.clone());
            JsonRpcResponse::success(
                id,
                serde_json::to_value(core_ui_manifest(
                    state.demo_targets.first().map(String::as_str),
                    sections.as_ref(),
                ))
                .expect("core UI manifest is serializable"),
            )
        }
        RPC_METHOD_CORE_DETECT => {
            // Only core.detect is metered. core.info and core.manifest are
            // read-only metadata, so they stay free of the per-IP limit.
            match state.rate_limiter.check_peer(peer.0) {
                Ok(()) => match serde_json::from_value::<ProbeRequest>(request.params) {
                    Ok(request) => match execute_detection(&state, request).await {
                        Ok(report) => JsonRpcResponse::success(
                            id,
                            serde_json::to_value(report).expect("detection report is serializable"),
                        ),
                        Err(error) => JsonRpcResponse::error(
                            id,
                            -32000,
                            error.public_message(),
                            Some(json!({"code": error.code()})),
                        ),
                    },
                    Err(_) => {
                        JsonRpcResponse::error(id, -32602, "invalid core.detect parameters", None)
                    }
                },
                // Rate limiting is an HTTP-level condition: the caller gets the
                // same 429 and CoreApiError envelope as the REST routes.
                Err(error) => return Err(error),
            }
        }
        _ => JsonRpcResponse::error(id, -32601, "method not found", None),
    };
    Ok(Json(response))
}

async fn execute_detection(
    state: &AppState,
    request: ProbeRequest,
) -> Result<DetectionReport, ServiceError> {
    execute_detection_observed(state, request, None).await
}

async fn execute_detection_observed(
    state: &AppState,
    mut request: ProbeRequest,
    observer: Option<Arc<dyn RuntimeObserver>>,
) -> Result<DetectionReport, ServiceError> {
    let _slot = state
        .detection_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ServiceError::Overloaded)?;
    request.base_url = request.base_url.trim().trim_end_matches('/').to_owned();
    request.model = request.model.trim().to_owned();
    request.api_key = request.api_key.trim().to_owned();
    if request.model.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "model must not be empty".into(),
        ));
    }
    if request.api_key.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "API key must not be empty".into(),
        ));
    }

    let demo = is_demo_target(&request.base_url, &state.demo_targets);
    let pinned_transport = if demo {
        None
    } else {
        validate_target_resolution(
            &request.base_url,
            state.allow_private_targets,
            state.target_dns_timeout,
        )
        .await?
        .map(|(host, addresses)| {
            HttpTransport::with_resolved_target(state.live_transport.config(), &host, &addresses)
                .map_err(|_| ServiceError::TargetResolutionFailed)
        })
        .transpose()?
    };
    let transport: &dyn ProbeTransport = if demo {
        &DemoTransport
    } else {
        pinned_transport
            .as_ref()
            .map_or(&state.live_transport as &dyn ProbeTransport, |transport| {
                transport
            })
    };
    let rule_bundle = match &state.rule_loader {
        Some(loader) => loader.resolve().await,
        None => state.static_rule_bundle.clone(),
    };
    let engine = Engine::new(EngineConfig {
        rule_bundle,
        ..state.engine_config.clone()
    });
    engine
        .detect_with_observer(request, transport, observer)
        .await
        .map_err(ServiceError::Core)
}

#[cfg(not(test))]
fn default_test_rule_bundle() -> Option<Arc<CoreRuleBundle>> {
    None
}

#[cfg(test)]
fn default_test_rule_bundle() -> Option<Arc<CoreRuleBundle>> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../SanBiao/rules/the-standard/stable.json");
    Some(Arc::new(
        CoreRuleBundle::from_document(&std::fs::read(path).unwrap(), None)
            .expect("shared Knowledge rule fixture"),
    ))
}

fn authorize(
    headers: &HeaderMap,
    expected: Option<&str>,
    required: bool,
) -> Result<(), ServiceError> {
    let Some(expected) = expected else {
        if required {
            return Err(ServiceError::Unauthorized);
        }
        return Ok(());
    };
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if provided == Some(expected) {
        Ok(())
    } else {
        Err(ServiceError::Unauthorized)
    }
}

fn is_demo_target(target: &str, demo_targets: &[String]) -> bool {
    Url::parse(target).is_ok_and(|url| {
        let origin = url.origin().ascii_serialization();
        demo_targets.iter().any(|target| target == &origin)
    })
}

#[cfg(not(test))]
fn default_test_demo_targets() -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
fn default_test_demo_targets() -> Vec<String> {
    vec!["https://demo.example.com".into()]
}

fn validate_target(target: &str, allow_private: bool) -> Result<(), ServiceError> {
    let url = Url::parse(target)
        .map_err(|_| ServiceError::InvalidRequest("target URL is invalid".into()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ServiceError::InvalidRequest(
            "only http and https targets are accepted".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ServiceError::InvalidRequest("target host is required".into()))?;
    if allow_private {
        return Ok(());
    }
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
        return Err(ServiceError::InvalidRequest(
            "private and loopback targets are disabled".into(),
        ));
    }
    if host
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok_and(is_restricted)
    {
        return Err(ServiceError::InvalidRequest(
            "private and loopback targets are disabled".into(),
        ));
    }
    Ok(())
}

async fn validate_target_resolution(
    target: &str,
    allow_private: bool,
    dns_timeout: Duration,
) -> Result<Option<(String, Vec<SocketAddr>)>, ServiceError> {
    validate_target(target, allow_private)?;
    if allow_private {
        return Ok(None);
    }
    let url = Url::parse(target)
        .map_err(|_| ServiceError::InvalidRequest("target URL is invalid".into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ServiceError::InvalidRequest("target host is required".into()))?;
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return Ok(None);
    }
    let port = url.port_or_known_default().ok_or_else(|| {
        ServiceError::InvalidRequest("target URL does not have a known port".into())
    })?;
    let addresses = tokio::time::timeout(dns_timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| ServiceError::TargetResolutionTimeout)?
        .map_err(|_| ServiceError::TargetResolutionFailed)?
        .collect::<std::collections::BTreeSet<_>>();
    let address_ips = addresses
        .iter()
        .map(|address| address.ip())
        .collect::<std::collections::BTreeSet<_>>();
    if addresses.is_empty() {
        return Err(ServiceError::TargetResolutionFailed);
    }
    if address_ips.into_iter().any(is_restricted) {
        return Err(ServiceError::RestrictedTargetResolution);
    }
    Ok(Some((host.to_owned(), addresses.into_iter().collect())))
}

fn is_restricted(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_loopback()
                || address.is_unspecified()
                || address.is_private()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
                || octets[0] >= 240
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] & 0xffc0) == 0xfec0
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|address| is_restricted(IpAddr::V4(address)))
        }
    }
}

#[derive(Debug)]
enum ServiceError {
    InvalidRequest(String),
    Unauthorized,
    Overloaded,
    TargetResolutionTimeout,
    TargetResolutionFailed,
    RestrictedTargetResolution,
    JobNotFound,
    RateLimited { retry_after_seconds: u64 },
    Core(CoreError),
}

impl ServiceError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Overloaded => "service_overloaded",
            Self::TargetResolutionTimeout => "target_resolution_timeout",
            Self::TargetResolutionFailed => "target_resolution_failed",
            Self::RestrictedTargetResolution => "restricted_target_resolution",
            Self::JobNotFound => "job_not_found",
            Self::RateLimited { .. } => "rate_limited",
            Self::Core(CoreError::InvalidEndpoint(_)) => "invalid_request",
            Self::Core(CoreError::InvalidSections(_)) => "invalid_request",
            Self::Core(CoreError::Transport(_)) => "upstream_unavailable",
            Self::Core(CoreError::Parse(_)) => "upstream_invalid_response",
            Self::Core(CoreError::NoObservations) => "no_observations",
            Self::Core(CoreError::OverallTimeout(_)) => "detection_timeout",
            Self::Core(CoreError::RulesUnavailable) => "rules_unavailable",
        }
    }

    fn public_message(&self) -> String {
        match self {
            Self::InvalidRequest(message) => message.clone(),
            Self::Unauthorized => "missing or invalid service authorization".into(),
            Self::Overloaded => "detection capacity is currently full; retry later".into(),
            Self::TargetResolutionTimeout => {
                "target hostname resolution exceeded the configured timeout".into()
            }
            Self::TargetResolutionFailed => "target hostname could not be resolved".into(),
            Self::RestrictedTargetResolution => {
                "target hostname resolves to a restricted network address".into()
            }
            Self::JobNotFound => "detection job was not found or has expired".into(),
            Self::RateLimited {
                retry_after_seconds,
            } => format!(
                "per-IP detection rate limit exceeded; retry in {retry_after_seconds} seconds"
            ),
            Self::Core(CoreError::InvalidEndpoint(message)) => message.clone(),
            Self::Core(CoreError::InvalidSections(message)) => message.clone(),
            Self::Core(CoreError::Transport(_)) => "target API request failed".into(),
            Self::Core(CoreError::Parse(_)) => "target API returned an invalid response".into(),
            Self::Core(CoreError::NoObservations) => {
                "the detection engine produced no observations".into()
            }
            Self::Core(CoreError::OverallTimeout(_)) => {
                "the detection exceeded its configured overall timeout".into()
            }
            Self::Core(CoreError::RulesUnavailable) => {
                "no validated Core rule bundle is currently available".into()
            }
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Overloaded | Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::TargetResolutionTimeout | Self::TargetResolutionFailed => StatusCode::BAD_GATEWAY,
            Self::RestrictedTargetResolution => StatusCode::BAD_REQUEST,
            Self::JobNotFound => StatusCode::NOT_FOUND,
            Self::InvalidRequest(_)
            | Self::Core(CoreError::InvalidEndpoint(_))
            | Self::Core(CoreError::InvalidSections(_)) => StatusCode::BAD_REQUEST,
            Self::Core(CoreError::RulesUnavailable) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Core(CoreError::OverallTimeout(_)) => StatusCode::GATEWAY_TIMEOUT,
            Self::Core(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = CoreApiError {
            code: self.code().into(),
            message: self.public_message(),
        };
        match &self {
            ServiceError::Overloaded => (
                status,
                [(header::RETRY_AFTER, HeaderValue::from_static("1"))],
                Json(body),
            )
                .into_response(),
            ServiceError::RateLimited {
                retry_after_seconds,
            } => {
                let retry_after = HeaderValue::from_str(&(*retry_after_seconds).max(1).to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("60"));
                (status, [(header::RETRY_AFTER, retry_after)], Json(body)).into_response()
            }
            _ => (status, Json(body)).into_response(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{
        AppState, CoreServiceConfig, FileConfig, PeerAddr, PerIpRateLimiter, RATE_LIMIT_WINDOW,
        RateLimitDecision, RuleBundleLoader, SERVICE_ROUTES, ServiceError, build_app,
        execute_detection, is_restricted, openapi_document, parse_allowed_origins, rpc,
        validate_target, validate_target_resolution,
    };
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::{ConnectInfo, State},
        http::{HeaderMap, Request, StatusCode, header},
        response::IntoResponse,
        routing::get,
    };
    use serde_json::{Value, json};
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use the_standard::{
        CoreApiError, CoreError, CoreUiManifest, DetectionJobSnapshot, DetectionJobStatus,
        DetectionReport, JSON_RPC_VERSION, JsonRpcRequest, JsonRpcResponse,
        PRESENTATION_SCHEMA_VERSION, REPORT_SCHEMA_VERSION, RPC_METHOD_CORE_DETECT,
        RPC_METHOD_CORE_INFO, RPC_METHOD_CORE_MANIFEST, UI_MANIFEST_SCHEMA_VERSION,
        core_build_info,
    };
    use tower::ServiceExt;
    use ulid::Ulid;

    /// Core version reported by the library itself, so no test has to hardcode
    /// a version string that a concurrent release bump would invalidate.
    fn expected_core_version() -> String {
        core_build_info().version
    }

    /// Rule-repository manifest of the SanBiao repository, read at test time so
    /// its release can move independently of the service version.
    fn sanbiao_manifest() -> Value {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../SanBiao");
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap())
            .expect("SanBiao manifest is valid JSON")
    }

    async fn repository_config() -> the_standard::RuleRepositoryConfig {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../SanBiao");
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
        let rules: Value = serde_json::from_slice(
            &std::fs::read(root.join("rules/the-standard/stable.json")).unwrap(),
        )
        .unwrap();
        let app = Router::new()
            .route(
                "/manifest.json",
                get(move || {
                    let manifest = manifest.clone();
                    async move { Json(manifest) }
                }),
            )
            .route(
                "/rules/the-standard/stable.json",
                get(move || {
                    let rules = rules.clone();
                    async move { Json(rules) }
                }),
            );
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        the_standard::RuleRepositoryConfig::new(
            &format!("http://{address}/manifest.json"),
            None,
            false,
        )
        .unwrap()
    }

    fn detection_request() -> Value {
        json!({
            "baseUrl": "https://demo.example.com",
            "apiKey": "sk-test-secret-value",
            "model": "claude-sonnet-4-6",
            "protocol": "anthropic",
            "mode": "quick"
        })
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn async_detection_job_reports_redacted_runtime_events() {
        let app = build_app(CoreServiceConfig::default());
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/detect/jobs")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&detection_request()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let created: DetectionJobSnapshot =
            serde_json::from_value(response_json(response).await).unwrap();
        assert_eq!(created.status, DetectionJobStatus::Queued);
        assert!(created.id.parse::<Ulid>().is_ok());

        let mut final_snapshot = created;
        for _ in 0..100 {
            let response = app
                .clone()
                .oneshot(
                    Request::get(format!("/v1/detect/jobs/{}", final_snapshot.id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            final_snapshot = serde_json::from_value(response_json(response).await).unwrap();
            if matches!(
                final_snapshot.status,
                DetectionJobStatus::Completed | DetectionJobStatus::Failed
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(final_snapshot.status, DetectionJobStatus::Completed);
        assert!(final_snapshot.report.is_some());
        assert!(
            final_snapshot
                .events
                .iter()
                .any(|event| event.event == "probe_attempt_started")
        );
        assert!(
            final_snapshot
                .events
                .iter()
                .any(|event| event.event == "report_build_completed")
        );
        let encoded = serde_json::to_string(&final_snapshot).unwrap();
        assert!(!encoded.contains("sk-test-secret-value"));
        assert!(!encoded.to_ascii_lowercase().contains("authorization"));
    }

    #[tokio::test]
    async fn missing_detection_job_is_a_stable_not_found_error() {
        let response = build_app(CoreServiceConfig::default())
            .oneshot(
                Request::get("/v1/detect/jobs/01J00000000000000000000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response_json(response).await;
        assert_eq!(body["code"], "job_not_found");
    }

    #[test]
    fn blocks_private_targets_by_default() {
        assert!(validate_target("http://127.0.0.1:9000", false).is_err());
        assert!(validate_target("https://api.example.com", false).is_ok());
    }

    #[test]
    fn rejects_every_non_public_literal_address_class() {
        for target in [
            "http://100.64.0.1",
            "http://192.0.2.1",
            "http://198.18.0.1",
            "http://224.0.0.1",
            "http://[::1]",
            "http://[fd00::1]",
            "http://[fe80::1]",
            "http://[2001:db8::1]",
            "http://[::ffff:127.0.0.1]",
        ] {
            assert!(
                validate_target(target, false).is_err(),
                "{target} must be rejected"
            );
        }
        assert!(validate_target("http://1.1.1.1", false).is_ok());
        assert!(validate_target("http://[2606:4700:4700::1111]", false).is_ok());
    }

    #[test]
    fn restricted_address_policy_covers_ipv4_and_ipv6_special_ranges() {
        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "10.0.0.1".parse().unwrap(),
            "169.254.169.254".parse().unwrap(),
            "100.64.0.1".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            "198.18.0.1".parse().unwrap(),
            "224.0.0.1".parse().unwrap(),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "fd00::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
        ] {
            assert!(is_restricted(address), "{address} must be restricted");
        }
        assert!(!is_restricted("1.1.1.1".parse().unwrap()));
        assert!(!is_restricted("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn explicit_private_target_mode_bypasses_resolution_policy() {
        assert!(
            validate_target_resolution("http://localhost:8181", false, Duration::from_secs(1))
                .await
                .is_err()
        );
        assert_eq!(
            validate_target_resolution("http://localhost:8181", true, Duration::from_secs(1))
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn loopback_hostname_resolution_is_rejected_before_core_execution() {
        let error =
            validate_target_resolution("http://localhost:8181", false, Duration::from_secs(1))
                .await
                .unwrap_err();
        assert_eq!(error.code(), "invalid_request");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn detection_timeout_uses_gateway_timeout_semantics() {
        assert_eq!(
            ServiceError::Core(CoreError::OverallTimeout(Duration::from_secs(1))).status(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            ServiceError::Core(CoreError::Transport("upstream".into())).status(),
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn file_configuration_resolves_all_runtime_limits() {
        let file: FileConfig = toml::from_str(
            r#"
                [service]
                host = "127.0.0.1"
                port = 8181
                require_auth = false
                allow_private_targets = false
                allowed_origins = ["https://console.example"]
                demo_targets = []
                target_dns_timeout_seconds = 6
                per_ip_detect_requests_per_minute = 30
                rate_limit_max_entries = 512

                [engine]
                request_timeout_seconds = 20
                max_retries = 2
                retry_backoff_milliseconds = 250
                max_concurrent = 6
                quick_timeout_seconds = 45
                standard_timeout_seconds = 90
                full_timeout_seconds = 150

                [transport]
                max_response_bytes = 6291456
                max_stream_bytes = 8388608
                max_stream_events = 20000

                [rules]
                manifest_url = "https://rules.example/manifest.json"
                source_revision = "0123456789abcdef0123456789abcdef01234567"
                allow_insecure_http = false
                refresh_seconds = 600
                request_timeout_seconds = 8
                max_manifest_bytes = 524288
                max_document_bytes = 2097152
            "#,
        )
        .unwrap();
        let config = CoreServiceConfig::resolve(file, |_| None).unwrap();
        assert_eq!(config.port, 8181);
        assert_eq!(
            config.engine_config.request_timeout,
            Duration::from_secs(20)
        );
        assert_eq!(config.engine_config.max_retries, 2);
        assert_eq!(
            config.engine_config.retry_backoff,
            Duration::from_millis(250)
        );
        assert_eq!(config.engine_config.max_concurrent, 6);
        assert_eq!(config.engine_config.full_timeout, Duration::from_secs(150));
        assert_eq!(config.transport_config.max_response_bytes, 6 * 1024 * 1024);
        assert_eq!(config.transport_config.max_stream_bytes, 8 * 1024 * 1024);
        assert_eq!(config.transport_config.max_stream_events, 20_000);
        assert_eq!(config.target_dns_timeout, Duration::from_secs(6));
        assert_eq!(config.per_ip_detect_requests_per_minute, 30);
        assert_eq!(config.rate_limit_max_entries, 512);
        let repository = config.rule_repository.unwrap();
        assert_eq!(repository.request_timeout, Duration::from_secs(8));
        assert_eq!(repository.max_manifest_bytes, 512 * 1024);
        assert_eq!(repository.max_document_bytes, 2 * 1024 * 1024);
        assert_eq!(config.rule_refresh_interval, Duration::from_secs(600));
    }

    #[test]
    fn explicit_configuration_files_are_read_from_disk() {
        let directory = std::env::temp_dir().join(format!(
            "the-standard-service-explicit-config-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("the-standard.toml");
        // The invalid manifest URL can only fail after the file was parsed, so
        // it proves the explicit path was read instead of the built-in default.
        std::fs::write(&path, "[rules]\nmanifest_url = \"not-a-url\"\n").unwrap();
        let error = CoreServiceConfig::load_from_file(&path).unwrap_err();
        assert!(error.to_string().contains("rule manifest URL"), "{error}");
        std::fs::write(&path, "[service]\nport = 8199\n").unwrap();
        assert!(CoreServiceConfig::load_from_file(&path).is_ok());
        // Unlike `load`, an explicit path must exist.
        assert!(CoreServiceConfig::load_from_file(&directory.join("absent.toml")).is_err());
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn service_resilience_defaults_are_applied_to_partial_toml() {
        let file: FileConfig = toml::from_str(
            r#"
                [service]
                host = "127.0.0.1"
                port = 8181
                require_auth = false
                allow_private_targets = false
                allowed_origins = ["https://console.example"]
                demo_targets = []
                [rules]
                manifest_url = "https://rules.example/manifest.json"
                allow_insecure_http = false
                refresh_seconds = 300
            "#,
        )
        .unwrap();
        assert_eq!(file.service.max_inflight_detections, 8);
        assert_eq!(file.service.max_request_body_bytes, 2 * 1024 * 1024);
        assert_eq!(file.service.shutdown_grace_seconds, 30);
        assert_eq!(file.service.target_dns_timeout_seconds, 5);
        assert_eq!(file.service.per_ip_detect_requests_per_minute, 0);
        assert_eq!(file.service.rate_limit_max_entries, 4096);
        assert_eq!(file.transport.max_response_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn environment_values_override_file_runtime_limits() {
        let values = std::collections::BTreeMap::from([
            ("THE_STANDARD_ENGINE_REQUEST_TIMEOUT_SECONDS", "12"),
            ("THE_STANDARD_ENGINE_MAX_RETRIES", "0"),
            ("THE_STANDARD_ENGINE_RETRY_BACKOFF_MILLISECONDS", "0"),
            ("THE_STANDARD_ENGINE_MAX_CONCURRENT", "9"),
            ("THE_STANDARD_ENGINE_QUICK_TIMEOUT_SECONDS", "30"),
            ("THE_STANDARD_ENGINE_STANDARD_TIMEOUT_SECONDS", "60"),
            ("THE_STANDARD_ENGINE_FULL_TIMEOUT_SECONDS", "120"),
            ("THE_STANDARD_TRANSPORT_MAX_STREAM_BYTES", "16777216"),
            ("THE_STANDARD_TRANSPORT_MAX_STREAM_EVENTS", "30000"),
            ("THE_STANDARD_TRANSPORT_MAX_RESPONSE_BYTES", "8388608"),
            ("THE_STANDARD_RULE_REQUEST_TIMEOUT_SECONDS", "9"),
            ("THE_STANDARD_RULE_MAX_MANIFEST_BYTES", "1048576"),
            ("THE_STANDARD_RULE_MAX_DOCUMENT_BYTES", "4194304"),
            ("THE_STANDARD_RULE_REFRESH_SECONDS", "900"),
            ("THE_STANDARD_SERVICE_MAX_INFLIGHT_DETECTIONS", "12"),
            ("THE_STANDARD_SERVICE_MAX_REQUEST_BODY_BYTES", "4194304"),
            ("THE_STANDARD_SERVICE_SHUTDOWN_GRACE_SECONDS", "45"),
            ("THE_STANDARD_SERVICE_TARGET_DNS_TIMEOUT_SECONDS", "7"),
            (
                "THE_STANDARD_SERVICE_PER_IP_DETECT_REQUESTS_PER_MINUTE",
                "40",
            ),
            ("THE_STANDARD_SERVICE_RATE_LIMIT_MAX_ENTRIES", "256"),
        ]);
        let config = CoreServiceConfig::resolve(FileConfig::default(), |name| {
            values.get(name).map(|value| (*value).to_owned())
        })
        .unwrap();
        assert_eq!(
            config.engine_config.request_timeout,
            Duration::from_secs(12)
        );
        assert_eq!(config.engine_config.max_retries, 0);
        assert_eq!(config.engine_config.max_concurrent, 9);
        assert_eq!(config.transport_config.max_response_bytes, 8 * 1024 * 1024);
        assert_eq!(config.transport_config.max_stream_bytes, 16 * 1024 * 1024);
        assert_eq!(config.transport_config.max_stream_events, 30_000);
        assert_eq!(config.max_inflight_detections, 12);
        assert_eq!(config.max_request_body_bytes, 4 * 1024 * 1024);
        assert_eq!(config.shutdown_grace_period, Duration::from_secs(45));
        assert_eq!(config.target_dns_timeout, Duration::from_secs(7));
        assert_eq!(config.per_ip_detect_requests_per_minute, 40);
        assert_eq!(config.rate_limit_max_entries, 256);
        let repository = config.rule_repository.unwrap();
        assert_eq!(repository.request_timeout, Duration::from_secs(9));
        assert_eq!(repository.max_document_bytes, 4 * 1024 * 1024);
        assert_eq!(config.rule_refresh_interval, Duration::from_secs(900));
    }

    #[test]
    fn invalid_runtime_configuration_fails_instead_of_being_clamped() {
        let values = std::collections::BTreeMap::from([("THE_STANDARD_RULE_REFRESH_SECONDS", "1")]);
        let error = CoreServiceConfig::resolve(FileConfig::default(), |name| {
            values.get(name).map(|value| (*value).to_owned())
        })
        .unwrap_err();
        assert!(error.to_string().contains("between 30 and 86400"));

        let values =
            std::collections::BTreeMap::from([("THE_STANDARD_ENGINE_MAX_CONCURRENT", "0")]);
        let error = CoreServiceConfig::resolve(FileConfig::default(), |name| {
            values.get(name).map(|value| (*value).to_owned())
        })
        .unwrap_err();
        assert!(error.to_string().contains("maximum concurrency"));

        let values = std::collections::BTreeMap::from([(
            "THE_STANDARD_SERVICE_MAX_REQUEST_BODY_BYTES",
            "1024",
        )]);
        let error = CoreServiceConfig::resolve(FileConfig::default(), |name| {
            values.get(name).map(|value| (*value).to_owned())
        })
        .unwrap_err();
        assert!(error.to_string().contains("16777216"));

        let values = std::collections::BTreeMap::from([(
            "THE_STANDARD_SERVICE_SHUTDOWN_GRACE_SECONDS",
            "301",
        )]);
        let error = CoreServiceConfig::resolve(FileConfig::default(), |name| {
            values.get(name).map(|value| (*value).to_owned())
        })
        .unwrap_err();
        assert!(error.to_string().contains("SHUTDOWN_GRACE_SECONDS"));

        for invalid in ["0", "31"] {
            let values = std::collections::BTreeMap::from([(
                "THE_STANDARD_SERVICE_TARGET_DNS_TIMEOUT_SECONDS",
                invalid,
            )]);
            let error = CoreServiceConfig::resolve(FileConfig::default(), |name| {
                values.get(name).map(|value| (*value).to_owned())
            })
            .unwrap_err();
            assert!(error.to_string().contains("TARGET_DNS_TIMEOUT_SECONDS"));
        }

        for invalid in ["1024", "67108865"] {
            let values = std::collections::BTreeMap::from([(
                "THE_STANDARD_TRANSPORT_MAX_RESPONSE_BYTES",
                invalid,
            )]);
            let error = CoreServiceConfig::resolve(FileConfig::default(), |name| {
                values.get(name).map(|value| (*value).to_owned())
            })
            .unwrap_err();
            assert!(error.to_string().contains("response byte limit"));
        }

        for invalid in ["60001", "usize::MAX"] {
            let values = std::collections::BTreeMap::from([(
                "THE_STANDARD_SERVICE_PER_IP_DETECT_REQUESTS_PER_MINUTE",
                invalid,
            )]);
            let error = CoreServiceConfig::resolve(FileConfig::default(), |name| {
                values.get(name).map(|value| (*value).to_owned())
            })
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("PER_IP_DETECT_REQUESTS_PER_MINUTE")
            );
        }

        for invalid in ["0", "1048577"] {
            let values = std::collections::BTreeMap::from([(
                "THE_STANDARD_SERVICE_RATE_LIMIT_MAX_ENTRIES",
                invalid,
            )]);
            let error = CoreServiceConfig::resolve(FileConfig::default(), |name| {
                values.get(name).map(|value| (*value).to_owned())
            })
            .unwrap_err();
            assert!(error.to_string().contains("RATE_LIMIT_MAX_ENTRIES"));
        }
    }

    #[tokio::test]
    async fn health_exposes_the_actual_core_version() {
        let response = build_app(CoreServiceConfig::default())
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["core"]["name"], "TheStandard");
        assert_eq!(
            body["core"]["version"],
            Value::String(expected_core_version())
        );
        assert_eq!(body["core"]["reportSchemaVersion"], REPORT_SCHEMA_VERSION);
        assert_eq!(body["rules"]["status"], "active");
        assert_eq!(body["rules"]["bundle"]["id"], "the-standard");
        assert_eq!(
            body["rules"]["bundle"]["version"],
            sanbiao_manifest()["coreRules"]["version"]
        );
        assert_eq!(body["runtime"]["engine"]["requestTimeoutMs"], 30_000);
        assert_eq!(body["runtime"]["engine"]["maxConcurrent"], 3);
        assert_eq!(body["runtime"]["transport"]["maxResponseBytes"], 4_194_304);
        assert_eq!(body["runtime"]["transport"]["maxStreamBytes"], 4_194_304);
        assert_eq!(body["runtime"]["rules"]["refreshIntervalSeconds"], 300);
        assert_eq!(body["runtime"]["service"]["maxInflightDetections"], 8);
        assert_eq!(body["runtime"]["service"]["maxRequestBodyBytes"], 2_097_152);
        assert_eq!(body["runtime"]["service"]["shutdownGraceSeconds"], 30);
        assert_eq!(body["runtime"]["service"]["targetDnsTimeoutSeconds"], 5);
        // Effective rate-limit settings are published; no per-IP state is.
        assert_eq!(
            body["runtime"]["service"]["rateLimit"]["perIpDetectRequestsPerMinute"],
            0
        );
        assert_eq!(body["runtime"]["service"]["rateLimit"]["maxEntries"], 4096);
        assert_eq!(body["runtime"]["service"]["rateLimit"]["windowSeconds"], 60);
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("service-secret"));
        assert!(!serialized.contains("demo.example.com"));
        assert!(!serialized.contains("raw.githubusercontent.com"));
    }

    #[tokio::test]
    async fn health_is_degraded_without_a_valid_rule_bundle() {
        let config = CoreServiceConfig {
            rule_bundle: None,
            ..CoreServiceConfig::default()
        };
        let response = build_app(config)
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["rules"]["status"], "unavailable");
        assert!(body["rules"].get("bundle").is_none());
    }

    #[tokio::test]
    async fn responses_include_server_generated_request_ids() {
        let response = build_app(CoreServiceConfig::default())
            .oneshot(
                Request::get("/health")
                    .header("x-request-id", "caller-controlled")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .expect("request id header");
        assert!(Ulid::from_string(request_id).is_ok());
        assert_ne!(request_id, "caller-controlled");
    }

    #[tokio::test]
    async fn concurrent_rule_resolutions_share_one_repository_refresh() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../SanBiao");
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
        let rules: Value = serde_json::from_slice(
            &std::fs::read(root.join("rules/the-standard/stable.json")).unwrap(),
        )
        .unwrap();
        let manifest_requests = Arc::new(AtomicUsize::new(0));
        let rule_requests = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/manifest.json",
                get({
                    let manifest_requests = manifest_requests.clone();
                    move || {
                        let manifest = manifest.clone();
                        let manifest_requests = manifest_requests.clone();
                        async move {
                            manifest_requests.fetch_add(1, Ordering::SeqCst);
                            Json(manifest)
                        }
                    }
                }),
            )
            .route(
                "/rules/the-standard/stable.json",
                get({
                    let rule_requests = rule_requests.clone();
                    move || {
                        let rules = rules.clone();
                        let rule_requests = rule_requests.clone();
                        async move {
                            rule_requests.fetch_add(1, Ordering::SeqCst);
                            Json(rules)
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let repository = the_standard::RuleRepositoryConfig::new(
            &format!("http://{address}/manifest.json"),
            None,
            false,
        )
        .unwrap();
        let loader = RuleBundleLoader::new(repository, Duration::from_secs(300));
        let mut tasks = Vec::new();
        for _ in 0..12 {
            let loader = loader.clone();
            tasks.push(tokio::spawn(async move { loader.resolve().await }));
        }
        for task in tasks {
            assert!(task.await.unwrap().is_some());
        }
        assert_eq!(manifest_requests.load(Ordering::SeqCst), 1);
        assert_eq!(rule_requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn oversized_request_bodies_are_rejected_with_a_request_id() {
        let config = CoreServiceConfig {
            max_request_body_bytes: 4096,
            ..CoreServiceConfig::default()
        };
        let response = build_app(config)
            .oneshot(
                Request::post("/rpc")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![b'x'; 8 * 1024]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(response.headers().get("x-request-id").is_some());
    }

    #[tokio::test]
    async fn overloaded_detection_returns_retry_after_and_request_id() {
        let config = CoreServiceConfig {
            max_inflight_detections: 1,
            ..CoreServiceConfig::default()
        };
        let state = AppState::from(config.clone());
        let held = state.detection_slots.clone().try_acquire_owned().unwrap();
        let error = execute_detection(&state, serde_json::from_value(detection_request()).unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.code(), "service_overloaded");
        let response = ServiceError::Overloaded.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        drop(held);
        let response = build_app(config)
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(response.headers().get("x-request-id").is_some());
    }

    #[tokio::test]
    async fn rpc_overload_is_a_stable_application_error() {
        let config = CoreServiceConfig {
            max_inflight_detections: 1,
            ..CoreServiceConfig::default()
        };
        let state = AppState::from(config);
        let _held = state.detection_slots.clone().try_acquire_owned().unwrap();
        let response = rpc(
            State(state),
            PeerAddr(None),
            HeaderMap::new(),
            Json(JsonRpcRequest {
                jsonrpc: JSON_RPC_VERSION.into(),
                id: json!("01RPCOVERLOAD000000000000000"),
                method: RPC_METHOD_CORE_DETECT.into(),
                params: detection_request(),
            }),
        )
        .await
        .unwrap();
        let body = serde_json::to_value(response.0).unwrap();
        assert_eq!(body["error"]["code"], -32000);
        assert_eq!(body["error"]["data"]["code"], "service_overloaded");
        assert_eq!(
            body["error"]["message"],
            "detection capacity is currently full; retry later"
        );
    }

    #[tokio::test]
    async fn liveness_does_not_depend_on_rule_repository_readiness() {
        let config = CoreServiceConfig {
            rule_bundle: None,
            ..CoreServiceConfig::default()
        };
        let response = build_app(config)
            .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["name"], "TheStandard");
        assert_eq!(body["version"], Value::String(expected_core_version()));
    }

    #[tokio::test]
    async fn readiness_returns_service_unavailable_until_rules_are_active() {
        let unavailable = CoreServiceConfig {
            rule_bundle: None,
            ..CoreServiceConfig::default()
        };
        let response = build_app(unavailable)
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response_json(response).await["rules"]["status"],
            "unavailable"
        );

        let response = build_app(CoreServiceConfig::default())
            .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["rules"]["status"], "active");
    }

    #[tokio::test]
    async fn health_loads_core_rules_directly_from_the_repository_manifest() {
        let config = CoreServiceConfig {
            rule_repository: Some(repository_config().await),
            rule_bundle: None,
            ..CoreServiceConfig::default()
        };
        let response = build_app(config)
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["status"], "ok");
        let manifest = sanbiao_manifest();
        assert_eq!(
            body["rules"]["bundle"]["version"],
            manifest["coreRules"]["version"]
        );
        assert_eq!(
            body["rules"]["bundle"]["repository"]["release"],
            manifest["release"]
        );
        assert_eq!(
            body["rules"]["bundle"]["repository"]["manifestSource"],
            "remote"
        );
        assert_eq!(
            body["rules"]["bundle"]["repository"]["documentSource"],
            "remote"
        );
    }

    #[tokio::test]
    async fn rest_detection_masks_secrets_and_returns_versioned_report() {
        let response = build_app(CoreServiceConfig::default())
            .oneshot(
                Request::post("/v1/detect")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(detection_request().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let report: DetectionReport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report.core.version, expected_core_version());
        assert_eq!(report.core.report_schema_version, REPORT_SCHEMA_VERSION);
        let presentation = report.presentation.expect("Core supplies a presentation");
        assert_eq!(presentation.language, "en");
        assert_eq!(presentation.schema_version, PRESENTATION_SCHEMA_VERSION);
        assert!(!report.target.api_key_masked.contains("secret"));
        assert!(!String::from_utf8_lossy(&bytes).contains("sk-test-secret-value"));
    }

    #[tokio::test]
    async fn manifest_publishes_the_declared_detection_sections() {
        let response = build_app(CoreServiceConfig::default())
            .oneshot(Request::get("/v1/manifest").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let manifest: CoreUiManifest =
            serde_json::from_value(response_json(response).await).unwrap();
        let field = manifest
            .request
            .fields
            .iter()
            .find(|field| field.json_pointer == "/sections")
            .expect("the rule repository declares detection sections");
        assert_eq!(field.control, "sections");
        assert_eq!(field.default_value, json!([]));
        assert!(!field.required);
        assert!(
            field
                .options
                .iter()
                .any(|option| option.value == json!("identity"))
        );
    }

    #[tokio::test]
    async fn section_selection_is_recorded_and_unknown_sections_are_rejected() {
        let mut selected = detection_request();
        selected["sections"] = json!(["identity"]);
        let response = build_app(CoreServiceConfig::default())
            .oneshot(
                Request::post("/v1/detect")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(selected.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let report: DetectionReport = serde_json::from_slice(&bytes).unwrap();
        let selection = report
            .section_selection
            .expect("an explicit selection is recorded in the report");
        assert_eq!(selection.requested, vec!["identity".to_string()]);
        assert!(selection.not_selected.contains(&"tools".to_string()));
        assert!(!selection.not_selected.contains(&"identity".to_string()));
        assert!(
            report
                .evidence
                .iter()
                .all(|item| item.name != "tool_contract")
        );
        assert!(
            report
                .presentation
                .as_ref()
                .expect("Core supplies a presentation")
                .views
                .iter()
                .flat_map(|view| view.sections.iter())
                .any(|section| section.id == "section-selection")
        );

        let mut invalid = detection_request();
        invalid["sections"] = json!(["not-a-section"]);
        let response = build_app(CoreServiceConfig::default())
            .oneshot(
                Request::post("/v1/detect")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(invalid.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: CoreApiError = serde_json::from_value(response_json(response).await).unwrap();
        assert_eq!(error.code, "invalid_request");
        assert!(error.message.contains("not-a-section"));
    }
    #[tokio::test]
    async fn rest_and_rpc_return_the_same_english_manifest() {
        let response = build_app(CoreServiceConfig::default())
            .oneshot(Request::get("/v1/manifest").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rest: CoreUiManifest = serde_json::from_value(response_json(response).await).unwrap();

        let response = build_app(CoreServiceConfig::default())
            .oneshot(
                Request::post("/rpc")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "jsonrpc": JSON_RPC_VERSION,
                            "id": "01RPCMANIFEST00000000000000",
                            "method": RPC_METHOD_CORE_MANIFEST,
                            "params": {}
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rpc: JsonRpcResponse = serde_json::from_value(response_json(response).await).unwrap();
        let rpc: CoreUiManifest = serde_json::from_value(rpc.result.unwrap()).unwrap();

        assert_eq!(rest, rpc);
        assert_eq!(rest.schema_version, UI_MANIFEST_SCHEMA_VERSION);
        assert_eq!(rest.language, "en");
        let api_key = rest
            .request
            .fields
            .iter()
            .find(|field| field.json_pointer == "/apiKey")
            .unwrap();
        assert!(api_key.sensitive);
        assert!(!serde_json::to_string(&rest).unwrap().contains("sk-test"));
    }

    #[tokio::test]
    async fn rest_and_rpc_detection_share_the_same_versioned_contract() {
        let response = build_app(CoreServiceConfig::default())
            .oneshot(
                Request::post("/v1/detect")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(detection_request().to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rest: DetectionReport = serde_json::from_value(response_json(response).await).unwrap();

        let response = build_app(CoreServiceConfig::default())
            .oneshot(
                Request::post("/rpc")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "jsonrpc": JSON_RPC_VERSION,
                            "id": "01RPCDETECT0000000000000000",
                            "method": RPC_METHOD_CORE_DETECT,
                            "params": detection_request()
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let rpc: JsonRpcResponse = serde_json::from_value(response_json(response).await).unwrap();
        let rpc: DetectionReport = serde_json::from_value(rpc.result.unwrap()).unwrap();

        assert_eq!(rest.core, rpc.core);
        assert_eq!(rest.core.report_schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(rest.core.capability_profile, rpc.core.capability_profile);
        assert_eq!(
            rest.evidence
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            rpc.evidence
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            rest.presentation.as_ref().map(|item| item.schema_version),
            rpc.presentation.as_ref().map(|item| item.schema_version)
        );
        assert_eq!(
            rest.presentation.as_ref().map(|item| item
                .views
                .iter()
                .map(|view| view.id.as_str())
                .collect::<Vec<_>>()),
            rpc.presentation.as_ref().map(|item| item
                .views
                .iter()
                .map(|view| view.id.as_str())
                .collect::<Vec<_>>())
        );
    }

    #[tokio::test]
    async fn rpc_info_and_detection_share_the_core_contract() {
        for (method, params) in [
            (RPC_METHOD_CORE_INFO, json!({})),
            (RPC_METHOD_CORE_MANIFEST, json!({})),
            (RPC_METHOD_CORE_DETECT, detection_request()),
        ] {
            let response = build_app(CoreServiceConfig::default())
                .oneshot(
                    Request::post("/rpc")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({
                                "jsonrpc": JSON_RPC_VERSION,
                                "id": "01RPCREQUEST0000000000000000",
                                "method": method,
                                "params": params
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response_json(response).await;
            let rpc: JsonRpcResponse = serde_json::from_value(body).unwrap();
            assert!(rpc.error.is_none());
            let result = rpc.result.unwrap();
            if method == RPC_METHOD_CORE_INFO {
                assert_eq!(result["version"], Value::String(expected_core_version()));
            } else if method == RPC_METHOD_CORE_MANIFEST {
                assert_eq!(result["schemaVersion"], UI_MANIFEST_SCHEMA_VERSION);
            } else {
                assert_eq!(
                    result["core"]["version"],
                    Value::String(expected_core_version())
                );
            }
        }
    }

    #[tokio::test]
    async fn configured_token_protects_service_methods_but_not_health() {
        let config = CoreServiceConfig {
            auth_token: Some("service-secret".into()),
            ..CoreServiceConfig::default()
        };
        let response = build_app(config.clone())
            .oneshot(Request::get("/v1/core").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = build_app(config)
            .oneshot(
                Request::get("/v1/core")
                    .header("authorization", "Bearer service-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn required_auth_rejects_missing_credentials_while_health_stays_public() {
        let config = CoreServiceConfig {
            auth_token: Some("service-secret".into()),
            require_auth: true,
            ..CoreServiceConfig::default()
        };
        let app = build_app(config);
        let response = app
            .clone()
            .oneshot(Request::get("/v1/manifest").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::get("/v1/manifest")
                    .header("authorization", "Bearer service-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn validates_origins_without_accepting_paths_or_non_http_schemes() {
        assert_eq!(
            parse_allowed_origins("http://localhost:5174, https://demo.example/").unwrap(),
            vec!["http://localhost:5174", "https://demo.example"]
        );
        assert!(parse_allowed_origins("https://demo.example/path").is_err());
        assert!(parse_allowed_origins("file:///tmp/demo").is_err());
    }

    #[tokio::test]
    async fn browser_preflight_allows_only_configured_origins_and_headers() {
        let app = build_app(CoreServiceConfig::default());
        let allowed = app
            .clone()
            .oneshot(
                Request::options("/v1/detect")
                    .header(header::ORIGIN, "http://localhost:5174")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "authorization,content-type",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            allowed.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "http://localhost:5174"
        );
        assert!(
            allowed.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
                .to_str()
                .unwrap()
                .contains("authorization")
        );

        let browser_response = app
            .clone()
            .oneshot(
                Request::get("/health/live")
                    .header(header::ORIGIN, "http://localhost:5174")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(browser_response.headers().get("x-request-id").is_some());
        assert!(
            browser_response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS]
                .to_str()
                .unwrap()
                .contains("x-request-id")
        );

        let denied = app
            .oneshot(
                Request::options("/v1/detect")
                    .header(header::ORIGIN, "https://unconfigured.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            denied
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }
    fn collect_refs(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if key == "$ref" {
                        if let Some(reference) = child.as_str() {
                            found.push(reference.to_owned());
                        }
                    } else {
                        collect_refs(child, found);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_refs(item, found);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn openapi_document_covers_every_router_route() {
        let document = openapi_document();
        let paths = document["paths"]
            .as_object()
            .expect("the document declares a paths object");
        for route in SERVICE_ROUTES {
            let item = paths.get(route.path).unwrap_or_else(|| {
                panic!(
                    "{} is served by the router but missing from the document",
                    route.path
                )
            });
            assert!(
                item.get(route.method).is_some(),
                "{} {} is served by the router but missing from the document",
                route.method,
                route.path
            );
        }
        let served_paths = SERVICE_ROUTES
            .iter()
            .map(|route| route.path)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            paths.len(),
            served_paths.len(),
            "the document must not describe paths the router does not serve"
        );
        for (path, item) in paths {
            let documented = item
                .as_object()
                .expect("a path item is an object")
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            let served = SERVICE_ROUTES
                .iter()
                .filter(|route| route.path == path)
                .map(|route| route.method.to_owned())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                documented, served,
                "documented methods for {path} must match the served methods"
            );
            for (method, operation) in item.as_object().expect("a path item is an object") {
                assert!(
                    operation.get("operationId").is_some(),
                    "{method} {path} needs an operationId"
                );
                assert_eq!(
                    operation["summary"],
                    SERVICE_ROUTES
                        .iter()
                        .find(|route| route.path == path && route.method == method)
                        .expect("documented routes come from the route table")
                        .summary
                );
                assert!(
                    operation["responses"]
                        .as_object()
                        .is_some_and(|responses| !responses.is_empty()),
                    "{method} {path} must document at least one response"
                );
            }
        }
    }

    #[test]
    fn openapi_document_is_valid_versioned_json_with_resolvable_refs() {
        let raw = openapi_document().to_string();
        let document: Value = serde_json::from_str(&raw).expect("the document must be valid JSON");
        assert_eq!(document["info"]["title"], "TheStandard Core API");
        assert_eq!(
            document["info"]["version"],
            Value::String(env!("CARGO_PKG_VERSION").to_owned())
        );
        let openapi = document["openapi"]
            .as_str()
            .expect("the document declares its OpenAPI version");
        assert!(
            openapi.starts_with("3.1."),
            "an OpenAPI 3.1.x document is required, found {openapi}"
        );
        assert_eq!(
            document["paths"].as_object().expect("paths").len(),
            SERVICE_ROUTES.len()
        );

        let mut references = Vec::new();
        collect_refs(&document, &mut references);
        assert!(!references.is_empty());
        for reference in references {
            let (section, name) = match reference.split_once("/components/") {
                Some((_, rest)) => match rest.split_once('/') {
                    Some((section, name)) => (section, name),
                    None => panic!("unsupported $ref {reference}"),
                },
                None => panic!("unsupported $ref {reference}"),
            };
            assert!(
                document["components"][section].get(name).is_some(),
                "{reference} does not resolve to a component"
            );
        }
    }

    #[tokio::test]
    async fn openapi_document_is_served_without_authorization() {
        let config = CoreServiceConfig {
            auth_token: Some("service-secret".into()),
            require_auth: true,
            ..CoreServiceConfig::default()
        };
        let response = build_app(config)
            .oneshot(Request::get("/openapi.json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );
        let body = response_json(response).await;
        assert_eq!(body, openapi_document());
    }

    #[tokio::test]
    async fn every_documented_route_is_registered_in_the_router() {
        let app = build_app(CoreServiceConfig::default());
        for route in SERVICE_ROUTES {
            let path = route.path.replace("{job_id}", "01J00000000000000000000000");
            // A registered path answers an unsupported method with 405; an
            // unregistered path would answer 404.
            let probe = app
                .clone()
                .oneshot(Request::patch(&path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                probe.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{} must be registered in the router",
                route.path
            );
            let request = match route.method {
                "get" => Request::get(&path),
                "post" => Request::post(&path).header(header::CONTENT_TYPE, "application/json"),
                other => panic!("documented method {other} is not exercised by this test"),
            };
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{} {} must be served by the router",
                route.method,
                route.path
            );
        }
    }
    /// Service configuration with the per-IP detection limit under test.
    fn rate_limited_config(requests_per_minute: usize, max_entries: usize) -> CoreServiceConfig {
        CoreServiceConfig {
            per_ip_detect_requests_per_minute: requests_per_minute,
            rate_limit_max_entries: max_entries,
            ..CoreServiceConfig::default()
        }
    }

    /// Attaches the peer address the serve path supplies through
    /// `into_make_service_with_connect_info`.
    fn with_peer(request: Request<Body>, address: SocketAddr) -> Request<Body> {
        let (mut parts, body) = request.into_parts();
        parts.extensions.insert(ConnectInfo(address));
        Request::from_parts(parts, body)
    }

    fn detect_http_request() -> Request<Body> {
        Request::post("/v1/detect")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&detection_request()).unwrap(),
            ))
            .unwrap()
    }

    fn rpc_http_request(body: &Value) -> Request<Body> {
        Request::post("/rpc")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn retry_after_seconds(response: &axum::response::Response) -> u64 {
        response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .expect("rate-limited responses carry Retry-After")
            .parse()
            .expect("Retry-After is a whole number of seconds")
    }

    #[tokio::test]
    async fn per_ip_rate_limit_returns_429_with_retry_after() {
        let app = build_app(rate_limited_config(1, 16));
        let peer = SocketAddr::from(([203, 0, 113, 7], 4444));
        let first = app
            .clone()
            .oneshot(with_peer(detect_http_request(), peer))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let limited = app
            .clone()
            .oneshot(with_peer(detect_http_request(), peer))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = retry_after_seconds(&limited);
        assert!(
            (1..=RATE_LIMIT_WINDOW.as_secs()).contains(&retry_after),
            "Retry-After {retry_after} must stay inside the window"
        );
        let body = response_json(limited).await;
        assert_eq!(body["code"], "rate_limited");
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty())
        );
    }

    #[tokio::test]
    async fn detection_jobs_share_the_per_ip_limit() {
        let app = build_app(rate_limited_config(1, 16));
        let peer = SocketAddr::from(([203, 0, 113, 8], 4445));
        let request = || {
            Request::post("/v1/detect/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&detection_request()).unwrap(),
                ))
                .unwrap()
        };
        let accepted = app
            .clone()
            .oneshot(with_peer(request(), peer))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let limited = app
            .clone()
            .oneshot(with_peer(request(), peer))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(retry_after_seconds(&limited) >= 1);
        assert_eq!(response_json(limited).await["code"], "rate_limited");
    }

    #[test]
    fn rate_limit_window_rolls_over_and_allows_again() {
        let limiter = PerIpRateLimiter::new(2, 8, RATE_LIMIT_WINDOW);
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let start = Instant::now();
        assert_eq!(limiter.check(peer, start), RateLimitDecision::Allowed);
        assert_eq!(
            limiter.check(peer, start + Duration::from_secs(1)),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check(peer, start + Duration::from_secs(2)),
            RateLimitDecision::Limited {
                retry_after_seconds: 58
            }
        );
        assert_eq!(
            limiter.check(peer, start + Duration::from_secs(59)),
            RateLimitDecision::Limited {
                retry_after_seconds: 1
            }
        );
        // The window rolls exactly at its length.
        assert_eq!(
            limiter.check(peer, start + RATE_LIMIT_WINDOW),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check(peer, start + RATE_LIMIT_WINDOW + Duration::from_secs(1)),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check(peer, start + RATE_LIMIT_WINDOW + Duration::from_secs(2)),
            RateLimitDecision::Limited {
                retry_after_seconds: 58
            }
        );
    }

    #[tokio::test]
    async fn disabled_rate_limit_never_limits() {
        let app = build_app(rate_limited_config(0, 16));
        let peer = SocketAddr::from(([203, 0, 113, 10], 4446));
        for _ in 0..4 {
            let response = app
                .clone()
                .oneshot(with_peer(detect_http_request(), peer))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[test]
    fn rate_limit_map_stays_bounded_and_evicts_idle_entries() {
        let now = Instant::now();
        let limiter = PerIpRateLimiter::new(5, 2, RATE_LIMIT_WINDOW);
        let first: IpAddr = "203.0.113.1".parse().unwrap();
        let second: IpAddr = "203.0.113.2".parse().unwrap();
        let third: IpAddr = "203.0.113.3".parse().unwrap();
        assert_eq!(limiter.check(first, now), RateLimitDecision::Allowed);
        assert_eq!(
            limiter.check(second, now + Duration::from_secs(5)),
            RateLimitDecision::Allowed
        );
        assert_eq!(limiter.tracked_entries(), 2);
        // The third address evicts instead of growing the map.
        assert_eq!(
            limiter.check(third, now + Duration::from_secs(10)),
            RateLimitDecision::Allowed
        );
        assert_eq!(limiter.tracked_entries(), 2);
        // A flood of distinct addresses never pushes the map past the cap.
        let later = now + Duration::from_secs(120);
        for octet in 10..40 {
            let peer: IpAddr = format!("198.51.100.{octet}").parse().unwrap();
            assert_eq!(limiter.check(peer, later), RateLimitDecision::Allowed);
            assert!(limiter.tracked_entries() <= 2);
        }

        // Expired windows are reclaimed before live ones, so an active client
        // keeps its budget while idle entries are dropped.
        let limiter = PerIpRateLimiter::new(1, 2, RATE_LIMIT_WINDOW);
        let idle: IpAddr = "198.51.100.1".parse().unwrap();
        let active: IpAddr = "198.51.100.2".parse().unwrap();
        let fresh: IpAddr = "198.51.100.3".parse().unwrap();
        assert_eq!(limiter.check(idle, now), RateLimitDecision::Allowed);
        assert_eq!(
            limiter.check(active, now + Duration::from_secs(30)),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check(fresh, now + Duration::from_secs(61)),
            RateLimitDecision::Allowed
        );
        assert_eq!(limiter.tracked_entries(), 2);
        assert_eq!(
            limiter.check(active, now + Duration::from_secs(62)),
            RateLimitDecision::Limited {
                retry_after_seconds: 28
            }
        );
    }

    #[tokio::test]
    async fn health_and_manifest_never_consume_the_detect_limit() {
        let app = build_app(rate_limited_config(1, 16));
        let peer = SocketAddr::from(([203, 0, 113, 11], 4447));
        for _ in 0..3 {
            for path in ["/health", "/health/ready", "/v1/manifest", "/v1/core"] {
                let response = app
                    .clone()
                    .oneshot(with_peer(
                        Request::get(path).body(Body::empty()).unwrap(),
                        peer,
                    ))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "{path} must never be rate limited"
                );
            }
        }
        // The detection budget is untouched by those reads.
        let first = app
            .clone()
            .oneshot(with_peer(detect_http_request(), peer))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = app
            .clone()
            .oneshot(with_peer(detect_http_request(), peer))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn json_rpc_metadata_methods_are_not_counted() {
        let app = build_app(rate_limited_config(1, 16));
        let peer = SocketAddr::from(([203, 0, 113, 12], 4448));
        for _ in 0..3 {
            for method in [RPC_METHOD_CORE_INFO, RPC_METHOD_CORE_MANIFEST] {
                let request = json!({
                    "jsonrpc": JSON_RPC_VERSION,
                    "id": 1,
                    "method": method,
                    "params": {},
                });
                let response = app
                    .clone()
                    .oneshot(with_peer(rpc_http_request(&request), peer))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert!(
                    response_json(response).await.get("result").is_some(),
                    "{method} must not be rate limited"
                );
            }
        }

        // core.detect is counted, so the second call in the window is refused.
        let mut request = json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": 2,
            "method": RPC_METHOD_CORE_DETECT,
            "params": detection_request(),
        });
        let first = app
            .clone()
            .oneshot(with_peer(rpc_http_request(&request), peer))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        request["id"] = json!(3);
        let limited = app
            .clone()
            .oneshot(with_peer(rpc_http_request(&request), peer))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(retry_after_seconds(&limited) >= 1);
        assert_eq!(response_json(limited).await["code"], "rate_limited");
    }

    #[test]
    fn openapi_documents_rate_limited_responses() {
        let document = openapi_document();
        for path in ["/v1/detect", "/v1/detect/jobs", "/rpc"] {
            assert!(
                document["paths"][path]["post"]["responses"]["429"].is_object(),
                "{path} must document the 429 response"
            );
        }
        assert!(
            document["components"]["schemas"]["CoreRuntimeServiceHealth"]["properties"]["rateLimit"]
                .is_object()
        );
    }
}
