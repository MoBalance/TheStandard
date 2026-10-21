use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use url::Url;
pub use wire_contracts::ProbeMode;

const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_OVERALL_TIMEOUT: Duration = Duration::from_secs(3_600);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(60);
const MAX_RETRIES: usize = 10;
const MAX_CONCURRENT_PROBES: usize = 64;
const MIN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MIN_STREAM_BYTES: usize = 64 * 1024;
const MAX_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_STREAM_EVENTS: usize = 100_000;
const MIN_RULE_DOCUMENT_BYTES: usize = 4 * 1024;
const MAX_RULE_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RULE_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RuleRepositoryConfig {
    pub manifest_url: Url,
    pub source_revision: Option<String>,
    pub request_timeout: Duration,
    pub max_manifest_bytes: usize,
    pub max_document_bytes: usize,
    pub fallback_directory: Option<PathBuf>,
}

impl RuleRepositoryConfig {
    pub fn new(
        manifest_url: &str,
        source_revision: Option<&str>,
        allow_insecure_http: bool,
    ) -> Result<Self, String> {
        let mut manifest_url = Url::parse(manifest_url.trim())
            .map_err(|_| "rule manifest URL is invalid".to_owned())?;
        if manifest_url.query().is_some()
            || manifest_url.fragment().is_some()
            || manifest_url.host_str().is_none()
            || !manifest_url.username().is_empty()
            || manifest_url.password().is_some()
        {
            return Err(
                "rule manifest URL must be absolute and contain no credentials, query, or fragment"
                    .into(),
            );
        }
        let loopback_http = manifest_url.scheme() == "http"
            && manifest_url.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            });
        if manifest_url.scheme() != "https" && !loopback_http && !allow_insecure_http {
            return Err(
                "rule manifest URL must use HTTPS unless insecure HTTP is explicitly enabled"
                    .into(),
            );
        }
        if !matches!(manifest_url.scheme(), "http" | "https") {
            return Err("rule manifest URL must use HTTP or HTTPS".into());
        }
        if !manifest_url.path().ends_with(".json") {
            return Err("rule manifest URL must reference a JSON document".into());
        }

        let explicit_revision = source_revision
            .map(str::trim)
            .filter(|revision| !revision.is_empty())
            .map(str::to_ascii_lowercase);
        if explicit_revision
            .as_deref()
            .is_some_and(|revision| !valid_revision(revision))
        {
            return Err("rule source revision must be a 40-character Git commit SHA".into());
        }
        if let Some(revision) = explicit_revision.as_deref() {
            pin_raw_github_url(&mut manifest_url, revision)?;
        }
        let source_revision = explicit_revision.or_else(|| revision_from_raw_url(&manifest_url));

        let config = Self {
            manifest_url,
            source_revision,
            request_timeout: Duration::from_secs(5),
            max_manifest_bytes: 256 * 1024,
            max_document_bytes: 1024 * 1024,
            fallback_directory: None,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_limits(
        mut self,
        request_timeout: Duration,
        max_manifest_bytes: usize,
        max_document_bytes: usize,
    ) -> Result<Self, String> {
        self.request_timeout = request_timeout;
        self.max_manifest_bytes = max_manifest_bytes;
        self.max_document_bytes = max_document_bytes;
        self.validate()?;
        Ok(self)
    }

    pub fn with_fallback_directory(mut self, directory: Option<PathBuf>) -> Self {
        self.fallback_directory = directory;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        require_duration(
            "rule repository request timeout",
            self.request_timeout,
            Duration::from_secs(60),
        )?;
        require_usize_range(
            "rule manifest byte limit",
            self.max_manifest_bytes,
            MIN_RULE_DOCUMENT_BYTES,
            MAX_RULE_MANIFEST_BYTES,
        )?;
        require_usize_range(
            "rule document byte limit",
            self.max_document_bytes,
            MIN_RULE_DOCUMENT_BYTES,
            MAX_RULE_DOCUMENT_BYTES,
        )?;
        Ok(())
    }
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn revision_from_raw_url(url: &Url) -> Option<String> {
    if url.host_str() != Some("raw.githubusercontent.com") {
        return None;
    }
    let revision = url.path_segments()?.nth(2)?;
    valid_revision(revision).then(|| revision.to_ascii_lowercase())
}

fn pin_raw_github_url(url: &mut Url, revision: &str) -> Result<(), String> {
    if url.host_str() != Some("raw.githubusercontent.com") {
        return Ok(());
    }
    let mut segments = url
        .path_segments()
        .ok_or_else(|| "raw GitHub rule manifest path is invalid".to_owned())?
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if segments.len() < 4 {
        return Err(
            "raw GitHub rule manifest path must include owner, repository, and revision".into(),
        );
    }
    segments[2] = revision.to_owned();
    url.set_path(&segments.join("/"));
    Ok(())
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub request_timeout: Duration,
    pub max_retries: usize,
    pub retry_backoff: Duration,
    pub max_concurrent: usize,
    pub quick_timeout: Duration,
    pub standard_timeout: Duration,
    pub full_timeout: Duration,
    pub rule_repository: Option<RuleRepositoryConfig>,
    pub rule_bundle: Option<Arc<crate::CoreRuleBundle>>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_backoff: Duration::from_secs(1),
            max_concurrent: 8,
            quick_timeout: Duration::from_secs(60),
            standard_timeout: Duration::from_secs(120),
            full_timeout: Duration::from_secs(180),
            rule_repository: None,
            rule_bundle: default_test_rule_bundle(),
        }
    }
}

#[cfg(not(test))]
fn default_test_rule_bundle() -> Option<Arc<crate::CoreRuleBundle>> {
    None
}

#[cfg(test)]
fn default_test_rule_bundle() -> Option<Arc<crate::CoreRuleBundle>> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../SanBiao/rules/the-standard/stable.json");
    Some(Arc::new(
        crate::CoreRuleBundle::from_document(&std::fs::read(path).unwrap(), None)
            .expect("shared Knowledge rule fixture"),
    ))
}

impl EngineConfig {
    pub fn validate(&self) -> Result<(), String> {
        require_duration(
            "engine request timeout",
            self.request_timeout,
            MAX_REQUEST_TIMEOUT,
        )?;
        if self.max_retries > MAX_RETRIES {
            return Err(format!("engine max retries must not exceed {MAX_RETRIES}"));
        }
        if self.max_retries > 0 {
            require_duration(
                "engine retry backoff",
                self.retry_backoff,
                MAX_RETRY_BACKOFF,
            )?;
        } else if self.retry_backoff > MAX_RETRY_BACKOFF {
            return Err(format!(
                "engine retry backoff must not exceed {} milliseconds",
                MAX_RETRY_BACKOFF.as_millis()
            ));
        }
        require_usize_range(
            "engine maximum concurrency",
            self.max_concurrent,
            1,
            MAX_CONCURRENT_PROBES,
        )?;
        for (name, timeout) in [
            ("quick", self.quick_timeout),
            ("standard", self.standard_timeout),
            ("full", self.full_timeout),
        ] {
            require_duration(
                &format!("engine {name} overall timeout"),
                timeout,
                MAX_OVERALL_TIMEOUT,
            )?;
            if timeout < self.request_timeout {
                return Err(format!(
                    "engine {name} overall timeout must be at least the request timeout"
                ));
            }
        }
        if self.standard_timeout < self.quick_timeout || self.full_timeout < self.standard_timeout {
            return Err("engine overall timeouts must satisfy quick <= standard <= full".into());
        }
        if let Some(repository) = &self.rule_repository {
            repository.validate()?;
        }
        Ok(())
    }

    pub fn overall_timeout(&self, mode: ProbeMode) -> Duration {
        match mode {
            ProbeMode::Quick => self.quick_timeout,
            ProbeMode::Standard => self.standard_timeout,
            ProbeMode::Full => self.full_timeout,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTransportConfig {
    pub max_response_bytes: usize,
    pub max_stream_bytes: usize,
    pub max_stream_events: usize,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            max_response_bytes: 4 * 1024 * 1024,
            max_stream_bytes: 4 * 1024 * 1024,
            max_stream_events: 10_000,
        }
    }
}

impl HttpTransportConfig {
    pub fn validate(&self) -> Result<(), String> {
        require_usize_range(
            "transport response byte limit",
            self.max_response_bytes,
            MIN_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES,
        )?;
        require_usize_range(
            "transport stream byte limit",
            self.max_stream_bytes,
            MIN_STREAM_BYTES,
            MAX_STREAM_BYTES,
        )?;
        require_usize_range(
            "transport stream event limit",
            self.max_stream_events,
            1,
            MAX_STREAM_EVENTS,
        )?;
        Ok(())
    }
}

fn require_duration(name: &str, value: Duration, maximum: Duration) -> Result<(), String> {
    if value.is_zero() {
        return Err(format!("{name} must be greater than zero"));
    }
    if value > maximum {
        return Err(format!(
            "{name} must not exceed {} milliseconds",
            maximum.as_millis()
        ));
    }
    Ok(())
}

fn require_usize_range(
    name: &str,
    value: usize,
    minimum: usize,
    maximum: usize,
) -> Result<(), String> {
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be between {minimum} and {maximum}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EngineConfig, HttpTransportConfig, RuleRepositoryConfig};
    use std::time::Duration;

    #[test]
    fn engine_configuration_rejects_inconsistent_budgets() {
        let config = EngineConfig {
            request_timeout: Duration::from_secs(61),
            quick_timeout: Duration::from_secs(60),
            ..EngineConfig::default()
        };
        assert!(config.validate().unwrap_err().contains("quick"));

        let config = EngineConfig {
            quick_timeout: Duration::from_secs(180),
            standard_timeout: Duration::from_secs(120),
            ..EngineConfig::default()
        };
        assert!(config.validate().unwrap_err().contains("quick <= standard"));
    }

    #[test]
    fn engine_configuration_allows_explicitly_disabled_retries() {
        let config = EngineConfig {
            max_retries: 0,
            retry_backoff: Duration::ZERO,
            ..EngineConfig::default()
        };
        config.validate().unwrap();
    }

    #[test]
    fn transport_configuration_rejects_unbounded_values() {
        assert!(
            HttpTransportConfig {
                max_response_bytes: usize::MAX,
                ..HttpTransportConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            HttpTransportConfig {
                max_stream_bytes: usize::MAX,
                ..HttpTransportConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            HttpTransportConfig {
                max_stream_events: 0,
                ..HttpTransportConfig::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn rule_repository_configuration_validates_limits() {
        let config =
            RuleRepositoryConfig::new("https://rules.example.com/manifest.json", None, false)
                .unwrap();
        assert!(
            config
                .clone()
                .with_limits(Duration::ZERO, 256 * 1024, 1024 * 1024)
                .is_err()
        );
        assert!(
            config
                .with_limits(Duration::from_secs(5), 1024, 1024 * 1024)
                .is_err()
        );
    }
}
