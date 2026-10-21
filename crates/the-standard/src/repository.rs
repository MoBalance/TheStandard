use crate::{Protocol, RuleRepositoryConfig};
use futures_util::StreamExt;
use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path};
use thiserror::Error;
use url::Url;
use wire_contracts::RuleRepositorySource;

const REPOSITORY_SCHEMA_VERSION: u32 = 1;
const MAX_KNOWLEDGE_PACKS: usize = 128;
const MAX_FINGERPRINT_BANKS: usize = 8;
const MAX_TARGETS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleRepositoryManifest {
    pub repository_schema_version: u32,
    pub release: String,
    pub core_rules: RepositoryDocument,
    pub knowledge_packs: Vec<RepositoryKnowledgePack>,
    /// Optional reference banks used for numeric model attribution. Manifests
    /// published before the field existed simply omit it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fingerprint_banks: Vec<RepositoryFingerprintBank>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryDocument {
    pub id: String,
    pub version: String,
    pub channel: String,
    pub path: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryKnowledgePack {
    pub id: String,
    pub version: String,
    pub channel: String,
    pub path: String,
    pub digest: String,
    pub targets: Vec<RepositoryTarget>,
}

/// Descriptor of an optional numeric model-fingerprint bank.
///
/// `source` is descriptive provenance published by the repository and is not
/// used for validation: the canonical digest is what binds the document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryFingerprintBank {
    pub id: String,
    pub version: String,
    pub channel: String,
    pub path: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryTarget {
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub model: String,
}

#[derive(Debug, Clone)]
pub struct RepositoryFetch<T> {
    pub value: T,
    pub source: RuleRepositorySource,
}

impl RuleRepositoryManifest {
    pub fn from_bytes(bytes: &[u8], max_bytes: usize) -> Result<Self, RuleRepositoryError> {
        if bytes.len() > max_bytes {
            return Err(RuleRepositoryError::TooLarge("manifest"));
        }
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), RuleRepositoryError> {
        if self.repository_schema_version != REPOSITORY_SCHEMA_VERSION {
            return Err(RuleRepositoryError::Invalid(
                "unsupported repository schema version",
            ));
        }
        validate_identifier(&self.release, "repository release")?;
        validate_document(&self.core_rules)?;
        if self.core_rules.id != "the-standard" {
            return Err(RuleRepositoryError::Invalid(
                "core rule descriptor must use the the-standard id",
            ));
        }
        if self.knowledge_packs.len() > MAX_KNOWLEDGE_PACKS {
            return Err(RuleRepositoryError::Invalid(
                "repository contains too many knowledge packs",
            ));
        }

        let mut identities = BTreeSet::from([document_identity(&self.core_rules)]);
        let mut paths = BTreeSet::from([self.core_rules.path.as_str()]);
        for pack in &self.knowledge_packs {
            let document = pack.document();
            validate_document(&document)?;
            if !identities.insert(document_identity(&document)) {
                return Err(RuleRepositoryError::Invalid(
                    "repository document identities must be unique",
                ));
            }
            if !paths.insert(pack.path.as_str()) {
                return Err(RuleRepositoryError::Invalid(
                    "repository document paths must be unique",
                ));
            }
            validate_targets(&pack.targets)?;
        }
        if self.fingerprint_banks.len() > MAX_FINGERPRINT_BANKS {
            return Err(RuleRepositoryError::Invalid(
                "repository contains too many fingerprint banks",
            ));
        }
        for bank in &self.fingerprint_banks {
            let document = bank.document();
            validate_document(&document)?;
            if !identities.insert(document_identity(&document)) {
                return Err(RuleRepositoryError::Invalid(
                    "repository document identities must be unique",
                ));
            }
            if !paths.insert(bank.path.as_str()) {
                return Err(RuleRepositoryError::Invalid(
                    "repository document paths must be unique",
                ));
            }
        }
        Ok(())
    }

    /// Selects the fingerprint bank the engine should attribute against.
    ///
    /// A manifest that predates the field, or one that publishes no bank for
    /// the requested channel, yields `None` and therefore no attribution.
    pub fn select_fingerprint_bank<'a>(
        &'a self,
        channel: &str,
        bank_id: Option<&str>,
        version: Option<&str>,
    ) -> Option<&'a RepositoryFingerprintBank> {
        self.fingerprint_banks
            .iter()
            .filter(|bank| {
                bank.channel == channel
                    && bank_id.is_none_or(|id| bank.id == id)
                    && version.is_none_or(|expected| bank.version == expected)
            })
            .max_by(|left, right| {
                left.version
                    .cmp(&right.version)
                    .then(left.id.cmp(&right.id))
            })
    }

    pub fn select_knowledge_pack<'a>(
        &'a self,
        protocol: Protocol,
        model: &str,
        provider: Option<&str>,
        pack_id: Option<&str>,
        version: Option<&str>,
        channel: &str,
    ) -> Option<&'a RepositoryKnowledgePack> {
        let model = model.trim();
        let provider = provider.map(str::trim).filter(|value| !value.is_empty());
        self.knowledge_packs
            .iter()
            .filter(|pack| {
                pack.channel == channel
                    && pack_id.is_none_or(|id| pack.id == id)
                    && version.is_none_or(|expected| pack.version == expected)
                    && pack.targets.iter().any(|target| {
                        target.protocol == protocol
                            && target.model == model
                            && provider.is_none_or(|expected| {
                                target
                                    .provider
                                    .as_deref()
                                    .is_none_or(|actual| actual.eq_ignore_ascii_case(expected))
                            })
                    })
            })
            .max_by(|left, right| {
                left.version
                    .cmp(&right.version)
                    .then(left.id.cmp(&right.id))
            })
    }
}

impl RepositoryKnowledgePack {
    pub fn document(&self) -> RepositoryDocument {
        RepositoryDocument {
            id: self.id.clone(),
            version: self.version.clone(),
            channel: self.channel.clone(),
            path: self.path.clone(),
            digest: self.digest.clone(),
        }
    }
}

impl RepositoryFingerprintBank {
    pub fn document(&self) -> RepositoryDocument {
        RepositoryDocument {
            id: self.id.clone(),
            version: self.version.clone(),
            channel: self.channel.clone(),
            path: self.path.clone(),
            digest: self.digest.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RuleRepositoryClient {
    config: RuleRepositoryConfig,
    client: reqwest::Client,
}

impl RuleRepositoryClient {
    pub fn new(
        config: RuleRepositoryConfig,
        user_agent: &str,
    ) -> Result<Self, RuleRepositoryError> {
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(user_agent)
            .build()
            .map_err(|_| RuleRepositoryError::Client)?;
        Ok(Self { config, client })
    }

    pub fn config(&self) -> &RuleRepositoryConfig {
        &self.config
    }

    pub async fn fetch_manifest(&self) -> Result<RuleRepositoryManifest, RuleRepositoryError> {
        self.fetch_manifest_with_source()
            .await
            .map(|result| result.value)
    }

    pub async fn fetch_manifest_with_source(
        &self,
    ) -> Result<RepositoryFetch<RuleRepositoryManifest>, RuleRepositoryError> {
        let (bytes, source) = match self
            .fetch_limited(&self.config.manifest_url, self.config.max_manifest_bytes)
            .await
        {
            Ok(bytes) => (bytes, RuleRepositorySource::Remote),
            Err(error) => (
                self.fetch_local("manifest.json", self.config.max_manifest_bytes)
                    .or(Err(error))?,
                RuleRepositorySource::LocalFallback,
            ),
        };
        Ok(RepositoryFetch {
            value: RuleRepositoryManifest::from_bytes(&bytes, self.config.max_manifest_bytes)?,
            source,
        })
    }

    pub async fn fetch_document(
        &self,
        descriptor: &RepositoryDocument,
    ) -> Result<Vec<u8>, RuleRepositoryError> {
        self.fetch_document_with_source(descriptor)
            .await
            .map(|result| result.value)
    }

    pub async fn fetch_document_with_source(
        &self,
        descriptor: &RepositoryDocument,
    ) -> Result<RepositoryFetch<Vec<u8>>, RuleRepositoryError> {
        let url = self.document_url(&descriptor.path)?;
        let (bytes, source) = match self
            .fetch_limited(&url, self.config.max_document_bytes)
            .await
        {
            Ok(bytes) => (bytes, RuleRepositorySource::Remote),
            Err(error) => (
                self.fetch_local(&descriptor.path, self.config.max_document_bytes)
                    .or(Err(error))?,
                RuleRepositorySource::LocalFallback,
            ),
        };
        let digest = canonical_json_digest_bytes(&bytes)?;
        if digest != descriptor.digest {
            return Err(RuleRepositoryError::DigestMismatch);
        }
        Ok(RepositoryFetch {
            value: bytes,
            source,
        })
    }

    fn fetch_local(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>, RuleRepositoryError> {
        let Some(root) = self.config.fallback_directory.as_ref() else {
            return Err(RuleRepositoryError::Unavailable);
        };
        validate_path(path)?;
        let root = Path::new(root);
        let file = root.join(path);
        let bytes = fs::read(file).map_err(|_| RuleRepositoryError::Unavailable)?;
        if bytes.len() > max_bytes {
            return Err(RuleRepositoryError::TooLarge("document"));
        }
        Ok(bytes)
    }

    pub fn document_url(&self, path: &str) -> Result<Url, RuleRepositoryError> {
        validate_path(path)?;
        let url = self
            .config
            .manifest_url
            .join(path)
            .map_err(|_| RuleRepositoryError::Invalid("repository document path is invalid"))?;
        if !same_origin(&self.config.manifest_url, &url)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(RuleRepositoryError::Invalid(
                "repository document must remain on the manifest origin",
            ));
        }
        Ok(url)
    }

    async fn fetch_limited(
        &self,
        url: &Url,
        max_bytes: usize,
    ) -> Result<Vec<u8>, RuleRepositoryError> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| RuleRepositoryError::Unavailable)?;
        if response.url() != url {
            return Err(RuleRepositoryError::Invalid(
                "repository responses must not redirect",
            ));
        }
        if !response.status().is_success() {
            return Err(RuleRepositoryError::Http(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(RuleRepositoryError::TooLarge("document"));
        }

        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| RuleRepositoryError::Unavailable)?;
            if bytes.len().saturating_add(chunk.len()) > max_bytes {
                return Err(RuleRepositoryError::TooLarge("document"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

pub(crate) fn canonical_json_digest(value: &Value) -> Result<String, serde_json::Error> {
    let mut bytes = Vec::new();
    write_canonical_json(value, &mut bytes)?;
    let mut context = Context::new(&SHA256);
    context.update(&bytes);
    let digest = context.finish();
    Ok(format!(
        "sha256:{}",
        digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

pub(crate) fn canonical_json_digest_bytes(bytes: &[u8]) -> Result<String, RuleRepositoryError> {
    let value: Value = serde_json::from_slice(bytes)?;
    canonical_json_digest(&value).map_err(RuleRepositoryError::Json)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    match value {
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical_json(&object[key], output)?;
            }
            output.push(b'}');
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Number(number) => {
            let encoded = number.to_string();
            output.extend_from_slice(encoded.strip_suffix(".0").unwrap_or(&encoded).as_bytes());
        }
        _ => serde_json::to_writer(output, value)?,
    }
    Ok(())
}

fn validate_document(document: &RepositoryDocument) -> Result<(), RuleRepositoryError> {
    validate_identifier(&document.id, "document id")?;
    validate_identifier(&document.version, "document version")?;
    validate_identifier(&document.channel, "document channel")?;
    if document.channel != document.channel.to_ascii_lowercase() {
        return Err(RuleRepositoryError::Invalid(
            "document channel must be lowercase",
        ));
    }
    validate_path(&document.path)?;
    validate_digest(&document.digest)
}

fn validate_targets(targets: &[RepositoryTarget]) -> Result<(), RuleRepositoryError> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(RuleRepositoryError::Invalid(
            "knowledge pack targets must contain 1 to 64 entries",
        ));
    }
    let mut unique = BTreeSet::new();
    for target in targets {
        validate_identifier(&target.model, "target model")?;
        if let Some(provider) = &target.provider {
            validate_identifier(provider, "target provider")?;
        }
        let identity = format!(
            "{:?}:{}:{}",
            target.protocol,
            target.provider.as_deref().unwrap_or_default(),
            target.model
        );
        if !unique.insert(identity) {
            return Err(RuleRepositoryError::Invalid(
                "knowledge pack targets must be unique",
            ));
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), RuleRepositoryError> {
    if value.is_empty()
        || value.len() > 160
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'+' | b'-')
        })
    {
        return Err(RuleRepositoryError::Invalid(field));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), RuleRepositoryError> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.contains("//")
        || !path.ends_with(".json")
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || !path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'+' | b'-')
        })
    {
        return Err(RuleRepositoryError::Invalid(
            "repository document path is invalid",
        ));
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), RuleRepositoryError> {
    let value = digest.strip_prefix("sha256:");
    if value.is_none_or(|value| {
        value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(RuleRepositoryError::Invalid(
            "repository digest must be lowercase SHA-256",
        ));
    }
    Ok(())
}

fn document_identity(document: &RepositoryDocument) -> String {
    format!("{}:{}:{}", document.id, document.version, document.channel)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[derive(Debug, Error)]
pub enum RuleRepositoryError {
    #[error("rule repository is unavailable")]
    Unavailable,
    #[error("rule repository returned HTTP {0}")]
    Http(u16),
    #[error("rule repository HTTP client could not be created")]
    Client,
    #[error("rule repository {0} exceeds its configured size limit")]
    TooLarge(&'static str),
    #[error("invalid rule repository: {0}")]
    Invalid(&'static str),
    #[error("rule repository document digest does not match the manifest")]
    DigestMismatch,
    #[error("invalid rule repository JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn manifest_bytes() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../SanBiao/manifest.json");
        std::fs::read(path).unwrap()
    }

    #[test]
    fn validates_the_shared_repository_manifest() {
        let raw: Value = serde_json::from_slice(&manifest_bytes()).unwrap();
        let manifest = RuleRepositoryManifest::from_bytes(&manifest_bytes(), 256 * 1024).unwrap();
        // Version-agnostic: the typed parser must preserve the published
        // release values instead of pinning a literal that breaks on every bump.
        assert_eq!(manifest.release, raw["release"].as_str().unwrap());
        assert_eq!(
            manifest.core_rules.version,
            raw["coreRules"]["version"].as_str().unwrap()
        );
        assert_eq!(manifest.release, manifest.core_rules.version);
        assert_eq!(manifest.knowledge_packs.len(), 1);
        let rules = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../SanBiao/rules/the-standard/stable.json");
        assert_eq!(
            canonical_json_digest_bytes(&std::fs::read(rules).unwrap()).unwrap(),
            manifest.core_rules.digest
        );
    }

    #[test]
    fn rejects_unknown_fields_and_path_traversal() {
        let mut manifest: Value = serde_json::from_slice(&manifest_bytes()).unwrap();
        manifest["extra"] = Value::Bool(true);
        assert!(
            RuleRepositoryManifest::from_bytes(&serde_json::to_vec(&manifest).unwrap(), 256 * 1024)
                .is_err()
        );

        let mut manifest: Value = serde_json::from_slice(&manifest_bytes()).unwrap();
        manifest["coreRules"]["path"] = Value::String("../rules.json".into());
        assert!(
            RuleRepositoryManifest::from_bytes(&serde_json::to_vec(&manifest).unwrap(), 256 * 1024)
                .is_err()
        );
    }

    #[test]
    fn repository_config_pins_raw_github_urls_and_rejects_credentials() {
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let config = RuleRepositoryConfig::new(
            "https://raw.githubusercontent.com/acme/rules/main/manifest.json",
            Some(revision),
            false,
        )
        .unwrap();
        assert!(config.manifest_url.as_str().contains(revision));
        assert_eq!(config.source_revision.as_deref(), Some(revision));
        assert!(
            RuleRepositoryConfig::new("https://user@example.com/manifest.json", None, false)
                .is_err()
        );
    }

    #[tokio::test]
    async fn identifies_validated_local_fallback_documents() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../SanBiao");
        let config = RuleRepositoryConfig::new("http://127.0.0.1:1/manifest.json", None, false)
            .unwrap()
            .with_fallback_directory(Some(root));
        let client = RuleRepositoryClient::new(config, "repository-source-test").unwrap();
        let manifest = client.fetch_manifest_with_source().await.unwrap();
        assert_eq!(manifest.source, RuleRepositorySource::LocalFallback);
        let document = client
            .fetch_document_with_source(&manifest.value.core_rules)
            .await
            .unwrap();
        assert_eq!(document.source, RuleRepositorySource::LocalFallback);
        assert_eq!(
            manifest.value.release,
            serde_json::from_slice::<Value>(&manifest_bytes()).unwrap()["release"]
                .as_str()
                .unwrap()
        );
    }

    #[test]
    fn optional_fingerprint_banks_keep_older_manifests_valid() {
        let mut raw: Value = serde_json::from_slice(&manifest_bytes()).unwrap();
        raw["fingerprintBanks"] = Value::Array(Vec::new());
        let manifest =
            RuleRepositoryManifest::from_bytes(&serde_json::to_vec(&raw).unwrap(), 256 * 1024)
                .unwrap();
        assert!(manifest.fingerprint_banks.is_empty());
        assert!(
            manifest
                .select_fingerprint_bank("stable", None, None)
                .is_none()
        );

        // A manifest published before the field existed must parse unchanged.
        let mut legacy: Value = serde_json::from_slice(&manifest_bytes()).unwrap();
        legacy.as_object_mut().unwrap().remove("fingerprintBanks");
        let manifest =
            RuleRepositoryManifest::from_bytes(&serde_json::to_vec(&legacy).unwrap(), 256 * 1024)
                .unwrap();
        assert!(manifest.fingerprint_banks.is_empty());
        assert_eq!(manifest.knowledge_packs.len(), 1);
    }

    #[test]
    fn shared_fingerprint_bank_descriptor_matches_its_document() {
        let manifest = RuleRepositoryManifest::from_bytes(&manifest_bytes(), 256 * 1024).unwrap();
        let Some(bank) = manifest.select_fingerprint_bank("stable", None, None) else {
            return;
        };
        assert_eq!(bank.id, "model-fingerprint-bank");
        let document = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../SanBiao")
            .join(&bank.path);
        assert_eq!(
            canonical_json_digest_bytes(&std::fs::read(document).unwrap()).unwrap(),
            bank.digest
        );
    }

    #[tokio::test]
    async fn fetches_the_fingerprint_bank_from_the_local_fallback_directory() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../SanBiao");
        let config = RuleRepositoryConfig::new("http://127.0.0.1:1/manifest.json", None, false)
            .unwrap()
            .with_fallback_directory(Some(root));
        let client = RuleRepositoryClient::new(config, "repository-fingerprint-test").unwrap();
        let manifest = client.fetch_manifest_with_source().await.unwrap();
        let Some(bank) = manifest.value.select_fingerprint_bank("stable", None, None) else {
            return;
        };
        let document = client
            .fetch_document_with_source(&bank.document())
            .await
            .unwrap();
        assert_eq!(document.source, RuleRepositorySource::LocalFallback);
        let parsed: Value = serde_json::from_slice(&document.value).unwrap();
        assert_eq!(parsed["id"], "model-fingerprint-bank");
        assert!(parsed["numeric"]["models"].as_array().unwrap().len() >= 18);
    }
}
