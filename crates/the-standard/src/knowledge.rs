use crate::{
    ProbeRequest, RepositoryKnowledgePack, RepositoryTarget, RuleRepositoryClient,
    RuleRepositoryConfig, RuleRepositoryError, RuleRepositorySource,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

const PACK_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KnowledgeChallenge {
    id: String,
    prompt: String,
    expected_terms: Vec<String>,
    #[serde(default)]
    uncertainty_terms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackDocument {
    schema_version: u32,
    id: String,
    version: String,
    channel: String,
    published_at: DateTime<Utc>,
    targets: Vec<RepositoryTarget>,
    challenges: Vec<KnowledgeChallenge>,
}

enum ResolutionError {
    Unavailable,
    Invalid,
}

pub(crate) async fn prepare_knowledge_request(
    config: Option<&RuleRepositoryConfig>,
    request: &mut ProbeRequest,
) {
    let enabled = crate::rules::rules_from_request(request).is_some_and(|rules| {
        rules
            .probes
            .activation
            .knowledge_challenges
            .enabled(request.mode, request.protocol)
    });
    if !enabled || has_manual_pack(request) {
        return;
    }
    if request
        .parameters
        .get("knowledgeRepositoryEnabled")
        .and_then(Value::as_bool)
        == Some(false)
    {
        record_resolution(request, "disabled", None, None, None, None);
        return;
    }
    let Some(config) = config else {
        return;
    };
    match resolve(config, request).await {
        Ok(Some((descriptor, pack, release, manifest_source, document_source))) => apply_pack(
            request,
            descriptor,
            pack,
            &release,
            manifest_source,
            document_source,
        ),
        Ok(None) => record_resolution(request, "not_found", None, None, None, None),
        Err(ResolutionError::Unavailable) => record_resolution(
            request,
            "error",
            Some("repository_unavailable"),
            None,
            None,
            None,
        ),
        Err(ResolutionError::Invalid) => record_resolution(
            request,
            "error",
            Some("repository_invalid_document"),
            None,
            None,
            None,
        ),
    }
}

fn has_manual_pack(request: &ProbeRequest) -> bool {
    request
        .parameters
        .get("knowledgeChallenges")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
}

async fn resolve(
    config: &RuleRepositoryConfig,
    request: &ProbeRequest,
) -> Result<
    Option<(
        RepositoryKnowledgePack,
        PackDocument,
        String,
        RuleRepositorySource,
        RuleRepositorySource,
    )>,
    ResolutionError,
> {
    let client = RuleRepositoryClient::new(
        config.clone(),
        concat!("the-standard/", env!("CARGO_PKG_VERSION")),
    )
    .map_err(map_repository_error)?;
    let manifest = client
        .fetch_manifest_with_source()
        .await
        .map_err(map_repository_error)?;
    let channel = parameter_string(request, "knowledgePackChannel").unwrap_or("stable");
    let Some(descriptor) = manifest.value.select_knowledge_pack(
        request.protocol,
        request.model.trim(),
        parameter_string(request, "expectedProvider"),
        parameter_string(request, "knowledgePackId"),
        parameter_string(request, "knowledgePackVersion"),
        channel,
    ) else {
        return Ok(None);
    };
    let descriptor = descriptor.clone();
    let document = client
        .fetch_document_with_source(&descriptor.document())
        .await
        .map_err(map_repository_error)?;
    let pack: PackDocument =
        serde_json::from_slice(&document.value).map_err(|_| ResolutionError::Invalid)?;
    validate_pack(&pack, &descriptor)?;
    Ok(Some((
        descriptor,
        pack,
        manifest.value.release,
        manifest.source,
        document.source,
    )))
}

fn map_repository_error(error: RuleRepositoryError) -> ResolutionError {
    match error {
        RuleRepositoryError::Unavailable | RuleRepositoryError::Http(_) => {
            ResolutionError::Unavailable
        }
        _ => ResolutionError::Invalid,
    }
}

fn validate_pack(
    pack: &PackDocument,
    descriptor: &RepositoryKnowledgePack,
) -> Result<(), ResolutionError> {
    if pack.schema_version != PACK_SCHEMA_VERSION
        || pack.id != descriptor.id
        || pack.version != descriptor.version
        || pack.channel != descriptor.channel
        || pack.targets != descriptor.targets
        || pack.targets.is_empty()
        || pack.targets.len() > 64
        || pack.challenges.is_empty()
        || pack.challenges.len() > 64
    {
        return Err(ResolutionError::Invalid);
    }
    let mut ids = BTreeSet::new();
    for challenge in &pack.challenges {
        if !valid_identifier(&challenge.id)
            || !ids.insert(challenge.id.as_str())
            || challenge.prompt.trim().is_empty()
            || challenge.prompt.len() > 1_500
            || challenge.expected_terms.is_empty()
            || challenge.expected_terms.len() > 16
            || challenge
                .expected_terms
                .iter()
                .any(|term| term.is_empty() || term.len() > 256)
            || challenge.uncertainty_terms.len() > 16
            || challenge
                .uncertainty_terms
                .iter()
                .any(|term| term.is_empty() || term.len() > 256)
        {
            return Err(ResolutionError::Invalid);
        }
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'+' | b'-')
        })
}

fn apply_pack(
    request: &mut ProbeRequest,
    descriptor: RepositoryKnowledgePack,
    pack: PackDocument,
    repository_release: &str,
    manifest_source: RuleRepositorySource,
    document_source: RuleRepositorySource,
) {
    request.parameters.insert(
        "knowledgeChallenges".into(),
        json!(
            pack.challenges
                .iter()
                .map(|challenge| json!({
                    "id": challenge.id,
                    "prompt": challenge.prompt,
                    "expectedTerms": challenge.expected_terms,
                    "uncertaintyTerms": challenge.uncertainty_terms,
                }))
                .collect::<Vec<_>>()
        ),
    );
    request
        .parameters
        .insert("knowledgePackId".into(), json!(descriptor.id));
    request
        .parameters
        .insert("knowledgePackVersion".into(), json!(descriptor.version));
    request
        .parameters
        .insert("knowledgePackChannel".into(), json!(descriptor.channel));
    request
        .parameters
        .insert("knowledgePackDigest".into(), json!(descriptor.digest));
    record_resolution(
        request,
        "resolved",
        None,
        Some(repository_release),
        Some(manifest_source),
        Some(document_source),
    );
}

fn record_resolution(
    request: &mut ProbeRequest,
    status: &str,
    error: Option<&str>,
    repository_release: Option<&str>,
    manifest_source: Option<RuleRepositorySource>,
    document_source: Option<RuleRepositorySource>,
) {
    let mut resolution = BTreeMap::from([
        ("source".to_owned(), json!("repository")),
        ("status".to_owned(), json!(status)),
    ]);
    if let Some(error) = error {
        resolution.insert("error".into(), json!(error));
    }
    if let Some(release) = repository_release {
        resolution.insert("repositoryRelease".into(), json!(release));
    }
    if let Some(source) = manifest_source {
        resolution.insert("manifestSource".into(), json!(source));
    }
    if let Some(source) = document_source {
        resolution.insert("documentSource".into(), json!(source));
    }
    request
        .parameters
        .insert("knowledgePackResolution".into(), json!(resolution));
}

fn parameter_string<'a>(request: &'a ProbeRequest, key: &str) -> Option<&'a str> {
    request
        .parameters
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProbeMode, Protocol, repository::canonical_json_digest};
    use axum::{Json, Router, routing::get};
    use serde_json::json;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    fn request() -> ProbeRequest {
        ProbeRequest {
            base_url: "https://demo.example.com".into(),
            api_key: "demo-key".into(),
            model: "the-standard-demo-model".into(),
            protocol: Protocol::Anthropic,
            mode: ProbeMode::Standard,
            parameters: BTreeMap::from([("expectedProvider".into(), json!("the-standard"))]),
            sections: Vec::new(),
        }
    }

    fn pack() -> Value {
        json!({
            "schemaVersion": 1,
            "id": "sanbiao-demo-knowledge",
            "version": "2026.08.07.1",
            "channel": "stable",
            "publishedAt": "2026-08-07T00:00:00Z",
            "targets": [{
                "protocol": "anthropic",
                "provider": "the-standard",
                "model": "the-standard-demo-model"
            }],
            "challenges": [{
                "id": "fixture",
                "prompt": "Return TheStandard.",
                "expectedTerms": ["TheStandard"],
                "uncertaintyTerms": []
            }]
        })
    }

    async fn repository(pack: Value, digest: String) -> RuleRepositoryConfig {
        let pack_body = pack.clone();
        let manifest = json!({
            "repositorySchemaVersion": 1,
            "release": "2026.08.07.2",
            "coreRules": {
                "id": "the-standard",
                "version": "2026.08.07.2",
                "channel": "stable",
                "path": "rules/the-standard/stable.json",
                "digest": "sha256:4727dd564de20fd10c005cb3f18e4470f441fa1f246d0dd9fc448802b430905d"
            },
            "knowledgePacks": [{
                "id": "sanbiao-demo-knowledge",
                "version": "2026.08.07.1",
                "channel": "stable",
                "path": "packs/demo.json",
                "digest": digest,
                "targets": [{
                    "protocol": "anthropic",
                    "provider": "the-standard",
                    "model": "the-standard-demo-model"
                }]
            }]
        });
        let app = Router::new()
            .route(
                "/manifest.json",
                get(move || {
                    let manifest = manifest.clone();
                    async move { Json(manifest) }
                }),
            )
            .route(
                "/packs/demo.json",
                get(move || {
                    let pack = pack_body.clone();
                    async move { Json(pack) }
                }),
            );
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config =
            RuleRepositoryConfig::new(&format!("http://{address}/manifest.json"), None, false)
                .unwrap();
        config.request_timeout = Duration::from_secs(1);
        config
    }

    #[tokio::test]
    async fn resolves_and_injects_a_digest_verified_pack() {
        let pack = pack();
        let digest = canonical_json_digest(&pack).unwrap();
        let config = repository(pack, digest).await;
        let mut request = request();
        prepare_knowledge_request(Some(&config), &mut request).await;
        assert_eq!(
            request.parameters["knowledgePackResolution"]["status"],
            "resolved"
        );
        assert_eq!(
            request.parameters["knowledgePackResolution"]["source"],
            "repository"
        );
        assert_eq!(
            request.parameters["knowledgePackResolution"]["manifestSource"],
            "remote"
        );
        assert_eq!(
            request.parameters["knowledgePackResolution"]["documentSource"],
            "remote"
        );
        assert_eq!(
            request.parameters["knowledgePackId"],
            "sanbiao-demo-knowledge"
        );
        assert_eq!(
            request.parameters["knowledgeChallenges"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn rejects_digest_mismatch_without_injecting_challenges() {
        let config = repository(
            pack(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        )
        .await;
        let mut request = request();
        prepare_knowledge_request(Some(&config), &mut request).await;
        assert_eq!(
            request.parameters["knowledgePackResolution"]["error"],
            "repository_invalid_document"
        );
        assert!(!request.parameters.contains_key("knowledgeChallenges"));
    }

    #[tokio::test]
    async fn manual_challenges_bypass_the_repository() {
        let config = repository(pack(), "sha256:invalid".into()).await;
        let mut request = request();
        request.parameters.insert(
            "knowledgeChallenges".into(),
            json!([{"id":"manual","prompt":"Manual?","expectedTerms":["yes"]}]),
        );
        prepare_knowledge_request(Some(&config), &mut request).await;
        assert!(!request.parameters.contains_key("knowledgePackResolution"));
        assert_eq!(request.parameters["knowledgeChallenges"][0]["id"], "manual");
    }

    #[test]
    fn repository_config_requires_https_outside_explicit_development_mode() {
        assert!(
            RuleRepositoryConfig::new("http://rules.example/manifest.json", None, false).is_err()
        );
        assert!(
            RuleRepositoryConfig::new("https://rules.example/manifest.json", None, false).is_ok()
        );
        assert!(
            RuleRepositoryConfig::new("http://rules.internal/manifest.json", None, true).is_ok()
        );
    }
}
