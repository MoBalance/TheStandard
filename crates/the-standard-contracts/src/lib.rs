//! Stable wire contracts shared by TheStandard adapters and clients.
//!
//! This crate contains no detection algorithm, HTTP client, web framework, or
//! environment-variable access. Other languages can implement the same JSON
//! schema without depending on Rust internals.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const REPORT_SCHEMA_VERSION: u32 = 7;
pub const UI_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const PRESENTATION_SCHEMA_VERSION: u32 = 1;
pub const CORE_CAPABILITY_PROFILE: &str = "adaptive-evidence-v17";
pub const CORE_CAPABILITIES: &[&str] = &[
    "identity_evidence",
    "behavioral_scenario_evidence",
    "reasoning_attestation_evidence",
    "reasoning_budget_fingerprint_v3",
    "non_gpt_juice_guard_v4",
    "core_rule_bundle_v1",
    "direct_json_rule_repository",
    "rule_bundle_digest_verification",
    "rule_bundle_report_provenance",
    "model_route_consistency",
    "knowledge_challenge_packs",
    "knowledge_repository_resolution",
    "document_understanding",
    "tool_contract_adherence",
    "response_protocol_conformance",
    "stream_event_conformance",
    "stream_nonstream_integrity",
    "token_usage_plausibility",
    "identifier_conformance",
    "text_fingerprint_v2",
    "context_gradient",
    "input_token_overhead_estimation",
    "controlled_context_echo",
    "observed_inferred_unsupported_basis",
    "retry_backoff_telemetry",
    "bounded_probe_deadlines",
    "partial_timeout_evidence",
    "self_describing_presentation",
    "runtime_progress_jobs",
    "context_request_isolation",
    "relay_payload_integrity_v1",
    "section_selection_v1",
    "evidence_coverage_ratio_v1",
    "reasoning_iq_evidence_v1",
    "reasoning_iq_scoring_version_v1",
    "thinking_chain_evidence_v1",
    "rule_repository_source_provenance",
];

pub const JSON_RPC_VERSION: &str = "2.0";
pub const RPC_METHOD_CORE_INFO: &str = "core.info";
pub const RPC_METHOD_CORE_DETECT: &str = "core.detect";
pub const RPC_METHOD_CORE_MANIFEST: &str = "core.manifest";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CoreUiManifest {
    pub schema_version: u32,
    pub language: String,
    pub request: ProbeRequestManifest,
    pub presentation: PresentationContract,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRequestManifest {
    pub submit_label: String,
    pub fields: Vec<ProbeInputField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeInputField {
    pub id: String,
    pub json_pointer: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub control: String,
    pub required: bool,
    pub sensitive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    pub default_value: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<ProbeInputOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeInputOption {
    pub value: Value,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PresentationContract {
    pub schema_version: u32,
    pub supported_layouts: Vec<String>,
    pub supported_formats: Vec<String>,
    pub unknown_hint_fallback: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Anthropic,
    Openai,
    Gemini,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMode {
    Quick,
    #[default]
    Standard,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreBuildInfo {
    pub name: String,
    pub version: String,
    pub report_schema_version: u32,
    pub capability_profile: String,
    pub capabilities: Vec<String>,
    pub supported_protocols: Vec<Protocol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRequest {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub mode: ProbeMode,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, Value>,
    /// Optional section selection. Empty means every default-enabled section,
    /// which is identical to the behavior of releases before 0.1.1013.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Identity,
    Behavior,
    ReasoningAttestation,
    ReasoningBudget,
    Knowledge,
    Document,
    ToolContract,
    Protocol,
    Context,
    Consistency,
    StreamIntegrity,
    LongOutput,
    CacheReuse,
    InjectionOverhead,
    KnowledgeCutoff,
    WebSearch,
    ReasoningIq,
    ThinkingChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StreamEventObservation {
    pub event: String,
    pub elapsed_ms: u64,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContextProbeMetadata {
    pub audit_id: String,
    pub level: usize,
    pub controlled_units: usize,
    pub controlled_bytes: usize,
    pub visible_input_token_estimate: u64,
    pub expects_exact_echo: bool,
    pub request_body_bytes: usize,
    pub message_count: usize,
    pub request_fingerprint: String,
    pub independent_request: bool,
}

impl ContextProbeMetadata {
    pub fn begin_marker(&self) -> String {
        format!("THE_STANDARD_CONTEXT_{}_BEGIN", self.audit_id)
    }

    pub fn end_marker(&self) -> String {
        format!("THE_STANDARD_CONTEXT_{}_END", self.audit_id)
    }

    pub fn controlled_context(&self) -> String {
        (0..self.controlled_units)
            .map(|index| {
                format!(
                    "THE_STANDARD_UNIT_{index:04}_{}_amber_cobalt_lumen_vector",
                    self.audit_id
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeObservation {
    pub kind: ProbeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    pub status_code: u16,
    pub latency_ms: u64,
    pub ttft_ms: Option<u64>,
    pub response: Value,
    pub text: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub response_headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream_events: Vec<StreamEventObservation>,
    #[serde(default)]
    pub usage: UsageMetrics,
    #[serde(default)]
    pub retry_count: usize,
    #[serde(default)]
    pub backoff_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<ContextProbeMetadata>,
}

impl ProbeObservation {
    pub fn fixture(
        kind: ProbeKind,
        status_code: u16,
        response: Value,
        text: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            challenge_id: None,
            status_code,
            latency_ms: 0,
            ttft_ms: None,
            response,
            text: text.into(),
            response_headers: BTreeMap::new(),
            stream_events: Vec::new(),
            usage: UsageMetrics::default(),
            retry_count: 0,
            backoff_count: 0,
            context: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageMetrics {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub cache_read_input_tokens: u64,
    #[serde(default)]
    pub cache_creation_input_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_extensions: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceMetrics {
    pub request_count: usize,
    pub total_latency_ms: u64,
    pub average_latency_ms: u64,
    pub ttft_ms: Option<u64>,
    pub tokens_per_second: Option<f64>,
    pub retry_count: usize,
    pub backoff_count: usize,
    pub usage: UsageMetrics,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContextOverheadAssessment {
    Expected,
    Elevated,
    High,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContextEchoStatus {
    Exact,
    Mismatch,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextAuditSample {
    pub level: usize,
    pub controlled_units: usize,
    pub controlled_bytes: usize,
    pub visible_input_token_estimate: u64,
    pub reported_input_tokens: Option<u64>,
    pub estimated_input_overhead_tokens: Option<i64>,
    pub exact_echo_requested: bool,
    pub request_body_bytes: usize,
    pub message_count: usize,
    pub request_fingerprint: String,
    pub independent_request: bool,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextAuditSummary {
    pub sample_count: usize,
    pub samples: Vec<ContextAuditSample>,
    pub usage_available: bool,
    pub monotonic_growth: Option<bool>,
    pub growth_ratio: Option<f64>,
    pub fit_confidence: Option<f64>,
    pub estimated_fixed_overhead_tokens: Option<i64>,
    pub overhead_assessment: ContextOverheadAssessment,
    pub final_echo_status: ContextEchoStatus,
    pub controlled_context_confirmed: bool,
    pub independent_requests: bool,
    pub unique_request_fingerprints: bool,
    pub cumulative_history_suspected: Option<bool>,
    pub cache_hit_observed: bool,
    pub accounting_interpretation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCategory {
    Authenticity,
    Capability,
    Protocol,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Pass,
    Warn,
    Fail,
    Error,
    Skip,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBasis {
    Observed,
    #[default]
    Inferred,
    Unsupported,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSeverity {
    Info,
    Minor,
    Major,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectorEvidence {
    pub name: String,
    pub display_name: String,
    pub category: EvidenceCategory,
    pub status: EvidenceStatus,
    pub severity: EvidenceSeverity,
    #[serde(default)]
    pub basis: EvidenceBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub score: f64,
    pub weight: f64,
    pub summary: String,
    #[serde(default)]
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Verified,
    Inconclusive,
    Rejected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionTier {
    Cryptographic,
    Protocol,
    Behavioral,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionTarget {
    pub base_url: String,
    pub api_key_masked: String,
    pub model: String,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleRepositorySource {
    Remote,
    LocalFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleRepositoryProvenance {
    pub release: String,
    pub manifest_source: RuleRepositorySource,
    pub document_source: RuleRepositorySource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleBundleProvenance {
    pub id: String,
    pub version: String,
    pub channel: String,
    pub published_at: DateTime<Utc>,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RuleRepositoryProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionReport {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub core: CoreBuildInfo,
    pub rules: RuleBundleProvenance,
    pub target: DetectionTarget,
    pub mode: ProbeMode,
    pub total_score: f64,
    /// Always-present evidence coverage. It never changes `total_score` or the
    /// verdict; it only states how much of the applicable detector weight was
    /// actually verified.
    pub coverage: EvidenceCoverage,
    pub verdict: Verdict,
    pub tier: DetectionTier,
    pub tier_message: String,
    pub evidence: Vec<DetectorEvidence>,
    pub performance: PerformanceMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_audit: Option<ContextAuditSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation: Option<ReportPresentation>,
    /// Present only when the request selected an explicit subset of detection
    /// sections. It marks that this report is not directly comparable with a
    /// default detection, because the weighted score covers fewer detectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_selection: Option<ReportSectionSelection>,
}

/// How much of the applicable detector weight produced a verdict.
///
/// `verified_weight` is the weighted-average denominator of `total_score`,
/// `applicable_weight` adds the skipped and errored detectors, and `ratio`
/// is `verified_weight / applicable_weight` rounded to four decimals. An
/// unknown detector lowers coverage; it never fails a detection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceCoverage {
    pub verified_weight: f64,
    pub applicable_weight: f64,
    pub ratio: f64,
    pub unverified_count: usize,
}

/// Provenance of an explicit detection-section selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReportSectionSelection {
    pub requested: Vec<String>,
    pub not_selected: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventStatus {
    Info,
    Running,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DetectionRuntimeEvent {
    pub sequence: u64,
    pub elapsed_ms: u64,
    pub stage: String,
    pub event: String,
    pub status: RuntimeEventStatus,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionJobStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionJobSnapshot {
    pub id: String,
    pub status: DetectionJobStatus,
    pub created_at: DateTime<Utc>,
    pub model: String,
    pub protocol: Protocol,
    pub mode: ProbeMode,
    pub events: Vec<DetectionRuntimeEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<DetectionReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CoreApiError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReportPresentation {
    pub schema_version: u32,
    pub language: String,
    pub views: Vec<PresentationView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PresentationView {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub sections: Vec<PresentationSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PresentationSection {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub layout: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<PresentationField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<PresentationRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PresentationField {
    pub key: String,
    pub label: String,
    pub value: Value,
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PresentationRow {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub fields: Vec<PresentationField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreServiceHealth {
    pub status: String,
    pub service: String,
    pub service_version: String,
    pub core: CoreBuildInfo,
    pub rules: CoreRuleRuntimeHealth,
    pub runtime: CoreRuntimeHealth,
    pub transports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreRuleRuntimeHealth {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<RuleBundleProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreRuntimeHealth {
    pub service: CoreRuntimeServiceHealth,
    pub engine: CoreRuntimeEngineHealth,
    pub transport: CoreRuntimeTransportHealth,
    pub rules: CoreRuntimeRuleHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreRuntimeServiceHealth {
    pub max_inflight_detections: usize,
    pub max_request_body_bytes: usize,
    pub shutdown_grace_seconds: u64,
    pub target_dns_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreRuntimeEngineHealth {
    pub request_timeout_ms: u64,
    pub max_retries: usize,
    pub retry_backoff_ms: u64,
    pub max_concurrent: usize,
    pub quick_timeout_ms: u64,
    pub standard_timeout_ms: u64,
    pub full_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreRuntimeTransportHealth {
    pub max_response_bytes: usize,
    pub max_stream_bytes: usize,
    pub max_stream_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreRuntimeRuleHealth {
    pub refresh_interval_seconds: u64,
    pub request_timeout_ms: u64,
    pub max_manifest_bytes: usize,
    pub max_document_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoreApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            jsonrpc: JSON_RPC_VERSION.into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::{
        CORE_CAPABILITIES, CORE_CAPABILITY_PROFILE, ContextProbeMetadata, EvidenceCoverage,
        JSON_RPC_VERSION, JsonRpcResponse, ProbeMode, ProbeRequest, Protocol,
        REPORT_SCHEMA_VERSION, ReportSectionSelection,
    };
    use serde_json::{Value, json};

    #[test]
    fn request_and_rpc_contracts_have_stable_json_shapes() {
        let request = ProbeRequest {
            base_url: "https://api.example.com".into(),
            api_key: "secret".into(),
            model: "model-a".into(),
            protocol: Protocol::Openai,
            mode: ProbeMode::Standard,
            parameters: [("temperature".into(), json!(0.2))].into(),
            sections: Vec::new(),
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["baseUrl"], "https://api.example.com");
        assert_eq!(value["protocol"], "openai");
        assert_eq!(value["mode"], "standard");
        assert_eq!(value["parameters"]["temperature"], 0.2);
        assert!(value.get("sections").is_none());
        let selected = ProbeRequest {
            sections: vec!["identity".into()],
            ..request
        };
        assert_eq!(
            serde_json::to_value(selected).unwrap()["sections"],
            json!(["identity"])
        );

        let rpc = JsonRpcResponse::success(Value::String("01TEST".into()), json!({"ok": true}));
        let value = serde_json::to_value(rpc).unwrap();
        assert_eq!(value["jsonrpc"], JSON_RPC_VERSION);
        assert!(value.get("error").is_none());
        assert_eq!(REPORT_SCHEMA_VERSION, 7);
    }

    #[test]
    fn section_selection_is_an_optional_report_field() {
        let selection = ReportSectionSelection {
            requested: vec!["identity".into()],
            not_selected: vec!["tools".into(), "knowledge".into()],
        };
        let value = serde_json::to_value(&selection).unwrap();
        assert_eq!(value["requested"], json!(["identity"]));
        assert_eq!(value["notSelected"], json!(["tools", "knowledge"]));
        assert!(value.get("not_selected").is_none());
    }

    #[test]
    fn evidence_coverage_is_an_always_present_report_field() {
        let coverage = EvidenceCoverage {
            verified_weight: 12.5,
            applicable_weight: 18.0,
            ratio: 0.6944,
            unverified_count: 2,
        };
        let value = serde_json::to_value(coverage).unwrap();
        assert_eq!(value["verifiedWeight"], 12.5);
        assert_eq!(value["applicableWeight"], 18.0);
        assert_eq!(value["ratio"], 0.6944);
        assert_eq!(value["unverifiedCount"], 2);
        assert!(value.get("verified_weight").is_none());
        // Version-agnostic: the profile must keep its shape and can only move
        // forward, so a bump never breaks this contract test.
        let level = CORE_CAPABILITY_PROFILE
            .strip_prefix("adaptive-evidence-v")
            .expect("the capability profile keeps its adaptive-evidence prefix");
        assert!(level.parse::<u32>().expect("the profile ends in a number") > 0);
        for capability in [
            "evidence_coverage_ratio_v1",
            "reasoning_iq_evidence_v1",
            "reasoning_iq_scoring_version_v1",
            "thinking_chain_evidence_v1",
        ] {
            assert!(
                CORE_CAPABILITIES.contains(&capability),
                "missing {capability}"
            );
        }
    }

    #[test]
    fn context_markers_use_the_standard_identity() {
        let metadata = ContextProbeMetadata {
            audit_id: "01TEST".into(),
            level: 0,
            controlled_units: 1,
            controlled_bytes: 0,
            visible_input_token_estimate: 0,
            expects_exact_echo: true,
            request_body_bytes: 0,
            message_count: 1,
            request_fingerprint: "sha256:test".into(),
            independent_request: true,
        };

        assert_eq!(metadata.begin_marker(), "THE_STANDARD_CONTEXT_01TEST_BEGIN");
        assert_eq!(metadata.end_marker(), "THE_STANDARD_CONTEXT_01TEST_END");
        assert_eq!(
            metadata.controlled_context(),
            "THE_STANDARD_UNIT_0000_01TEST_amber_cobalt_lumen_vector"
        );
    }
}
