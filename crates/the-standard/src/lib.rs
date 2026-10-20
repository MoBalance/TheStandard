//! TheStandard model-probe orchestration and evidence scoring engine.
//!
//! The crate does not read environment variables and does not depend on a web
//! framework, database, or cache. Callers provide configuration and transport.

pub mod config;
pub mod engine;
pub mod knowledge;
pub mod model;
pub mod presentation;
pub mod probe;
pub mod repository;
pub mod rule_evaluation;
pub mod rules;
pub mod signature;

pub use config::{EngineConfig, HttpTransportConfig, ProbeMode, RuleRepositoryConfig};
pub use engine::{Engine, RuntimeObserver};
pub use model::core_build_info;
pub use presentation::{core_ui_manifest, report_presentation};
pub use probe::{
    DemoTransport, HttpTransport, OutboundProbe, ProbeStrategy, ProbeTransport,
    ReasoningBudgetStrategy,
};
pub use repository::{
    RepositoryDocument, RepositoryFetch, RepositoryKnowledgePack, RepositoryTarget,
    RuleRepositoryClient, RuleRepositoryError, RuleRepositoryManifest,
};
pub use rules::{
    CoreRuleBundle, ResolvedSections, RuleBundleError, SectionRule, SectionRules,
    SectionSelectionError,
};
pub use wire_contracts::{
    CORE_CAPABILITIES, CORE_CAPABILITY_PROFILE, ContextAuditSample, ContextAuditSummary,
    ContextEchoStatus, ContextOverheadAssessment, ContextProbeMetadata, CoreApiError,
    CoreBuildInfo, CoreRuleRuntimeHealth, CoreRuntimeEngineHealth, CoreRuntimeHealth,
    CoreRuntimeRuleHealth, CoreRuntimeServiceHealth, CoreRuntimeTransportHealth, CoreServiceHealth,
    CoreUiManifest, DetectionJobSnapshot, DetectionJobStatus, DetectionReport,
    DetectionRuntimeEvent, DetectionTarget, DetectionTier, DetectorEvidence, EvidenceBasis,
    EvidenceCategory, EvidenceCoverage, EvidenceSeverity, EvidenceStatus, JSON_RPC_VERSION,
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, PRESENTATION_SCHEMA_VERSION, PerformanceMetrics,
    PresentationContract, PresentationField, PresentationRow, PresentationSection,
    PresentationView, ProbeInputField, ProbeInputOption, ProbeKind, ProbeObservation, ProbeRequest,
    ProbeRequestManifest, Protocol, REPORT_SCHEMA_VERSION, RPC_METHOD_CORE_DETECT,
    RPC_METHOD_CORE_INFO, RPC_METHOD_CORE_MANIFEST, ReportPresentation, ReportSectionSelection,
    RuleBundleProvenance, RuleRepositoryProvenance, RuleRepositorySource, RuntimeEventStatus,
    StreamEventObservation, UI_MANIFEST_SCHEMA_VERSION, UsageMetrics, Verdict,
};

/// Errors returned by probe construction, transport, and report aggregation.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("invalid detection section selection: {0}")]
    InvalidSections(String),
    #[error("probe transport failed: {0}")]
    Transport(String),
    #[error("upstream response could not be parsed: {0}")]
    Parse(String),
    #[error("no probe observations were collected")]
    NoObservations,
    #[error("detection exceeded its overall timeout of {0:?}")]
    OverallTimeout(std::time::Duration),
    #[error("no validated Core rule bundle is available")]
    RulesUnavailable,
}
