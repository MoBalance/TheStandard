use crate::{
    EvidenceSeverity, EvidenceStatus,
    rules::{OutcomeRule, RuleBundleError},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationRules {
    pub grade: GradeRules,
    pub skipped_summary: String,
    pub execution_errors: ExecutionErrorRules,
    pub identity: IdentityEvaluationRules,
    pub reasoning_attestation: ReasoningAttestationEvaluationRules,
    pub protocol: ProtocolEvaluationRules,
    pub context: ContextEvaluationRules,
    pub consistency: ConsistencyEvaluationRules,
    pub behavior_scenarios: GradedEvidenceRules,
    pub knowledge_challenges: KnowledgeEvaluationRules,
    pub document_understanding: DocumentEvaluationRules,
    pub tool_contract: GradedEvidenceRules,
    pub response_integrity: ResponseIntegrityEvaluationRules,
    pub relay_audit: RelayAuditEvaluationRules,
    pub identifiers: IdentifierEvaluationRules,
    pub cache_reuse: CacheReuseEvaluationRules,
    pub injection_overhead: InjectionOverheadEvaluationRules,
    pub knowledge_cutoff: KnowledgeCutoffEvaluationRules,
    pub web_search: WebSearchEvaluationRules,
    #[serde(rename = "reasoningIQ")]
    pub reasoning_iq: ReasoningIqEvaluationRules,
    pub thinking_chain: ThinkingChainEvaluationRules,
}

impl EvaluationRules {
    pub(crate) fn validate(&self) -> Result<(), RuleBundleError> {
        self.grade.validate()?;
        validate_text(&self.skipped_summary)?;
        self.execution_errors.validate()?;
        self.identity.validate()?;
        self.reasoning_attestation.validate()?;
        self.protocol.validate()?;
        self.context.validate()?;
        self.consistency.validate()?;
        self.behavior_scenarios.validate()?;
        self.knowledge_challenges.validate()?;
        self.document_understanding.validate()?;
        self.tool_contract.validate()?;
        self.response_integrity.validate()?;
        self.relay_audit.validate()?;
        self.identifiers.validate()?;
        self.cache_reuse.validate()?;
        self.injection_overhead.validate()?;
        self.knowledge_cutoff.validate()?;
        self.web_search.validate()?;
        self.reasoning_iq.validate()?;
        self.thinking_chain.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GradeRules {
    pub pass_minimum: f64,
    pub warn_minimum: f64,
}

impl GradeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if !(0.0..=100.0).contains(&self.warn_minimum)
            || !(0.0..=100.0).contains(&self.pass_minimum)
            || self.warn_minimum >= self.pass_minimum
        {
            return Err(RuleBundleError::Invalid(
                "invalid evidence grade thresholds",
            ));
        }
        Ok(())
    }

    pub(crate) fn status(&self, score: f64) -> EvidenceStatus {
        if score >= self.pass_minimum {
            EvidenceStatus::Pass
        } else if score >= self.warn_minimum {
            EvidenceStatus::Warn
        } else {
            EvidenceStatus::Fail
        }
    }

    pub(crate) fn severity(&self, score: f64) -> EvidenceSeverity {
        if score >= self.pass_minimum {
            EvidenceSeverity::Info
        } else if score >= self.warn_minimum {
            EvidenceSeverity::Minor
        } else {
            EvidenceSeverity::Major
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionErrorRules {
    pub failed_summary: String,
    pub partial_summary_suffix: String,
    pub confidence_multiplier: f64,
}

impl ExecutionErrorRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.failed_summary)?;
        validate_text(&self.partial_summary_suffix)?;
        validate_confidence(self.confidence_multiplier)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GradedEvidenceRules {
    pub display_name: String,
    pub weight: f64,
    pub summary: String,
    pub confidence: f64,
}

impl GradedEvidenceRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_text(&self.summary)?;
        validate_confidence(self.confidence)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub confidence: f64,
    pub metadata_points: f64,
    pub self_report_points: f64,
    pub provider_points: f64,
    pub matched_summary: String,
    pub partial_summary: String,
    pub mismatch_summary: String,
}

impl IdentityEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_confidence(self.confidence)?;
        for points in [
            self.metadata_points,
            self.self_report_points,
            self.provider_points,
        ] {
            validate_score(points)?;
        }
        if (self.metadata_points + self.self_report_points + self.provider_points - 100.0).abs()
            > f64::EPSILON
        {
            return Err(RuleBundleError::Invalid(
                "identity scoring points must total 100",
            ));
        }
        validate_text(&self.matched_summary)?;
        validate_text(&self.partial_summary)?;
        validate_text(&self.mismatch_summary)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningAttestationEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub minimum_opaque_length: usize,
    pub validated: ClassifiedOutcomeRule,
    pub plausible_unvalidated: ClassifiedOutcomeRule,
    pub malformed: ClassifiedOutcomeRule,
    pub missing: ClassifiedOutcomeRule,
}

impl ReasoningAttestationEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        if !(16..=16_384).contains(&self.minimum_opaque_length) {
            return Err(RuleBundleError::Invalid(
                "invalid opaque attestation length threshold",
            ));
        }
        for outcome in [
            &self.validated,
            &self.plausible_unvalidated,
            &self.malformed,
            &self.missing,
        ] {
            outcome.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub passed_summary: String,
    pub failed_summary: String,
    pub high_confidence_minimum_samples: usize,
    pub high_confidence: f64,
    pub base_confidence: f64,
}

impl ProtocolEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_text(&self.passed_summary)?;
        validate_text(&self.failed_summary)?;
        if !(1..=64).contains(&self.high_confidence_minimum_samples) {
            return Err(RuleBundleError::Invalid(
                "invalid protocol sample threshold",
            ));
        }
        validate_confidence(self.high_confidence)?;
        validate_confidence(self.base_confidence)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub growth_ratio_minimum: f64,
    pub growth_ratio_maximum: f64,
    pub fit_confidence_minimum: f64,
    pub cumulative_growth_ratio_threshold: f64,
    pub expected_overhead_maximum: i64,
    pub elevated_overhead_maximum: i64,
    pub echo_mismatch: ClassifiedOutcomeRule,
    pub usage_unavailable: ClassifiedOutcomeRule,
    pub gradient_mismatch: ClassifiedOutcomeRule,
    pub expected: ClassifiedOutcomeRule,
    pub elevated: ClassifiedOutcomeRule,
    pub high: ClassifiedOutcomeRule,
    pub unknown: ClassifiedOutcomeRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClassifiedOutcomeRule {
    pub score: f64,
    pub confidence: f64,
    pub severity: EvidenceSeverity,
    pub summary: String,
}

impl ClassifiedOutcomeRule {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if !(0.0..=100.0).contains(&self.score) {
            return Err(RuleBundleError::Invalid("invalid classified outcome score"));
        }
        validate_confidence(self.confidence)?;
        validate_text(&self.summary)
    }
}

impl ContextEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        if !(0.0..=4.0).contains(&self.growth_ratio_minimum)
            || !(0.0..=4.0).contains(&self.growth_ratio_maximum)
            || self.growth_ratio_minimum >= self.growth_ratio_maximum
            || !(0.0..=1.0).contains(&self.fit_confidence_minimum)
            || !(1.0..=10.0).contains(&self.cumulative_growth_ratio_threshold)
            || self.expected_overhead_maximum < 0
            || self.expected_overhead_maximum >= self.elevated_overhead_maximum
            || self.elevated_overhead_maximum > 100_000
        {
            return Err(RuleBundleError::Invalid(
                "invalid context evaluation thresholds",
            ));
        }
        for outcome in [
            &self.echo_mismatch,
            &self.usage_unavailable,
            &self.gradient_mismatch,
            &self.expected,
            &self.elevated,
            &self.high,
            &self.unknown,
        ] {
            outcome.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsistencyEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub summary: String,
    pub high_confidence_minimum_samples: usize,
    pub high_confidence: f64,
    pub base_confidence: f64,
    pub single_route_match_score: f64,
    pub repeated_route_points: f64,
    pub similarity_points: f64,
    pub output_stability_points: f64,
    pub stability_multiplier: f64,
}

impl ConsistencyEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_text(&self.summary)?;
        if !(1..=64).contains(&self.high_confidence_minimum_samples) {
            return Err(RuleBundleError::Invalid(
                "invalid consistency sample threshold",
            ));
        }
        validate_confidence(self.high_confidence)?;
        validate_confidence(self.base_confidence)?;
        validate_score(self.single_route_match_score)?;
        validate_score(self.repeated_route_points)?;
        validate_score(self.similarity_points)?;
        validate_score(self.output_stability_points)?;
        if !(0.0..=1.0).contains(&self.stability_multiplier)
            || self.repeated_route_points
                + (self.similarity_points + self.output_stability_points)
                    * self.stability_multiplier
                > 100.0 + f64::EPSILON
        {
            return Err(RuleBundleError::Invalid(
                "invalid consistency scoring weights",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeEvaluationRules {
    pub evidence: GradedEvidenceRules,
    pub standard_limit: usize,
    pub full_limit: usize,
    pub full_independent_limit: usize,
    pub default_uncertainty_terms: Vec<String>,
    pub invalid_pack_summary: String,
    pub not_found_summary: String,
    pub disabled_summary: String,
    pub registry_error_summary: String,
    pub missing_summary: String,
}

impl KnowledgeEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        self.evidence.validate()?;
        if !(1..=64).contains(&self.standard_limit)
            || self.full_limit < self.standard_limit
            || self.full_limit > 128
            || self.full_independent_limit == 0
            || self.full_independent_limit > self.full_limit
            || self.default_uncertainty_terms.is_empty()
            || self.default_uncertainty_terms.len() > 32
        {
            return Err(RuleBundleError::Invalid(
                "invalid knowledge evaluation limits",
            ));
        }
        for term in &self.default_uncertainty_terms {
            validate_short_text(term)?;
        }
        for summary in [
            &self.invalid_pack_summary,
            &self.not_found_summary,
            &self.disabled_summary,
            &self.registry_error_summary,
            &self.missing_summary,
        ] {
            validate_text(summary)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub unsupported_summary: String,
    pub recovered: OutcomeRule,
    pub accepted_without_marker: OutcomeRule,
    pub rejected: OutcomeRule,
}

impl DocumentEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_text(&self.unsupported_summary)?;
        self.recovered.validate()?;
        self.accepted_without_marker.validate()?;
        self.rejected.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseIntegrityEvaluationRules {
    pub evidence: GradedEvidenceRules,
    pub unsupported_summary: String,
    pub text_similarity_minimum: f64,
    pub minimum_chars_per_token: u64,
    pub maximum_chars_per_token: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAuditEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub confidence: f64,
    pub minimum_observations: usize,
    pub tool_mismatch_penalty: f64,
    pub model_mismatch_penalty: f64,
    pub stream_anomaly_penalty: f64,
    pub secret_marker_penalty: f64,
    pub insufficient_summary: String,
    pub clean_summary: String,
    pub anomaly_summary: String,
}

impl RelayAuditEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_confidence(self.confidence)?;
        if !(1..=128).contains(&self.minimum_observations) {
            return Err(RuleBundleError::Invalid(
                "invalid relay audit observation threshold",
            ));
        }
        for penalty in [
            self.tool_mismatch_penalty,
            self.model_mismatch_penalty,
            self.stream_anomaly_penalty,
            self.secret_marker_penalty,
        ] {
            validate_score(penalty)?;
        }
        if self.tool_mismatch_penalty
            + self.model_mismatch_penalty
            + self.stream_anomaly_penalty
            + self.secret_marker_penalty
            > 100.0
        {
            return Err(RuleBundleError::Invalid(
                "relay audit penalties must total at most 100",
            ));
        }
        validate_text(&self.insufficient_summary)?;
        validate_text(&self.clean_summary)?;
        validate_text(&self.anomaly_summary)
    }
}

impl ResponseIntegrityEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        self.evidence.validate()?;
        validate_text(&self.unsupported_summary)?;
        if !(0.0..=1.0).contains(&self.text_similarity_minimum)
            || self.minimum_chars_per_token == 0
            || self.minimum_chars_per_token > self.maximum_chars_per_token
            || self.maximum_chars_per_token > 1_000
        {
            return Err(RuleBundleError::Invalid(
                "invalid response-integrity thresholds",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentifierEvaluationRules {
    pub evidence: GradedEvidenceRules,
    pub unsupported_protocol_summary: String,
    pub unobserved_summary: String,
    pub message_prefix: String,
    pub client_tool_prefix: String,
    pub server_tool_prefix: String,
}

impl IdentifierEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        self.evidence.validate()?;
        validate_text(&self.unsupported_protocol_summary)?;
        validate_text(&self.unobserved_summary)?;
        for prefix in [
            &self.message_prefix,
            &self.client_tool_prefix,
            &self.server_tool_prefix,
        ] {
            if prefix.is_empty()
                || prefix.len() > 64
                || !prefix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(RuleBundleError::Invalid("invalid identifier prefix"));
            }
        }
        Ok(())
    }
}

/// Evaluation of the prompt-cache reuse chain.
///
/// The hit rate is reported for reference only. When the target does not
/// report any cache token accounting the evidence degrades to an unknown
/// result instead of a failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheReuseEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub confidence: f64,
    pub observed: ClassifiedOutcomeRule,
    pub absent: ClassifiedOutcomeRule,
    pub unsupported_summary: String,
}

impl CacheReuseEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_confidence(self.confidence)?;
        self.observed.validate()?;
        self.absent.validate()?;
        validate_text(&self.unsupported_summary)
    }
}

/// Evaluation of relay-added fixed input overhead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionOverheadEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub confidence: f64,
    pub expected_overhead_maximum: i64,
    pub elevated_overhead_maximum: i64,
    pub expected: ClassifiedOutcomeRule,
    pub elevated: ClassifiedOutcomeRule,
    pub high: ClassifiedOutcomeRule,
    pub unsupported_summary: String,
}

impl InjectionOverheadEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_confidence(self.confidence)?;
        if self.expected_overhead_maximum < 0
            || self.expected_overhead_maximum >= self.elevated_overhead_maximum
            || self.elevated_overhead_maximum > 100_000
        {
            return Err(RuleBundleError::Invalid(
                "invalid injection overhead thresholds",
            ));
        }
        self.expected.validate()?;
        self.elevated.validate()?;
        self.high.validate()?;
        validate_text(&self.unsupported_summary)
    }
}

/// Informational knowledge-cutoff evaluation.
///
/// The declared weight must be exactly `0.0`: a cutoff estimate is reported
/// for transparency and never enters any score.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeCutoffEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub confidence: f64,
    pub resolved_summary: String,
    pub unresolved_summary: String,
    pub exhausted_summary: String,
    pub invalidated_summary: String,
    pub unsupported_summary: String,
}

impl KnowledgeCutoffEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        if self.weight != 0.0 {
            return Err(RuleBundleError::Invalid(
                "knowledge cutoff evidence must have a zero weight",
            ));
        }
        validate_confidence(self.confidence)?;
        for summary in [
            &self.resolved_summary,
            &self.unresolved_summary,
            &self.exhausted_summary,
            &self.invalidated_summary,
            &self.unsupported_summary,
        ] {
            validate_text(summary)?;
        }
        Ok(())
    }
}

/// Evaluation of observed web-search execution and returned sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebSearchEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub confidence: f64,
    pub observed: ClassifiedOutcomeRule,
    pub unsupported_summary: String,
}

impl WebSearchEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        validate_confidence(self.confidence)?;
        self.observed.validate()?;
        validate_text(&self.unsupported_summary)
    }
}

/// Evaluation of the rule-scored reasoning IQ set.
///
/// Only fully answered questions enter the denominator. A refusal, a truncated
/// answer or unstructured noise downgrades the evidence instead of counting as
/// a wrong answer, and the declared weight may never exceed `0.08`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningIqEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub confidence: f64,
    pub minimum_answered: usize,
    pub summary_template: String,
    pub insufficient_summary: String,
    pub unsupported_summary: String,
}

impl ReasoningIqEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        if self.weight > MAX_REASONING_IQ_WEIGHT {
            return Err(RuleBundleError::Invalid(
                "reasoning IQ evidence weight must not exceed 0.08",
            ));
        }
        validate_confidence(self.confidence)?;
        if !(1..=crate::rules::REASONING_IQ_QUESTION_COUNT).contains(&self.minimum_answered) {
            return Err(RuleBundleError::Invalid(
                "invalid reasoning IQ answered-question threshold",
            ));
        }
        if ["{answered}", "{correct}", "{total}"]
            .iter()
            .any(|placeholder| !self.summary_template.contains(placeholder))
        {
            return Err(RuleBundleError::Invalid(
                "invalid reasoning IQ summary template",
            ));
        }
        validate_text(&self.summary_template)?;
        validate_text(&self.insufficient_summary)?;
        validate_text(&self.unsupported_summary)
    }
}

/// Evaluation of the returned thinking chain.
///
/// Thinking output only exists on the Anthropic messages protocol, so a
/// non-Claude target or a response without thinking fields is never a failure.
/// The declared weight may never exceed `0.05`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThinkingChainEvaluationRules {
    pub display_name: String,
    pub weight: f64,
    pub confidence: f64,
    pub observed: ClassifiedOutcomeRule,
    pub signature_missing: ClassifiedOutcomeRule,
    pub unsupported_summary: String,
    pub non_claude_summary: String,
    pub redacted_summary: String,
}

impl ThinkingChainEvaluationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        validate_text(&self.display_name)?;
        validate_weight(self.weight)?;
        if self.weight > MAX_THINKING_CHAIN_WEIGHT {
            return Err(RuleBundleError::Invalid(
                "thinking-chain evidence weight must not exceed 0.05",
            ));
        }
        validate_confidence(self.confidence)?;
        self.observed.validate()?;
        self.signature_missing.validate()?;
        validate_text(&self.unsupported_summary)?;
        validate_text(&self.non_claude_summary)?;
        validate_text(&self.redacted_summary)
    }
}

const MAX_REASONING_IQ_WEIGHT: f64 = 0.08;
const MAX_THINKING_CHAIN_WEIGHT: f64 = 0.05;
fn validate_score(value: f64) -> Result<(), RuleBundleError> {
    if !(0.0..=100.0).contains(&value) {
        return Err(RuleBundleError::Invalid("invalid evaluation score"));
    }
    Ok(())
}

fn validate_weight(value: f64) -> Result<(), RuleBundleError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(RuleBundleError::Invalid("invalid evidence weight"));
    }
    Ok(())
}

fn validate_confidence(value: f64) -> Result<(), RuleBundleError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(RuleBundleError::Invalid("invalid evidence confidence"));
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), RuleBundleError> {
    if value.is_empty() || value.len() > 2_000 {
        return Err(RuleBundleError::Invalid("invalid evaluation text"));
    }
    Ok(())
}

fn validate_short_text(value: &str) -> Result<(), RuleBundleError> {
    if value.is_empty() || value.len() > 160 {
        return Err(RuleBundleError::Invalid("invalid evaluation term"));
    }
    Ok(())
}
