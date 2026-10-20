use crate::repository::{RepositoryDocument, canonical_json_digest};
use crate::rule_evaluation::EvaluationRules;
use crate::{ProbeMode, ProbeRequest, Protocol};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use thiserror::Error;
use wire_contracts::{RuleBundleProvenance, RuleRepositoryProvenance};

const RULE_BUNDLE_SCHEMA_VERSION: u32 = 1;
const CORE_RULE_PAYLOAD_SCHEMA_VERSION: u32 = 2;
const INTERNAL_RULE_BUNDLE_KEY: &str = "_theStandardRuleBundle";
const INTERNAL_RULE_STATUS_KEY: &str = "_theStandardRuleStatus";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuleBundleDocument {
    schema_version: u32,
    id: String,
    version: String,
    channel: String,
    published_at: DateTime<Utc>,
    payload: CoreRules,
}

#[derive(Debug, Clone)]
pub struct CoreRuleBundle {
    pub provenance: RuleBundleProvenance,
    pub rules: CoreRules,
}

impl CoreRuleBundle {
    pub fn from_document(
        bytes: &[u8],
        source_revision: Option<String>,
    ) -> Result<Self, RuleBundleError> {
        if bytes.len() > 1024 * 1024 {
            return Err(RuleBundleError::TooLarge);
        }
        let raw_document: Value = serde_json::from_slice(bytes)?;
        let document: RuleBundleDocument = serde_json::from_value(raw_document.clone())?;
        if document.schema_version != RULE_BUNDLE_SCHEMA_VERSION
            || document.id != "the-standard"
            || source_revision.as_deref().is_some_and(|revision| {
                revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(RuleBundleError::Invalid(
                "rule metadata or source revision is invalid",
            ));
        }
        document.payload.validate()?;
        let digest = canonical_json_digest(&raw_document)?;
        Ok(Self {
            provenance: RuleBundleProvenance {
                id: document.id,
                version: document.version,
                channel: document.channel,
                published_at: document.published_at,
                digest,
                source_revision,
                repository: None,
            },
            rules: document.payload,
        })
    }

    pub fn from_repository_document(
        bytes: &[u8],
        descriptor: &RepositoryDocument,
        source_revision: Option<String>,
        repository: RuleRepositoryProvenance,
    ) -> Result<Self, RuleBundleError> {
        let mut bundle = Self::from_document(bytes, source_revision)?;
        if bundle.provenance.id != descriptor.id
            || bundle.provenance.version != descriptor.version
            || bundle.provenance.channel != descriptor.channel
            || bundle.provenance.digest != descriptor.digest
        {
            return Err(RuleBundleError::Invalid(
                "rule document does not match its repository descriptor",
            ));
        }
        bundle.provenance.repository = Some(repository);
        Ok(bundle)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoreRules {
    pub payload_schema_version: u32,
    pub engine: EngineRules,
    pub probes: ProbeRules,
    pub evaluation: EvaluationRules,
    pub strategies: StrategyRules,
    #[serde(default)]
    pub sections: Option<SectionRules>,
}

impl CoreRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.payload_schema_version != CORE_RULE_PAYLOAD_SCHEMA_VERSION {
            return Err(RuleBundleError::Invalid(
                "unsupported Core rule payload schema",
            ));
        }
        self.engine.validate()?;
        self.probes.validate()?;
        self.evaluation.validate()?;
        self.strategies.reasoning_budget_fingerprint.validate()?;
        if let Some(sections) = &self.sections {
            sections.validate()?;
        }
        Ok(())
    }
}

/// Declared detection sections.
///
/// A section groups engine strategies under a stable identifier so a caller can
/// run a subset of a detection without changing the scoring formula.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SectionRules {
    pub default_enabled: Vec<String>,
    pub items: Vec<SectionRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SectionRule {
    pub id: String,
    pub label: String,
    pub description: String,
    pub strategies: Vec<String>,
}

impl SectionRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.items.is_empty() || self.default_enabled.is_empty() {
            return Err(RuleBundleError::Invalid(
                "detection sections must not be empty",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut claimed = BTreeMap::new();
        for item in &self.items {
            validate_section_id(&item.id)?;
            if !ids.insert(item.id.clone()) {
                return Err(RuleBundleError::Invalid(
                    "duplicate detection section identifier",
                ));
            }
            if item.label.trim().is_empty() || item.label.len() > 120 {
                return Err(RuleBundleError::Invalid("invalid detection section label"));
            }
            if item.description.trim().is_empty() || item.description.len() > 600 {
                return Err(RuleBundleError::Invalid(
                    "invalid detection section description",
                ));
            }
            if item.strategies.is_empty() {
                return Err(RuleBundleError::Invalid(
                    "detection section must claim at least one strategy",
                ));
            }
            for strategy in &item.strategies {
                if !crate::probe::PROBE_STRATEGY_NAMES.contains(&strategy.as_str()) {
                    return Err(RuleBundleError::Invalid(
                        "detection section claims an unknown strategy",
                    ));
                }
                if claimed.insert(strategy.clone(), item.id.clone()).is_some() {
                    return Err(RuleBundleError::Invalid(
                        "strategy is claimed by more than one detection section",
                    ));
                }
            }
        }
        for strategy in crate::probe::PROBE_STRATEGY_NAMES {
            if !claimed.contains_key(*strategy) {
                return Err(RuleBundleError::Invalid(
                    "detection sections must claim every engine strategy",
                ));
            }
        }
        let mut enabled = BTreeSet::new();
        for id in &self.default_enabled {
            if !ids.contains(id) || !enabled.insert(id.clone()) {
                return Err(RuleBundleError::Invalid(
                    "default detection section is unknown or duplicated",
                ));
            }
        }
        Ok(())
    }

    fn declared_ids(&self) -> Vec<String> {
        self.items.iter().map(|item| item.id.clone()).collect()
    }

    fn item(&self, id: &str) -> Option<&SectionRule> {
        self.items.iter().find(|item| item.id == id)
    }
}

/// A validated section selection for one detection request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSections {
    /// Selected section identifiers in declaration order.
    pub requested: Vec<String>,
    /// Declared sections the request excluded, in declaration order.
    pub not_selected: Vec<String>,
    /// Strategy names the engine may run for this request.
    pub allowed_strategies: BTreeSet<String>,
    /// True when the caller did not request an explicit subset.
    pub default_selection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SectionSelectionError {
    #[error("the active rule bundle does not declare detection sections")]
    Unavailable,
    #[error("unknown detection section: {0}")]
    Unknown(String),
}

impl CoreRules {
    /// Resolves a requested section subset against the declared sections.
    ///
    /// `Ok(None)` means the rule bundle declares no sections at all, so every
    /// strategy runs and the request is not section-restricted.
    pub fn resolve_sections(
        &self,
        requested: &[String],
    ) -> Result<Option<ResolvedSections>, SectionSelectionError> {
        let Some(sections) = &self.sections else {
            return if requested.is_empty() {
                Ok(None)
            } else {
                Err(SectionSelectionError::Unavailable)
            };
        };
        let declared = sections.declared_ids();
        let selected: Vec<String> = if requested.is_empty() {
            declared
                .iter()
                .filter(|id| sections.default_enabled.contains(id))
                .cloned()
                .collect()
        } else {
            let unknown: BTreeSet<String> = requested
                .iter()
                .filter(|id| !declared.contains(id))
                .cloned()
                .collect();
            if !unknown.is_empty() {
                return Err(SectionSelectionError::Unknown(
                    unknown.into_iter().collect::<Vec<_>>().join(", "),
                ));
            }
            declared
                .iter()
                .filter(|id| requested.contains(id))
                .cloned()
                .collect()
        };
        let not_selected = declared
            .iter()
            .filter(|id| !selected.contains(id))
            .cloned()
            .collect();
        let mut allowed_strategies = BTreeSet::new();
        for id in &selected {
            if let Some(item) = sections.item(id) {
                allowed_strategies.extend(item.strategies.iter().cloned());
            }
        }
        // A strategy no section claims always runs, so adding an engine strategy
        // can never be silently dropped by a caller's older selection.
        for strategy in crate::probe::PROBE_STRATEGY_NAMES {
            let claimed = sections
                .items
                .iter()
                .any(|item| item.strategies.iter().any(|value| value == strategy));
            if !claimed {
                allowed_strategies.insert((*strategy).to_string());
            }
        }
        Ok(Some(ResolvedSections {
            requested: selected,
            not_selected,
            allowed_strategies,
            default_selection: requested.is_empty(),
        }))
    }
}

fn validate_section_id(value: &str) -> Result<(), RuleBundleError> {
    let mut characters = value.chars();
    let valid = matches!(characters.next(), Some(first) if first.is_ascii_alphabetic())
        && value.len() <= 40
        && characters.all(|character| character.is_ascii_alphanumeric());
    if !valid {
        return Err(RuleBundleError::Invalid(
            "detection section identifier is invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeRules {
    pub activation: ProbeActivationRules,
    pub identity: IdentityProbeRules,
    pub reasoning_attestation: ReasoningAttestationRules,
    pub behavior_scenarios: Vec<BehaviorScenarioRule>,
    pub knowledge: KnowledgeProbeRules,
    pub document_prompt: String,
    pub tool_contract: ToolContractRules,
    pub response_integrity: ResponseIntegrityRules,
    pub relay_audit: RelayAuditProbeRules,
    pub consistency: ConsistencyProbeRules,
    pub context: ContextProbeRules,
    pub cache: CacheReuseProbeRules,
    pub injection: InjectionOverheadProbeRules,
    pub knowledge_cutoff: KnowledgeCutoffProbeRules,
    pub web_search: WebSearchProbeRules,
    #[serde(rename = "reasoningIQ")]
    pub reasoning_iq: ReasoningIqProbeRules,
    pub thinking_chain: ThinkingChainProbeRules,
}

impl ProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        self.activation.validate()?;
        self.identity.validate()?;
        self.reasoning_attestation.validate()?;
        self.knowledge.validate()?;
        self.tool_contract.validate()?;
        self.response_integrity.validate()?;
        self.relay_audit.validate()?;
        self.consistency.validate()?;
        self.context.validate()?;
        self.cache.validate()?;
        self.injection.validate()?;
        self.knowledge_cutoff.validate()?;
        self.web_search.validate()?;
        self.reasoning_iq.validate()?;
        self.thinking_chain.validate()?;
        if self.behavior_scenarios.is_empty()
            || self.behavior_scenarios.len() > 32
            || self.document_prompt.is_empty()
            || self.document_prompt.len() > 1_500
        {
            return Err(RuleBundleError::Invalid("invalid probe rules"));
        }
        let mut behavior_ids = BTreeSet::new();
        for scenario in &self.behavior_scenarios {
            if !valid_id(&scenario.id, 80)
                || !behavior_ids.insert(scenario.id.as_str())
                || scenario.prompt.is_empty()
                || scenario.prompt.len() > 1_500
                || scenario.demo_response.is_empty()
                || scenario.demo_response.len() > 2_000
            {
                return Err(RuleBundleError::Invalid("invalid behavior scenario"));
            }
            scenario.expectation.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeActivationRules {
    pub behavior_scenarios: ActivationRule,
    pub knowledge_challenges: ActivationRule,
    pub document_understanding: ActivationRule,
    pub tool_contract: ActivationRule,
    pub tool_strict: ActivationRule,
    pub response_integrity: ActivationRule,
    pub relay_audit: ActivationRule,
    pub long_output: ActivationRule,
    pub cache: ActivationRule,
    pub injection: ActivationRule,
    pub knowledge_cutoff: ActivationRule,
    pub web_search: ActivationRule,
    #[serde(rename = "reasoningIQ")]
    pub reasoning_iq: ActivationRule,
    pub thinking_chain: ActivationRule,
}

impl ProbeActivationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        for activation in [
            &self.behavior_scenarios,
            &self.knowledge_challenges,
            &self.document_understanding,
            &self.tool_contract,
            &self.response_integrity,
            &self.relay_audit,
            &self.long_output,
            &self.cache,
            &self.injection,
            &self.knowledge_cutoff,
            &self.web_search,
            &self.reasoning_iq,
            &self.thinking_chain,
        ] {
            activation.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayAuditProbeRules {
    pub secret_markers: Vec<String>,
}

impl RelayAuditProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.secret_markers.is_empty() || self.secret_markers.len() > 32 {
            return Err(RuleBundleError::Invalid("invalid relay audit markers"));
        }
        if self
            .secret_markers
            .iter()
            .any(|marker| marker.trim().is_empty() || marker.len() > 80 || !marker.is_ascii())
        {
            return Err(RuleBundleError::Invalid("invalid relay audit marker"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActivationRule {
    pub modes: Vec<ProbeMode>,
    pub protocols: Vec<Protocol>,
}

impl ActivationRule {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.modes.is_empty()
            || self.modes.len() > 3
            || self.protocols.is_empty()
            || self.protocols.len() > 3
            || has_duplicates(&self.modes)
            || has_duplicates(&self.protocols)
        {
            return Err(RuleBundleError::Invalid("invalid probe activation rule"));
        }
        Ok(())
    }

    pub(crate) fn enabled(&self, mode: ProbeMode, protocol: Protocol) -> bool {
        self.modes.contains(&mode) && self.protocols.contains(&protocol)
    }
}

fn has_duplicates<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .any(|(index, item)| items[..index].contains(item))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityProbeRules {
    pub prompt: String,
    pub demo_response_template: String,
    pub families: Vec<IdentityFamilyRule>,
}

impl IdentityProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        let mut markers = BTreeSet::new();
        if self.prompt.is_empty()
            || self.prompt.len() > 1_500
            || !["{model}", "{family}", "{provider}"]
                .iter()
                .all(|placeholder| self.demo_response_template.contains(placeholder))
            || self.demo_response_template.len() > 2_000
            || self.families.is_empty()
            || self.families.len() > 32
            || self.families.iter().any(|family| {
                !valid_id(&family.marker, 80)
                    || !valid_id(&family.provider, 80)
                    || !markers.insert(family.marker.as_str())
                    || family.marker != family.marker.to_ascii_lowercase()
            })
        {
            return Err(RuleBundleError::Invalid("invalid identity rules"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityFamilyRule {
    pub marker: String,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningAttestationRules {
    pub prompt: String,
    pub follow_up_prompt: String,
    pub demo_response: String,
    pub demo_follow_up_response: String,
    pub adaptive_model_markers: Vec<String>,
    pub adaptive_max_tokens: u32,
    pub default_max_tokens: u32,
    pub default_budget_tokens: u32,
    pub follow_up_max_tokens: u32,
}

impl ReasoningAttestationRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.prompt.is_empty()
            || self.prompt.len() > 1_500
            || self.follow_up_prompt.is_empty()
            || self.follow_up_prompt.len() > 1_500
            || self.demo_response.is_empty()
            || self.demo_response.len() > 2_000
            || self.demo_follow_up_response.is_empty()
            || self.demo_follow_up_response.len() > 2_000
            || self.adaptive_model_markers.is_empty()
            || self.adaptive_model_markers.len() > 16
            || self
                .adaptive_model_markers
                .iter()
                .any(|marker| !valid_id(marker, 80))
            || !(1..=128_000).contains(&self.adaptive_max_tokens)
            || !(1..=128_000).contains(&self.default_max_tokens)
            || !(1..=128_000).contains(&self.default_budget_tokens)
            || !(1..=4_096).contains(&self.follow_up_max_tokens)
        {
            return Err(RuleBundleError::Invalid(
                "invalid reasoning attestation rules",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BehaviorScenarioRule {
    pub id: String,
    pub prompt: String,
    pub demo_response: String,
    pub expectation: BehaviorExpectation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum BehaviorExpectation {
    PrefixWithoutTerms {
        prefix: String,
        forbidden_terms: Vec<String>,
    },
    ExactText {
        value: String,
    },
    JsonFields {
        fields: BTreeMap<String, serde_json::Value>,
    },
    ContainsAny {
        terms: Vec<String>,
    },
}

impl BehaviorExpectation {
    fn validate(&self) -> Result<(), RuleBundleError> {
        match self {
            Self::PrefixWithoutTerms {
                prefix,
                forbidden_terms,
            } => {
                validate_rule_terms(std::slice::from_ref(prefix))?;
                validate_rule_terms(forbidden_terms)
            }
            Self::ExactText { value } => {
                if value.is_empty() || value.len() > 2_000 {
                    return Err(RuleBundleError::Invalid(
                        "invalid exact behavior expectation",
                    ));
                }
                Ok(())
            }
            Self::JsonFields { fields } => {
                if fields.is_empty()
                    || fields.len() > 32
                    || fields.keys().any(|key| !valid_id(key, 80))
                    || serde_json::to_vec(fields).is_ok_and(|bytes| bytes.len() > 4_096)
                {
                    return Err(RuleBundleError::Invalid(
                        "invalid JSON behavior expectation",
                    ));
                }
                Ok(())
            }
            Self::ContainsAny { terms } => validate_rule_terms(terms),
        }
    }
}

fn validate_rule_terms(terms: &[String]) -> Result<(), RuleBundleError> {
    if terms.is_empty()
        || terms.len() > 32
        || terms.iter().any(|term| term.is_empty() || term.len() > 160)
    {
        return Err(RuleBundleError::Invalid(
            "invalid behavior expectation terms",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeProbeRules {
    pub question_prefix: String,
    pub batch_template: String,
    pub demo_response: String,
}

impl KnowledgeProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.question_prefix.is_empty()
            || self.question_prefix.len() > 1_000
            || self.batch_template.is_empty()
            || self.batch_template.len() > 2_000
            || !self.batch_template.contains("{items}")
            || self.demo_response.is_empty()
            || self.demo_response.len() > 2_000
        {
            return Err(RuleBundleError::Invalid("invalid knowledge probe rules"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolContractRules {
    pub prompt: String,
    pub description: String,
    pub region: String,
    pub region_options: Vec<String>,
    pub priority: i64,
    pub priority_minimum: i64,
    pub priority_maximum: i64,
}

impl ToolContractRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if !self.prompt.contains("{region}")
            || !self.prompt.contains("{priority}")
            || self.prompt.len() > 1_500
            || self.description.is_empty()
            || self.description.len() > 500
            || !valid_id(&self.region, 80)
            || self.region_options.is_empty()
            || self.region_options.len() > 16
            || !self.region_options.contains(&self.region)
            || self.priority_minimum > self.priority
            || self.priority > self.priority_maximum
            || self.priority_minimum < -1_000
            || self.priority_maximum > 1_000
        {
            return Err(RuleBundleError::Invalid("invalid tool contract rules"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseIntegrityRules {
    pub equivalence_prompt: String,
    pub demo_equivalence_response: String,
    pub long_output_prompt_template: String,
    pub demo_long_output_template: String,
    pub long_output_max_tokens: u32,
    pub deterministic_sampling_excluded_model_markers: Vec<String>,
}

impl ResponseIntegrityRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.equivalence_prompt.is_empty()
            || self.equivalence_prompt.len() > 1_500
            || self.demo_equivalence_response.is_empty()
            || self.demo_equivalence_response.len() > 2_000
            || !self.long_output_prompt_template.contains("{marker}")
            || self.long_output_prompt_template.len() > 2_000
            || !self.demo_long_output_template.contains("{marker}")
            || self.demo_long_output_template.len() > 5_000
            || !(1..=128_000).contains(&self.long_output_max_tokens)
            || !valid_markers(&self.deterministic_sampling_excluded_model_markers)
        {
            return Err(RuleBundleError::Invalid("invalid response integrity rules"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsistencyProbeRules {
    pub prompt: String,
    pub demo_response: String,
    pub samples: ModeSampleCounts,
    pub deterministic_sampling_excluded_model_markers: Vec<String>,
}

impl ConsistencyProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.prompt.is_empty()
            || self.prompt.len() > 1_500
            || self.demo_response.is_empty()
            || self.demo_response.len() > 2_000
            || !valid_markers(&self.deterministic_sampling_excluded_model_markers)
        {
            return Err(RuleBundleError::Invalid("invalid consistency probe rules"));
        }
        self.samples.validate_counts()?;
        if self.samples.quick == 0 || self.samples.standard == 0 || self.samples.full == 0 {
            return Err(RuleBundleError::Invalid(
                "consistency sample counts must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextProbeRules {
    pub final_instruction: String,
    pub intermediate_instruction: String,
    pub prompt_template: String,
    pub gradient_units: ModeUnitLevels,
    pub final_bytes_per_token: u64,
    pub final_base_tokens: u64,
    pub final_minimum_tokens: u64,
    pub final_maximum_tokens: u64,
    pub intermediate_max_tokens: u64,
}

impl ContextProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        let placeholders = [
            "{responseInstruction}",
            "{auditId}",
            "{level}",
            "{controlledUnits}",
            "{beginMarker}",
            "{controlledContext}",
            "{endMarker}",
        ];
        if self.final_instruction.is_empty()
            || self.final_instruction.len() > 2_000
            || self.intermediate_instruction.is_empty()
            || self.intermediate_instruction.len() > 2_000
            || self.prompt_template.len() > 5_000
            || !placeholders
                .iter()
                .all(|placeholder| self.prompt_template.contains(placeholder))
            || self.final_bytes_per_token == 0
            || self.final_bytes_per_token > 32
            || self.final_base_tokens > 16_384
            || self.final_minimum_tokens == 0
            || self.final_minimum_tokens > self.final_maximum_tokens
            || self.final_maximum_tokens > 128_000
            || self.intermediate_max_tokens == 0
            || self.intermediate_max_tokens > 16_384
        {
            return Err(RuleBundleError::Invalid("invalid context probe rules"));
        }
        self.gradient_units.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModeUnitLevels {
    pub quick: Vec<usize>,
    pub standard: Vec<usize>,
    pub full: Vec<usize>,
}

impl ModeUnitLevels {
    fn validate(&self) -> Result<(), RuleBundleError> {
        for levels in [&self.quick, &self.standard, &self.full] {
            if !(2..=16).contains(&levels.len())
                || levels.first() != Some(&0)
                || levels.iter().any(|level| *level > 100_000)
                || levels.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(RuleBundleError::Invalid("invalid context gradient levels"));
            }
        }
        Ok(())
    }

    pub(crate) fn for_mode(&self, mode: ProbeMode) -> &[usize] {
        match mode {
            ProbeMode::Quick => &self.quick,
            ProbeMode::Standard => &self.standard,
            ProbeMode::Full => &self.full,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CacheReuseProbeRules {
    pub rounds: usize,
    pub max_tokens: u32,
    pub prefix_units: usize,
    pub prefix_unit_template: String,
    pub round_instruction_template: String,
    pub read_pointers: Vec<String>,
    pub write_pointers: Vec<String>,
}

impl CacheReuseProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if !(2..=8).contains(&self.rounds)
            || !(1..=4_096).contains(&self.max_tokens)
            || !(1..=1_024).contains(&self.prefix_units)
            || !self.prefix_unit_template.contains("{index}")
            || self.prefix_unit_template.len() > 512
            || !self.round_instruction_template.contains("{round}")
            || self.round_instruction_template.len() > 1_000
            || !valid_pointer_list(&self.read_pointers)
            || !valid_pointer_list(&self.write_pointers)
        {
            return Err(RuleBundleError::Invalid("invalid cache reuse probe rules"));
        }
        Ok(())
    }

    /// The deterministic shared prefix repeated by every cache round.
    pub(crate) fn prefix(&self) -> String {
        (0..self.prefix_units)
            .map(|index| {
                self.prefix_unit_template
                    .replace("{index}", &index.to_string())
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InjectionOverheadProbeRules {
    pub baseline_prompt: String,
    pub wrapped_prompt: String,
    pub expected_extra_tokens: i64,
    pub max_tokens: u32,
}

impl InjectionOverheadProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.baseline_prompt.is_empty()
            || self.baseline_prompt.len() > 1_500
            || self.wrapped_prompt.is_empty()
            || self.wrapped_prompt.len() > 4_096
            || self.wrapped_prompt == self.baseline_prompt
            || !(0..=4_096).contains(&self.expected_extra_tokens)
            || !(1..=4_096).contains(&self.max_tokens)
        {
            return Err(RuleBundleError::Invalid(
                "invalid injection overhead probe rules",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeCutoffProbeRules {
    pub max_questions: usize,
    pub max_tokens: u32,
    pub window: KnowledgeCutoffWindow,
    pub prompt_template: String,
    pub choice_line_template: String,
    pub invalidated_markers: Vec<String>,
    pub anchors: Vec<KnowledgeCutoffAnchor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeCutoffWindow {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeCutoffAnchor {
    pub id: String,
    pub date: String,
    pub event: String,
    pub question: String,
    pub choices: Vec<KnowledgeCutoffChoice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeCutoffChoice {
    pub letter: String,
    pub text: String,
    pub kind: KnowledgeCutoffChoiceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeCutoffChoiceKind {
    /// The event happened; answering this raises the lower bound.
    Known,
    /// The target only knows the schedule or is unsure; this lowers the upper bound.
    Unknown,
    /// A distractor; it never moves either bound.
    Wrong,
}

impl KnowledgeCutoffAnchor {
    pub(crate) fn parsed_date(&self) -> Option<NaiveDate> {
        NaiveDate::parse_from_str(&self.date, "%Y-%m-%d").ok()
    }
}

impl KnowledgeCutoffProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if !(1..=10).contains(&self.max_questions)
            || !(1..=4_096).contains(&self.max_tokens)
            || !self.prompt_template.contains("{question}")
            || !self.prompt_template.contains("{choices}")
            || self.prompt_template.len() > 4_000
            || !self.choice_line_template.contains("{letter}")
            || !self.choice_line_template.contains("{text}")
            || self.choice_line_template.len() > 200
            || self.invalidated_markers.is_empty()
            || self.invalidated_markers.len() > 32
            || self
                .invalidated_markers
                .iter()
                .any(|marker| marker.trim().is_empty() || marker.len() > 160)
            || self.anchors.is_empty()
            || self.anchors.len() > 32
        {
            return Err(RuleBundleError::Invalid(
                "invalid knowledge cutoff probe rules",
            ));
        }
        let Some(from) = NaiveDate::parse_from_str(&self.window.from, "%Y-%m-%d").ok() else {
            return Err(RuleBundleError::Invalid("invalid knowledge cutoff window"));
        };
        let Some(to) = NaiveDate::parse_from_str(&self.window.to, "%Y-%m-%d").ok() else {
            return Err(RuleBundleError::Invalid("invalid knowledge cutoff window"));
        };
        if from >= to {
            return Err(RuleBundleError::Invalid("invalid knowledge cutoff window"));
        }
        let mut ids = BTreeSet::new();
        for anchor in &self.anchors {
            if !valid_id(&anchor.id, 80)
                || !ids.insert(anchor.id.as_str())
                || anchor.event.trim().is_empty()
                || anchor.event.len() > 200
                || anchor.question.trim().is_empty()
                || anchor.question.len() > 400
            {
                return Err(RuleBundleError::Invalid("invalid knowledge cutoff anchor"));
            }
            let Some(date) = anchor.parsed_date() else {
                return Err(RuleBundleError::Invalid("invalid knowledge cutoff anchor"));
            };
            if date < from || date > to {
                return Err(RuleBundleError::Invalid(
                    "knowledge cutoff anchor is outside the declared window",
                ));
            }
            if anchor.choices.len() != 4 {
                return Err(RuleBundleError::Invalid(
                    "knowledge cutoff anchor must declare four choices",
                ));
            }
            let mut letters = BTreeSet::new();
            let mut known = 0;
            let mut unknown = 0;
            for choice in &anchor.choices {
                if choice.text.trim().is_empty()
                    || choice.text.len() > 200
                    || !matches!(choice.letter.as_str(), "A" | "B" | "C" | "D")
                    || !letters.insert(choice.letter.as_str())
                {
                    return Err(RuleBundleError::Invalid("invalid knowledge cutoff choice"));
                }
                match choice.kind {
                    KnowledgeCutoffChoiceKind::Known => known += 1,
                    KnowledgeCutoffChoiceKind::Unknown => unknown += 1,
                    KnowledgeCutoffChoiceKind::Wrong => {}
                }
            }
            if known != 1 || unknown == 0 {
                return Err(RuleBundleError::Invalid(
                    "knowledge cutoff anchor needs one known and at least one unknown choice",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebSearchProbeRules {
    pub prompt: String,
    pub max_tokens: u32,
    pub source_url_keys: Vec<String>,
    pub execution_markers: Vec<String>,
    pub protocols: Vec<WebSearchProtocolRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebSearchProtocolRule {
    pub protocol: Protocol,
    pub mode: String,
    pub body_patch: BTreeMap<String, Value>,
}

impl WebSearchProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.prompt.trim().is_empty()
            || self.prompt.len() > 1_500
            || !(1..=4_096).contains(&self.max_tokens)
            || !valid_key_list(&self.source_url_keys)
            || !valid_key_list(&self.execution_markers)
            || self.protocols.is_empty()
            || self.protocols.len() > 3
        {
            return Err(RuleBundleError::Invalid("invalid web search probe rules"));
        }
        let mut protocols: Vec<Protocol> = Vec::new();
        for entry in &self.protocols {
            if protocols.contains(&entry.protocol)
                || !matches!(entry.mode.as_str(), "native_tool" | "deepseek_tools_search")
                || entry.body_patch.is_empty()
                || serde_json::to_vec(&entry.body_patch).is_ok_and(|bytes| bytes.len() > 4_096)
            {
                return Err(RuleBundleError::Invalid("invalid web search protocol rule"));
            }
            protocols.push(entry.protocol);
        }
        Ok(())
    }

    pub(crate) fn protocol_rule(&self, protocol: Protocol) -> Option<&WebSearchProtocolRule> {
        self.protocols
            .iter()
            .find(|entry| entry.protocol == protocol)
    }
}

/// Rule-declared facts for the reasoning-IQ probe.
///
/// Every question must be verifiable and have exactly one correct answer, so a
/// score never depends on an opinion. `scoringVersion` travels with the report:
/// an older report keeps its own question set and is never rescored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningIqProbeRules {
    pub scoring_version: String,
    pub max_tokens: u32,
    pub prompt_template: String,
    pub answer_formats: ReasoningIqAnswerFormats,
    pub refusal_markers: Vec<String>,
    pub truncation_stop_reasons: Vec<String>,
    pub questions: Vec<ReasoningIqQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningIqAnswerFormats {
    pub integer: String,
    pub string: String,
    pub choice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningIqQuestion {
    pub id: String,
    pub prompt: String,
    pub answer_type: ReasoningIqAnswerType,
    pub expected: String,
    #[serde(default)]
    pub tolerance: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningIqAnswerType {
    Integer,
    String,
    Choice,
}

/// The fixed question count of the reasoning-IQ section.
pub(crate) const REASONING_IQ_QUESTION_COUNT: usize = 8;

impl ReasoningIqAnswerFormats {
    pub(crate) fn for_type(&self, answer_type: ReasoningIqAnswerType) -> &str {
        match answer_type {
            ReasoningIqAnswerType::Integer => &self.integer,
            ReasoningIqAnswerType::String => &self.string,
            ReasoningIqAnswerType::Choice => &self.choice,
        }
    }

    fn validate(&self) -> Result<(), RuleBundleError> {
        for format in [&self.integer, &self.string, &self.choice] {
            if format.trim().is_empty() || format.len() > 300 {
                return Err(RuleBundleError::Invalid(
                    "invalid reasoning IQ answer format",
                ));
            }
        }
        Ok(())
    }
}

impl ReasoningIqQuestion {
    /// The answer key used by the uniqueness rule.
    ///
    /// Answers must be unique per answer type: two integer questions may not
    /// share an expected value, while an integer and a word may share a
    /// spelling because they are judged differently.
    fn answer_key(&self) -> (ReasoningIqAnswerType, String) {
        (self.answer_type, self.expected.trim().to_ascii_lowercase())
    }

    /// Whether `expected` is a well-formed answer for its declared type.
    fn expected_is_parsable(&self) -> bool {
        match self.answer_type {
            ReasoningIqAnswerType::Integer => {
                self.expected.parse::<i64>().is_ok() && (0..=1_000).contains(&self.tolerance)
            }
            ReasoningIqAnswerType::String => {
                self.tolerance == 0
                    && self.expected.len() <= 80
                    && self
                        .expected
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            }
            ReasoningIqAnswerType::Choice => {
                self.tolerance == 0
                    && self.expected.len() == 1
                    && self.expected.bytes().all(|byte| byte.is_ascii_uppercase())
            }
        }
    }
}

impl ReasoningIqProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if !valid_id(&self.scoring_version, 40)
            || !(1..=4_096).contains(&self.max_tokens)
            || !self.prompt_template.contains("{question}")
            || !self.prompt_template.contains("{answerFormat}")
            || self.prompt_template.len() > 4_096
            || self.refusal_markers.is_empty()
            || self.refusal_markers.len() > 16
            || self
                .refusal_markers
                .iter()
                .any(|marker| marker.trim().is_empty() || marker.len() > 120)
            || !valid_key_list(&self.truncation_stop_reasons)
            || self.questions.len() != REASONING_IQ_QUESTION_COUNT
        {
            return Err(RuleBundleError::Invalid("invalid reasoning IQ rules"));
        }
        self.answer_formats.validate()?;
        let mut ids = BTreeSet::new();
        let mut answers = BTreeSet::new();
        for question in &self.questions {
            if !valid_id(&question.id, 40)
                || !ids.insert(question.id.as_str())
                || question.prompt.trim().is_empty()
                || question.prompt.len() > 600
                || question.expected.trim().is_empty()
                || question.expected.len() > 80
                || question.tolerance < 0
                || !question.expected_is_parsable()
                || !answers.insert(question.answer_key())
            {
                return Err(RuleBundleError::Invalid("invalid reasoning IQ question"));
            }
        }
        Ok(())
    }
}

/// Rule-declared facts for the thinking-chain probe.
///
/// Thinking output is only defined by the Anthropic messages protocol, and the
/// rule block says so in its own `limitations`: every other protocol is
/// unobservable and is therefore never scored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThinkingChainProbeRules {
    pub prompt: String,
    pub thinking_type: String,
    pub budget_tokens: u32,
    pub max_tokens: u32,
    pub thinking_block_types: Vec<String>,
    pub redacted_block_types: Vec<String>,
    pub content_type_key: String,
    pub text_key: String,
    pub signature_key: String,
    pub summary_maximum_chars: usize,
    pub full_text_minimum_chars: usize,
    pub non_claude_model_markers: Vec<String>,
    pub modes: ThinkingChainModes,
    pub limitations: Vec<String>,
}

/// The `mode` labels reported for an observed thinking response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThinkingChainModes {
    pub summary: String,
    pub full_text: String,
    pub redacted: String,
    pub absent: String,
}

impl ThinkingChainModes {
    fn validate(&self) -> Result<(), RuleBundleError> {
        let modes = [&self.summary, &self.full_text, &self.redacted, &self.absent];
        let mut unique = BTreeSet::new();
        if modes
            .iter()
            .any(|mode| !valid_id(mode, 40) || !unique.insert(mode.as_str()))
        {
            return Err(RuleBundleError::Invalid(
                "invalid thinking-chain mode labels",
            ));
        }
        Ok(())
    }
}

impl ThinkingChainProbeRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if self.prompt.trim().is_empty()
            || self.prompt.len() > 1_500
            || !matches!(self.thinking_type.as_str(), "enabled" | "adaptive")
            || self.budget_tokens == 0
            || !(1..=128_000).contains(&self.max_tokens)
            || self.max_tokens <= self.budget_tokens
            || !valid_key_list(&self.thinking_block_types)
            || !valid_key_list(&self.redacted_block_types)
            || !valid_id(&self.content_type_key, 40)
            || !valid_id(&self.text_key, 40)
            || !valid_id(&self.signature_key, 40)
            || !(16..20_000).contains(&self.summary_maximum_chars)
            || self.summary_maximum_chars >= self.full_text_minimum_chars
            || self.full_text_minimum_chars > 40_000
            || !valid_markers(&self.non_claude_model_markers)
            || self.limitations.is_empty()
            || self.limitations.len() > 16
            || self
                .limitations
                .iter()
                .any(|item| item.trim().is_empty() || item.len() > 512)
        {
            return Err(RuleBundleError::Invalid(
                "invalid thinking-chain probe rules",
            ));
        }
        self.modes.validate()
    }
}
fn valid_pointer_list(pointers: &[String]) -> bool {
    !pointers.is_empty()
        && pointers.len() <= 8
        && pointers.iter().all(|pointer| {
            pointer.starts_with('/')
                && pointer.len() <= 160
                && pointer
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b' ')
        })
}

fn valid_key_list(keys: &[String]) -> bool {
    !keys.is_empty()
        && keys.len() <= 16
        && keys
            .iter()
            .all(|key| !key.trim().is_empty() && key.len() <= 80)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineRules {
    pub verified_threshold: f64,
    pub inconclusive_threshold: f64,
    pub tier_messages: TierMessages,
}

impl EngineRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if !(0.0..=100.0).contains(&self.inconclusive_threshold)
            || !(0.0..=100.0).contains(&self.verified_threshold)
            || self.inconclusive_threshold >= self.verified_threshold
            || self.tier_messages.cryptographic.is_empty()
            || self.tier_messages.cryptographic.len() > 1_000
            || self.tier_messages.protocol.is_empty()
            || self.tier_messages.protocol.len() > 1_000
            || self.tier_messages.behavioral.is_empty()
            || self.tier_messages.behavioral.len() > 1_000
        {
            return Err(RuleBundleError::Invalid("invalid engine thresholds"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TierMessages {
    pub cryptographic: String,
    pub protocol: String,
    pub behavioral: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StrategyRules {
    pub reasoning_budget_fingerprint: JuiceRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuiceRules {
    pub display_name: String,
    pub non_gpt_display_name: String,
    pub skipped_summary: String,
    pub gpt_model_markers: Vec<String>,
    pub gpt_protocol: String,
    pub max_output_tokens: u32,
    pub primary_effort: String,
    pub primary_minimum_samples: usize,
    pub calibration: JuiceCalibrationRules,
    pub plans: JuicePlans,
    pub templates: Vec<JuiceTemplate>,
    pub prompt_template: String,
    pub non_gpt: NonGptJuiceRules,
    pub demo: DemoJuiceRules,
    pub families: Vec<JuiceFamilyRule>,
    pub scoring: JuiceScoring,
    pub limitations: Vec<String>,
}

impl JuiceRules {
    fn validate(&self) -> Result<(), RuleBundleError> {
        let valid_efforts = ["low", "medium", "high", "xhigh", "max"];
        if self.display_name.is_empty()
            || self.display_name.len() > 200
            || self.non_gpt_display_name.is_empty()
            || self.non_gpt_display_name.len() > 200
            || self.skipped_summary.is_empty()
            || self.skipped_summary.len() > 1_000
            || self.gpt_model_markers.is_empty()
            || self.gpt_model_markers.len() > 16
            || self.gpt_model_markers.iter().any(|marker| {
                marker.is_empty() || marker.len() > 64 || marker != &marker.to_ascii_lowercase()
            })
            || self.gpt_protocol != "openai"
            || !(1..=4096).contains(&self.max_output_tokens)
            || !valid_efforts.contains(&self.primary_effort.as_str())
            || !(1..=8).contains(&self.primary_minimum_samples)
            || self.templates.is_empty()
            || self.templates.len() > 8
            || self.prompt_template.len() > 4_096
            || !["{sampleId}", "{transformation}", "{effort}"]
                .iter()
                .all(|placeholder| self.prompt_template.contains(placeholder))
            || self.non_gpt.prompt.is_empty()
            || self.non_gpt.prompt.len() > 4_096
            || self.demo.non_gpt_response.len() > 1_000
            || self.families.is_empty()
            || self.families.len() > 64
            || self.limitations.is_empty()
            || self.limitations.len() > 16
            || self
                .limitations
                .iter()
                .any(|item| item.is_empty() || item.len() > 512)
        {
            return Err(RuleBundleError::Invalid("invalid Juice rule metadata"));
        }
        self.plans.validate(&valid_efforts)?;
        self.non_gpt.samples.validate_counts()?;
        self.demo.validate(&valid_efforts)?;
        self.scoring.validate()?;

        let mut template_ids = BTreeSet::new();
        for template in &self.templates {
            if !valid_id(&template.id, 80)
                || !template_ids.insert(template.id.as_str())
                || template.transformation.is_empty()
                || template.transformation.len() > 512
            {
                return Err(RuleBundleError::Invalid("invalid Juice template"));
            }
        }
        let max_samples = self
            .plans
            .quick
            .iter()
            .chain(&self.plans.standard)
            .chain(&self.plans.full)
            .map(|entry| entry.samples)
            .max()
            .unwrap_or_default();
        if max_samples > self.templates.len() {
            return Err(RuleBundleError::Invalid(
                "a Juice plan requests more samples than templates",
            ));
        }

        let mut family_ids = BTreeSet::new();
        for family in &self.families {
            if !valid_id(&family.id, 160)
                || !family_ids.insert(family.id.as_str())
                || !matches!(
                    family.calibration_state.as_str(),
                    "confirmed" | "partial" | "historical" | "unstable"
                )
                || family.matches.is_empty()
                || family.matches.len() > 16
            {
                return Err(RuleBundleError::Invalid("invalid Juice family"));
            }
            let mut efforts = BTreeSet::new();
            for matcher in &family.matches {
                if !valid_efforts.contains(&matcher.effort.as_str())
                    || !efforts.insert(matcher.effort.as_str())
                    || matcher.values.len() + matcher.prefixes.len() == 0
                    || matcher.values.len() + matcher.prefixes.len() > 16
                    || matcher
                        .values
                        .iter()
                        .chain(&matcher.prefixes)
                        .any(|value| !valid_decimal_rule(value))
                {
                    return Err(RuleBundleError::Invalid("invalid Juice matcher"));
                }
            }
        }
        self.calibration
            .validate(&valid_efforts, &family_ids, self)?;
        Ok(())
    }

    pub(crate) fn plan(&self, mode: ProbeMode) -> &[JuicePlanEntry] {
        match mode {
            ProbeMode::Quick => &self.plans.quick,
            ProbeMode::Standard => &self.plans.standard,
            ProbeMode::Full => &self.plans.full,
        }
    }

    pub(crate) fn is_gpt_model(&self, model: &str) -> bool {
        let model = model.to_ascii_lowercase();
        self.gpt_model_markers
            .iter()
            .any(|marker| model.contains(marker))
    }

    pub(crate) fn families_for(&self, effort: &str, value: &str) -> Vec<String> {
        self.families
            .iter()
            .filter(|family| family.classification_enabled)
            .filter(|family| {
                family.matches.iter().any(|matcher| {
                    matcher.effort == effort
                        && (matcher.values.iter().any(|item| item == value)
                            || matcher
                                .prefixes
                                .iter()
                                .any(|prefix| value.starts_with(prefix)))
                })
            })
            .map(|family| family.id.clone())
            .collect()
    }

    pub(crate) fn family_calibration_state(&self, family_id: &str) -> Option<&str> {
        self.families
            .iter()
            .find(|family| family.id == family_id)
            .map(|family| family.calibration_state.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuiceCalibrationRules {
    pub revision: String,
    pub completed_at: DateTime<Utc>,
    pub method: String,
    pub independent_runs: usize,
    pub templates_per_effort: usize,
    pub independent_requests: bool,
    pub conversation_history_reused: bool,
    pub accepted_values: Vec<JuiceCalibrationValue>,
    pub unresolved: Vec<String>,
}

impl JuiceCalibrationRules {
    fn validate(
        &self,
        valid_efforts: &[&str],
        family_ids: &BTreeSet<&str>,
        rules: &JuiceRules,
    ) -> Result<(), RuleBundleError> {
        if !valid_id(&self.revision, 160)
            || self.method.is_empty()
            || self.method.len() > 512
            || !(2..=16).contains(&self.independent_runs)
            || !(1..=8).contains(&self.templates_per_effort)
            || !self.independent_requests
            || self.conversation_history_reused
            || self.accepted_values.is_empty()
            || self.accepted_values.len() > 64
            || self.unresolved.len() > 16
            || self
                .unresolved
                .iter()
                .any(|item| item.is_empty() || item.len() > 512)
        {
            return Err(RuleBundleError::Invalid(
                "invalid Juice calibration provenance",
            ));
        }

        let mut accepted = BTreeSet::new();
        for entry in &self.accepted_values {
            if !family_ids.contains(entry.family.as_str())
                || !valid_efforts.contains(&entry.effort.as_str())
                || !valid_decimal_rule(&entry.value)
                || !accepted.insert((
                    entry.family.as_str(),
                    entry.effort.as_str(),
                    entry.value.as_str(),
                ))
                || !rules
                    .families_for(&entry.effort, &entry.value)
                    .iter()
                    .any(|family| family == &entry.family)
            {
                return Err(RuleBundleError::Invalid(
                    "invalid accepted Juice calibration value",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuiceCalibrationValue {
    pub family: String,
    pub effort: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuicePlans {
    pub quick: Vec<JuicePlanEntry>,
    pub standard: Vec<JuicePlanEntry>,
    pub full: Vec<JuicePlanEntry>,
}

impl JuicePlans {
    fn validate(&self, valid_efforts: &[&str]) -> Result<(), RuleBundleError> {
        for plan in [&self.quick, &self.standard, &self.full] {
            if plan.len() > 8
                || plan.iter().map(|entry| entry.samples).sum::<usize>() > 32
                || plan.iter().any(|entry| {
                    !valid_efforts.contains(&entry.effort.as_str())
                        || !(1..=8).contains(&entry.samples)
                })
            {
                return Err(RuleBundleError::Invalid("invalid Juice sample plan"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuicePlanEntry {
    pub effort: String,
    pub samples: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuiceTemplate {
    pub id: String,
    pub transformation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NonGptJuiceRules {
    pub prompt: String,
    pub samples: ModeSampleCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DemoJuiceRules {
    pub non_gpt_response: String,
    pub effort_responses: std::collections::BTreeMap<String, String>,
}

impl DemoJuiceRules {
    fn validate(&self, valid_efforts: &[&str]) -> Result<(), RuleBundleError> {
        if self.non_gpt_response.is_empty()
            || self.effort_responses.is_empty()
            || self.effort_responses.len() > valid_efforts.len()
            || self.effort_responses.iter().any(|(effort, value)| {
                !valid_efforts.contains(&effort.as_str()) || !valid_decimal_rule(value)
            })
        {
            return Err(RuleBundleError::Invalid(
                "invalid Juice demo response rules",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModeSampleCounts {
    pub quick: usize,
    pub standard: usize,
    pub full: usize,
}

impl ModeSampleCounts {
    fn validate_counts(&self) -> Result<(), RuleBundleError> {
        if self.quick > 8 || self.standard > 8 || self.full > 8 {
            return Err(RuleBundleError::Invalid("invalid mode sample count"));
        }
        Ok(())
    }

    pub(crate) fn for_mode(&self, mode: ProbeMode) -> usize {
        match mode {
            ProbeMode::Quick => self.quick,
            ProbeMode::Standard => self.standard,
            ProbeMode::Full => self.full,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuiceFamilyRule {
    pub id: String,
    pub calibration_state: String,
    pub classification_enabled: bool,
    pub matches: Vec<JuiceMatchRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuiceMatchRule {
    pub effort: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JuiceScoring {
    pub fingerprint_weight: f64,
    pub non_gpt_weight: f64,
    pub mixed: OutcomeRule,
    pub supported_primary: OutcomeRule,
    pub primary_only: OutcomeRule,
    pub no_numeric: OutcomeRule,
    pub ambiguous: OutcomeRule,
    pub non_gpt_unique: OutcomeRule,
    pub non_gpt_ambiguous: OutcomeRule,
    pub non_gpt_mixed: OutcomeRule,
    pub non_gpt_unmatched: OutcomeRule,
    pub non_gpt_unavailable: OutcomeRule,
    pub non_gpt_normal: OutcomeRule,
}

impl JuiceScoring {
    fn validate(&self) -> Result<(), RuleBundleError> {
        if !valid_weight(self.fingerprint_weight) || !valid_weight(self.non_gpt_weight) {
            return Err(RuleBundleError::Invalid("invalid Juice weight"));
        }
        for outcome in [
            &self.mixed,
            &self.supported_primary,
            &self.primary_only,
            &self.no_numeric,
            &self.ambiguous,
            &self.non_gpt_unique,
            &self.non_gpt_ambiguous,
            &self.non_gpt_mixed,
            &self.non_gpt_unmatched,
            &self.non_gpt_unavailable,
            &self.non_gpt_normal,
        ] {
            outcome.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeRule {
    pub score: f64,
    pub confidence: f64,
    pub summary: String,
}

impl OutcomeRule {
    pub(crate) fn validate(&self) -> Result<(), RuleBundleError> {
        if !(0.0..=100.0).contains(&self.score)
            || !(0.0..=1.0).contains(&self.confidence)
            || self.summary.is_empty()
            || self.summary.len() > 1_000
        {
            return Err(RuleBundleError::Invalid("invalid evaluation outcome"));
        }
        Ok(())
    }
}

pub(crate) fn install_rule_bundle(
    request: &mut ProbeRequest,
    bundle: Option<&Arc<CoreRuleBundle>>,
) {
    request.parameters.remove(INTERNAL_RULE_BUNDLE_KEY);
    request.parameters.remove(INTERNAL_RULE_STATUS_KEY);
    match bundle {
        Some(bundle) => {
            request.parameters.insert(
                INTERNAL_RULE_BUNDLE_KEY.into(),
                serde_json::to_value(bundle.rules.clone())
                    .expect("validated Core rules are serializable"),
            );
            request
                .parameters
                .insert(INTERNAL_RULE_STATUS_KEY.into(), serde_json::json!("active"));
        }
        None => {
            request.parameters.insert(
                INTERNAL_RULE_STATUS_KEY.into(),
                serde_json::json!("unavailable"),
            );
        }
    }
}

pub(crate) fn rules_from_request(request: &ProbeRequest) -> Option<CoreRules> {
    request
        .parameters
        .get(INTERNAL_RULE_BUNDLE_KEY)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .or_else(test_rules)
}

#[cfg(not(test))]
fn test_rules() -> Option<CoreRules> {
    None
}

#[cfg(test)]
fn test_rules() -> Option<CoreRules> {
    use std::{path::PathBuf, sync::LazyLock};

    static RULES: LazyLock<CoreRules> = LazyLock::new(|| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../SanBiao/rules/the-standard/stable.json");
        CoreRuleBundle::from_document(&std::fs::read(path).unwrap(), None)
            .expect("shared Knowledge rule fixture")
            .rules
    });
    Some(RULES.clone())
}

fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b'+')
        })
}

fn valid_markers(markers: &[String]) -> bool {
    !markers.is_empty()
        && markers.len() <= 32
        && markers
            .iter()
            .all(|marker| valid_id(marker, 80) && marker == &marker.to_ascii_lowercase())
}

fn valid_decimal_rule(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 16
        || value.starts_with('+')
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || value.bytes().filter(|byte| *byte == b'.').count() > 1
    {
        return false;
    }
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    if integer.is_empty()
        || (integer.len() > 1 && integer.starts_with('0'))
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    if value.contains('.') {
        !fraction.is_empty()
            && fraction.bytes().all(|byte| byte.is_ascii_digit())
            && !fraction.ends_with('0')
    } else {
        true
    }
}

fn valid_weight(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

#[derive(Debug, Error)]
pub enum RuleBundleError {
    #[error("rule bundle exceeds the one-megabyte response limit")]
    TooLarge,
    #[error("invalid rule bundle: {0}")]
    Invalid(&'static str),
    #[error("invalid rule bundle JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use wire_contracts::{RuleRepositoryProvenance, RuleRepositorySource};

    fn rule_document() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../SanBiao/rules/the-standard/stable.json");
        std::fs::read(path).unwrap()
    }

    fn repository_provenance() -> RuleRepositoryProvenance {
        RuleRepositoryProvenance {
            release: "2026.08.15.1".into(),
            manifest_source: RuleRepositorySource::Remote,
            document_source: RuleRepositorySource::Remote,
        }
    }

    #[test]
    fn validates_the_shared_repository_rule_document() {
        let bundle = CoreRuleBundle::from_document(&rule_document(), None).unwrap();
        assert_eq!(bundle.provenance.id, "the-standard");
        let raw: Value = serde_json::from_slice(&rule_document()).unwrap();
        assert_eq!(
            bundle.provenance.version,
            raw["version"].as_str().unwrap(),
            "the typed bundle must preserve the published document version"
        );
        assert!(bundle.provenance.digest.starts_with("sha256:"));
        assert_eq!(
            bundle
                .rules
                .strategies
                .reasoning_budget_fingerprint
                .families_for("high", "40855"),
            vec!["gpt-5.6-sol"]
        );
        assert!(
            bundle
                .rules
                .strategies
                .reasoning_budget_fingerprint
                .families_for("high", "40")
                .is_empty()
        );
        assert_eq!(
            bundle
                .rules
                .strategies
                .reasoning_budget_fingerprint
                .families_for("low", "8.855"),
            vec!["gpt-5.6-sol"]
        );
        assert!(
            !bundle
                .rules
                .strategies
                .reasoning_budget_fingerprint
                .families_for("high", "32")
                .contains(&"gpt-5.6-terra".to_string())
        );
    }

    #[test]
    fn rejects_repository_descriptor_mismatches() {
        let bundle = CoreRuleBundle::from_document(&rule_document(), None).unwrap();
        let descriptor = RepositoryDocument {
            id: bundle.provenance.id.clone(),
            version: bundle.provenance.version.clone(),
            channel: "candidate".into(),
            path: "rules/the-standard/stable.json".into(),
            digest: bundle.provenance.digest.clone(),
        };
        assert!(
            CoreRuleBundle::from_repository_document(
                &rule_document(),
                &descriptor,
                None,
                repository_provenance(),
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_a_digest_verified_repository_document() {
        let parsed = CoreRuleBundle::from_document(&rule_document(), None).unwrap();
        let descriptor = RepositoryDocument {
            id: parsed.provenance.id.clone(),
            version: parsed.provenance.version.clone(),
            channel: parsed.provenance.channel.clone(),
            path: "rules/the-standard/stable.json".into(),
            digest: parsed.provenance.digest.clone(),
        };
        let bundle = CoreRuleBundle::from_repository_document(
            &rule_document(),
            &descriptor,
            None,
            repository_provenance(),
        )
        .unwrap();
        assert_eq!(bundle.provenance.version, parsed.provenance.version);
        assert_eq!(
            bundle.provenance.repository.unwrap().release,
            "2026.08.15.1"
        );
    }

    #[test]
    fn accepts_only_canonical_decimal_rule_values() {
        for value in ["0", "8", "8.855", "960"] {
            assert!(valid_decimal_rule(value), "expected {value} to be valid");
        }
        for value in ["08.855", "8.8550", ".855", "8.", "1e3", "+8", "-1"] {
            assert!(
                !valid_decimal_rule(value),
                "expected {value} to be rejected"
            );
        }
    }

    #[test]
    fn resolves_declared_sections_and_rejects_unknown_ones() {
        let bundle = CoreRuleBundle::from_document(&rule_document(), None).unwrap();
        let rules = &bundle.rules;
        let sections = rules.sections.as_ref().expect("declared sections");
        assert_eq!(
            sections.items.len(),
            crate::probe::PROBE_STRATEGY_NAMES.len()
        );
        assert!(
            sections
                .default_enabled
                .iter()
                .all(|id| sections.items.iter().any(|item| &item.id == id))
        );
        assert!(sections.default_enabled.contains(&"cache".to_string()));
        assert!(sections.default_enabled.contains(&"injection".to_string()));
        assert!(
            sections
                .default_enabled
                .contains(&"knowledgeCutoff".to_string())
        );
        assert!(!sections.default_enabled.contains(&"web".to_string()));

        let default = rules
            .resolve_sections(&[])
            .unwrap()
            .expect("the shared rule document declares sections");
        assert!(default.default_selection);
        assert_eq!(default.requested.len(), sections.default_enabled.len());
        assert_eq!(default.not_selected, vec!["web".to_string()]);
        assert!(default.allowed_strategies.contains("cache_reuse"));
        assert!(default.allowed_strategies.contains("injection_overhead"));
        assert!(default.allowed_strategies.contains("knowledge_cutoff"));
        assert!(!default.allowed_strategies.contains("web_search"));

        let selected = rules
            .resolve_sections(&["tools".into(), "identity".into(), "identity".into()])
            .unwrap()
            .unwrap();
        assert!(!selected.default_selection);
        assert_eq!(
            selected.requested,
            vec!["identity".to_string(), "tools".to_string()]
        );
        assert!(!selected.not_selected.contains(&"identity".to_string()));
        assert!(selected.allowed_strategies.contains("tool_contract"));
        assert!(!selected.allowed_strategies.contains("knowledge_challenges"));

        assert_eq!(
            rules.resolve_sections(&["nope".into()]),
            Err(SectionSelectionError::Unknown("nope".into()))
        );

        let mut legacy_document: Value = serde_json::from_slice(&rule_document()).unwrap();
        legacy_document["payload"]
            .as_object_mut()
            .unwrap()
            .remove("sections");
        let legacy =
            CoreRuleBundle::from_document(&serde_json::to_vec(&legacy_document).unwrap(), None)
                .unwrap();
        assert!(legacy.rules.sections.is_none());
        assert!(legacy.rules.resolve_sections(&[]).unwrap().is_none());
        assert_eq!(
            legacy.rules.resolve_sections(&["identity".into()]),
            Err(SectionSelectionError::Unavailable)
        );
    }

    #[test]
    fn rejects_incomplete_or_ambiguous_section_declarations() {
        let mut uncovered: Value = serde_json::from_slice(&rule_document()).unwrap();
        uncovered["payload"]["sections"]["items"][0]["strategies"] = serde_json::json!([]);
        assert!(
            CoreRuleBundle::from_document(&serde_json::to_vec(&uncovered).unwrap(), None).is_err()
        );

        let mut ambiguous: Value = serde_json::from_slice(&rule_document()).unwrap();
        ambiguous["payload"]["sections"]["items"][1]["strategies"] =
            serde_json::json!(["identity", "behavior_scenarios"]);
        assert!(
            CoreRuleBundle::from_document(&serde_json::to_vec(&ambiguous).unwrap(), None).is_err()
        );

        let mut unknown_strategy: Value = serde_json::from_slice(&rule_document()).unwrap();
        unknown_strategy["payload"]["sections"]["items"][0]["strategies"] =
            serde_json::json!(["telepathy"]);
        assert!(
            CoreRuleBundle::from_document(&serde_json::to_vec(&unknown_strategy).unwrap(), None)
                .is_err()
        );

        let mut unknown_default: Value = serde_json::from_slice(&rule_document()).unwrap();
        unknown_default["payload"]["sections"]["defaultEnabled"] = serde_json::json!(["ghost"]);
        assert!(
            CoreRuleBundle::from_document(&serde_json::to_vec(&unknown_default).unwrap(), None)
                .is_err()
        );

        // Every engine strategy, including the second-wave detectors, must be
        // claimed by exactly one declared section.
        let mut missing_new_section: Value = serde_json::from_slice(&rule_document()).unwrap();
        let items = missing_new_section["payload"]["sections"]["items"]
            .as_array_mut()
            .expect("items");
        items.retain(|item| item["id"] != "web");
        assert!(
            CoreRuleBundle::from_document(&serde_json::to_vec(&missing_new_section).unwrap(), None)
                .is_err()
        );

        let mut duplicate_section: Value = serde_json::from_slice(&rule_document()).unwrap();
        let items = duplicate_section["payload"]["sections"]["items"]
            .as_array_mut()
            .expect("items");
        let mut clone = items[0].clone();
        clone["id"] = serde_json::json!("cache");
        items.push(clone);
        assert!(
            CoreRuleBundle::from_document(&serde_json::to_vec(&duplicate_section).unwrap(), None)
                .is_err()
        );
    }

    fn invalid(document: &Value) -> bool {
        CoreRuleBundle::from_document(&serde_json::to_vec(document).unwrap(), None).is_err()
    }

    #[test]
    fn reasoning_iq_and_thinking_chain_are_declared_once_and_default_enabled() {
        let bundle = CoreRuleBundle::from_document(&rule_document(), None).unwrap();
        let sections = bundle.rules.sections.as_ref().expect("declared sections");
        for (section, strategy) in [
            ("reasoningIQ", "reasoning_iq"),
            ("thinkingChain", "thinking_chain"),
        ] {
            let declared: Vec<&SectionRule> = sections
                .items
                .iter()
                .filter(|item| item.strategies.iter().any(|value| value == strategy))
                .collect();
            assert_eq!(declared.len(), 1, "{strategy} must be claimed exactly once");
            assert_eq!(declared[0].id, section);
            assert!(sections.default_enabled.contains(&section.to_string()));
        }
        let default = bundle.rules.resolve_sections(&[]).unwrap().unwrap();
        assert!(default.allowed_strategies.contains("reasoning_iq"));
        assert!(default.allowed_strategies.contains("thinking_chain"));
    }

    #[test]
    fn rejects_invalid_reasoning_iq_payloads() {
        let mut missing_question: Value = serde_json::from_slice(&rule_document()).unwrap();
        missing_question["payload"]["probes"]["reasoningIQ"]["questions"]
            .as_array_mut()
            .expect("questions")
            .pop();
        assert!(invalid(&missing_question));

        let mut duplicate_id: Value = serde_json::from_slice(&rule_document()).unwrap();
        duplicate_id["payload"]["probes"]["reasoningIQ"]["questions"][1]["id"] =
            serde_json::json!("iq-1");
        assert!(invalid(&duplicate_id));

        let mut duplicate_answer: Value = serde_json::from_slice(&rule_document()).unwrap();
        let expected =
            duplicate_answer["payload"]["probes"]["reasoningIQ"]["questions"][0]["expected"]
                .clone();
        duplicate_answer["payload"]["probes"]["reasoningIQ"]["questions"][2]["expected"] = expected;
        assert!(invalid(&duplicate_answer));

        let mut unknown_answer_type: Value = serde_json::from_slice(&rule_document()).unwrap();
        unknown_answer_type["payload"]["probes"]["reasoningIQ"]["questions"][0]["answerType"] =
            serde_json::json!("decimal");
        assert!(invalid(&unknown_answer_type));

        let mut tolerance_on_a_word: Value = serde_json::from_slice(&rule_document()).unwrap();
        tolerance_on_a_word["payload"]["probes"]["reasoningIQ"]["questions"][3]["tolerance"] =
            serde_json::json!(1);
        assert!(invalid(&tolerance_on_a_word));

        let mut unparsable_answer: Value = serde_json::from_slice(&rule_document()).unwrap();
        unparsable_answer["payload"]["probes"]["reasoningIQ"]["questions"][0]["expected"] =
            serde_json::json!("forty-two");
        assert!(invalid(&unparsable_answer));

        let mut heavy_weight: Value = serde_json::from_slice(&rule_document()).unwrap();
        heavy_weight["payload"]["evaluation"]["reasoningIQ"]["weight"] = serde_json::json!(0.2);
        assert!(invalid(&heavy_weight));
    }

    #[test]
    fn rejects_invalid_thinking_chain_payloads() {
        let mut heavy_weight: Value = serde_json::from_slice(&rule_document()).unwrap();
        heavy_weight["payload"]["evaluation"]["thinkingChain"]["weight"] = serde_json::json!(0.4);
        assert!(invalid(&heavy_weight));

        let mut missing_limitations: Value = serde_json::from_slice(&rule_document()).unwrap();
        missing_limitations["payload"]["probes"]["thinkingChain"]
            .as_object_mut()
            .expect("thinking chain rules")
            .remove("limitations");
        assert!(invalid(&missing_limitations));

        let mut inverted_thresholds: Value = serde_json::from_slice(&rule_document()).unwrap();
        inverted_thresholds["payload"]["probes"]["thinkingChain"]["summaryMaximumChars"] =
            serde_json::json!(900);
        assert!(invalid(&inverted_thresholds));
    }
}
