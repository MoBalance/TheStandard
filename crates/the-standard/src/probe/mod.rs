mod advanced;
mod demo;
mod juice;
mod reasoning;
mod second_wave;
mod strategies;
mod transport;
pub use advanced::{
    BehaviorScenarioStrategy, DocumentUnderstandingStrategy, IdentifierStrategy,
    KnowledgeChallengeStrategy, RelayPayloadIntegrityStrategy, ResponseIntegrityStrategy,
    ToolContractStrategy,
};
pub use demo::DemoTransport;
pub use juice::ReasoningBudgetStrategy;
pub use reasoning::{ReasoningIqStrategy, ThinkingChainStrategy};
pub use second_wave::{
    CacheReuseStrategy, InjectionOverheadStrategy, KnowledgeCutoffStrategy, WebSearchStrategy,
};
pub use strategies::{
    ConsistencyStrategy, ContextAuditStrategy, IdentityStrategy, ProtocolStrategy,
    ReasoningAttestationStrategy, summarize_context_audit,
};
pub use transport::{HttpTransport, OutboundProbe, ProbeTransport};

use crate::{CoreError, DetectorEvidence, ProbeObservation, ProbeRequest};

/// Every strategy the engine registers, in execution order.
///
/// The rule repository declares detection sections over exactly this set, so
/// adding a strategy here is a breaking rule change: the shared rule document
/// must claim the new name in one section.
pub const PROBE_STRATEGY_NAMES: &[&str] = &[
    "identity",
    "behavior_scenarios",
    "reasoning_attestation",
    "reasoning_budget_fingerprint",
    "knowledge_challenges",
    "document_understanding",
    "tool_contract",
    "context",
    "consistency",
    "response_integrity",
    "relay_payload_integrity",
    "protocol",
    "identifiers",
    "cache_reuse",
    "injection_overhead",
    "knowledge_cutoff",
    "web_search",
    "reasoning_iq",
    "thinking_chain",
];

pub trait ProbeStrategy: Send + Sync {
    fn name(&self) -> &'static str;
    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError>;
    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence;

    fn follow_up(
        &self,
        _request: &ProbeRequest,
        _observations: &[ProbeObservation],
    ) -> Result<Vec<OutboundProbe>, CoreError> {
        Ok(Vec::new())
    }

    fn observes_all(&self) -> bool {
        false
    }

    /// Whether the engine must run this strategy's follow-up probes one at a
    /// time, feeding each answer into the next question. A serial strategy
    /// receives the observations collected so far on every round.
    fn serial_follow_up(&self) -> bool {
        false
    }

    /// Upper bound on serial follow-up rounds. Ignored unless
    /// `serial_follow_up` is true; the default keeps one follow-up round, which
    /// is the behavior of every non-serial strategy.
    fn serial_follow_up_budget(&self, _request: &ProbeRequest) -> usize {
        1
    }
}
