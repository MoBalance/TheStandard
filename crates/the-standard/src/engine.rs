use crate::{
    CoreError, DetectionReport, DetectionTarget, DetectionTier, DetectorEvidence, EngineConfig,
    EvidenceCoverage, EvidenceSeverity, EvidenceStatus, OutboundProbe, PerformanceMetrics,
    ProbeObservation, ProbeRequest, ProbeTransport, Protocol, ReportSectionSelection,
    RuntimeEventStatus, UsageMetrics, Verdict, core_build_info,
    fingerprint::prepare_fingerprint_request,
    knowledge::prepare_knowledge_request,
    model::mask_api_key,
    probe::{
        BehaviorScenarioStrategy, ConsistencyStrategy, DocumentUnderstandingStrategy,
        IdentifierStrategy, IdentityStrategy, KnowledgeChallengeStrategy, ProtocolStrategy,
        ReasoningAttestationStrategy, ReasoningBudgetStrategy, RelayPayloadIntegrityStrategy,
        ResponseIntegrityStrategy, ToolContractStrategy,
    },
    report_presentation,
    rules::{CoreRules, ResolvedSections, install_rule_bundle},
};
use chrono::Utc;
use futures_util::{StreamExt, stream, stream::FuturesUnordered};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, Semaphore},
    time::Instant,
};
use ulid::Ulid;

/// The numeric fingerprint asks a single response for 320 integers, so a slow
/// upstream needs far more than the per-probe budget: at ~19 tokens/s that
/// answer alone takes around 35 s. Without this floor the probe timed out and
/// the report silently lost its attribution.
const NUMERIC_FINGERPRINT_TIMEOUT_SECONDS: u64 = 90;

pub trait RuntimeObserver: Send + Sync {
    fn emit(
        &self,
        stage: &str,
        event: &str,
        status: RuntimeEventStatus,
        message: &str,
        details: BTreeMap<String, Value>,
    );
}

fn emit_runtime(
    observer: Option<&dyn RuntimeObserver>,
    stage: &str,
    event: &str,
    status: RuntimeEventStatus,
    message: &str,
    details: BTreeMap<String, Value>,
) {
    if let Some(observer) = observer {
        observer.emit(stage, event, status, message, details);
    }
}

pub struct Engine {
    config: EngineConfig,
    strategies: Vec<Arc<dyn crate::ProbeStrategy>>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("config", &self.config)
            .field("strategy_count", &self.strategies.len())
            .finish()
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            strategies: vec![
                Arc::new(IdentityStrategy),
                Arc::new(BehaviorScenarioStrategy),
                Arc::new(ReasoningAttestationStrategy),
                Arc::new(ReasoningBudgetStrategy),
                Arc::new(KnowledgeChallengeStrategy),
                Arc::new(DocumentUnderstandingStrategy),
                Arc::new(ToolContractStrategy),
                Arc::new(crate::probe::ContextAuditStrategy),
                Arc::new(ConsistencyStrategy),
                Arc::new(ResponseIntegrityStrategy),
                Arc::new(RelayPayloadIntegrityStrategy),
                Arc::new(ProtocolStrategy),
                Arc::new(IdentifierStrategy),
                Arc::new(crate::probe::CacheReuseStrategy),
                Arc::new(crate::probe::InjectionOverheadStrategy),
                Arc::new(crate::probe::KnowledgeCutoffStrategy),
                Arc::new(crate::probe::WebSearchStrategy),
                Arc::new(crate::probe::ReasoningIqStrategy),
                Arc::new(crate::probe::ThinkingChainStrategy),
            ],
        }
    }

    pub async fn detect(
        &self,
        request: ProbeRequest,
        transport: &dyn ProbeTransport,
    ) -> Result<DetectionReport, CoreError> {
        self.detect_with_observer(request, transport, None).await
    }

    pub async fn detect_with_observer(
        &self,
        mut request: ProbeRequest,
        transport: &dyn ProbeTransport,
        observer: Option<Arc<dyn RuntimeObserver>>,
    ) -> Result<DetectionReport, CoreError> {
        if self.config.rule_bundle.is_none() {
            return Err(CoreError::RulesUnavailable);
        }
        let selection = match self
            .config
            .rule_bundle
            .as_ref()
            .expect("rule bundle was checked above")
            .rules
            .resolve_sections(&request.sections)
        {
            Ok(selection) => selection,
            Err(error) => return Err(CoreError::InvalidSections(error.to_string())),
        };
        let timeout = self.config.overall_timeout(request.mode);
        let deadline = Instant::now() + timeout;
        emit_runtime(
            observer.as_deref(),
            "engine",
            "engine_started",
            RuntimeEventStatus::Running,
            "Detection engine started",
            BTreeMap::from([
                ("model".into(), json!(request.model)),
                ("protocol".into(), json!(request.protocol)),
                ("mode".into(), json!(request.mode)),
                ("overallTimeoutMs".into(), json!(timeout.as_millis() as u64)),
            ]),
        );
        install_rule_bundle(&mut request, self.config.rule_bundle.as_ref());
        emit_runtime(
            observer.as_deref(),
            "rules",
            "rules_installed",
            RuntimeEventStatus::Success,
            "Validated rule bundle installed",
            BTreeMap::new(),
        );
        emit_runtime(
            observer.as_deref(),
            "knowledge",
            "knowledge_resolution_started",
            RuntimeEventStatus::Running,
            "Resolving compatible knowledge packs",
            BTreeMap::new(),
        );
        tokio::time::timeout_at(
            deadline,
            prepare_knowledge_request(self.config.rule_repository.as_ref(), &mut request),
        )
        .await
        .map_err(|_| CoreError::OverallTimeout(timeout))?;
        emit_runtime(
            observer.as_deref(),
            "knowledge",
            "knowledge_resolution_completed",
            RuntimeEventStatus::Success,
            "Knowledge-pack resolution completed",
            BTreeMap::new(),
        );
        emit_runtime(
            observer.as_deref(),
            "fingerprint",
            "fingerprint_resolution_started",
            RuntimeEventStatus::Running,
            "Resolving the optional numeric model-fingerprint bank",
            BTreeMap::new(),
        );
        tokio::time::timeout_at(
            deadline,
            prepare_fingerprint_request(self.config.rule_repository.as_ref(), &mut request),
        )
        .await
        .map_err(|_| CoreError::OverallTimeout(timeout))?;
        emit_runtime(
            observer.as_deref(),
            "fingerprint",
            "fingerprint_resolution_completed",
            RuntimeEventStatus::Success,
            "Numeric fingerprint-bank resolution completed",
            BTreeMap::new(),
        );
        self.detect_inner(request, selection, transport, deadline, timeout, observer)
            .await
    }

    async fn detect_inner(
        &self,
        request: ProbeRequest,
        selection: Option<ResolvedSections>,
        transport: &dyn ProbeTransport,
        deadline: Instant,
        overall_timeout: Duration,
        observer: Option<Arc<dyn RuntimeObserver>>,
    ) -> Result<DetectionReport, CoreError> {
        let mut evidence = Vec::new();
        let mut all_observations = Vec::new();
        let global_backoff = Arc::new(Mutex::new(None));
        let concurrency = Arc::new(Semaphore::new(self.config.max_concurrent.max(1)));
        let mut passive_strategies = Vec::new();
        let mut active_strategies = Vec::new();

        for strategy in &self.strategies {
            if let Some(selection) = &selection
                && !selection
                    .allowed_strategies
                    .iter()
                    .any(|name| name == strategy.name())
            {
                continue;
            }
            if strategy.observes_all() {
                passive_strategies.push(Arc::clone(strategy));
            } else {
                active_strategies.push(Arc::clone(strategy));
            }
        }
        if selection
            .as_ref()
            .is_some_and(|value| !value.default_selection)
            && active_strategies.is_empty()
        {
            return Err(CoreError::InvalidSections(
                "the selected detection sections contain no probe-producing strategy".into(),
            ));
        }

        let strategy_catalog = active_strategies.clone();
        let mut pending = FuturesUnordered::new();
        for (index, strategy) in active_strategies.into_iter().enumerate() {
            pending.push(self.execute_strategy(
                index,
                strategy,
                request.clone(),
                transport,
                Arc::clone(&global_backoff),
                Arc::clone(&concurrency),
                observer.clone(),
            ));
        }
        let mut completed = BTreeMap::new();
        let mut overall_timed_out = false;
        loop {
            match tokio::time::timeout_at(deadline, pending.next()).await {
                Ok(Some(result)) => {
                    let (index, item, observations) = result?;
                    completed.insert(index, (item, observations));
                }
                Ok(None) => break,
                Err(_) => {
                    overall_timed_out = true;
                    break;
                }
            }
        }
        drop(pending);
        for (index, strategy) in strategy_catalog.into_iter().enumerate() {
            if let Some((item, observations)) = completed.remove(&index) {
                evidence.push(item);
                all_observations.extend(observations);
            } else if overall_timed_out {
                let error = format!(
                    "strategy '{}' exceeded the detection deadline",
                    strategy.name()
                );
                evidence.push(attach_execution_errors(
                    strategy.analyze(&request, &[]),
                    &[error],
                    &request,
                ));
            }
        }

        if all_observations.is_empty() {
            return Err(if overall_timed_out {
                CoreError::OverallTimeout(overall_timeout)
            } else {
                CoreError::NoObservations
            });
        }
        for strategy in passive_strategies {
            evidence.push(strategy.analyze(&request, &all_observations));
        }
        emit_runtime(
            observer.as_deref(),
            "report",
            "report_build_started",
            RuntimeEventStatus::Running,
            "Building the detection report",
            BTreeMap::from([
                ("evidenceItems".into(), json!(evidence.len())),
                ("observations".into(), json!(all_observations.len())),
            ]),
        );
        let report = self.report(request, evidence, all_observations);
        emit_runtime(
            observer.as_deref(),
            "report",
            "report_build_completed",
            RuntimeEventStatus::Success,
            "Detection report completed",
            BTreeMap::from([
                ("reportId".into(), json!(report.id)),
                ("verdict".into(), json!(report.verdict)),
                ("score".into(), json!(report.total_score)),
            ]),
        );
        Ok(report)
    }

    async fn execute_strategy(
        &self,
        index: usize,
        strategy: Arc<dyn crate::ProbeStrategy>,
        request: ProbeRequest,
        transport: &dyn ProbeTransport,
        global_backoff: Arc<Mutex<Option<Instant>>>,
        concurrency: Arc<Semaphore>,
        observer: Option<Arc<dyn RuntimeObserver>>,
    ) -> Result<(usize, DetectorEvidence, Vec<ProbeObservation>), CoreError> {
        let strategy_name = strategy.name();
        emit_runtime(
            observer.as_deref(),
            "strategy",
            "strategy_started",
            RuntimeEventStatus::Running,
            "Detector strategy started",
            BTreeMap::from([("strategy".into(), json!(strategy_name))]),
        );
        let probes = strategy.build(&request)?;
        emit_runtime(
            observer.as_deref(),
            "strategy",
            "probes_planned",
            RuntimeEventStatus::Info,
            "Outbound probes planned",
            BTreeMap::from([
                ("strategy".into(), json!(strategy_name)),
                ("probeCount".into(), json!(probes.len())),
            ]),
        );
        let (mut observations, mut errors) = collect_probe_results(
            self.execute_probes(
                strategy_name,
                probes,
                transport,
                Arc::clone(&global_backoff),
                Arc::clone(&concurrency),
                observer.clone(),
            )
            .await,
        );
        let serial = strategy.serial_follow_up();
        let budget = strategy.serial_follow_up_budget(&request);
        let mut rounds = 0_usize;
        loop {
            let follow_up = strategy.follow_up(&request, &observations)?;
            if follow_up.is_empty() {
                break;
            }
            let (follow_up_observations, follow_up_errors) = collect_probe_results(
                self.execute_probes(
                    strategy_name,
                    follow_up,
                    transport,
                    Arc::clone(&global_backoff),
                    Arc::clone(&concurrency),
                    observer.clone(),
                )
                .await,
            );
            observations.extend(follow_up_observations);
            errors.extend(follow_up_errors);
            rounds += 1;
            if !serial || rounds >= budget {
                break;
            }
        }
        let evidence =
            attach_execution_errors(strategy.analyze(&request, &observations), &errors, &request);
        emit_runtime(
            observer.as_deref(),
            "strategy",
            "strategy_completed",
            if errors.is_empty() {
                RuntimeEventStatus::Success
            } else {
                RuntimeEventStatus::Warning
            },
            "Detector strategy completed",
            BTreeMap::from([
                ("strategy".into(), json!(strategy_name)),
                ("observations".into(), json!(observations.len())),
                ("errors".into(), json!(errors.len())),
                ("score".into(), json!(evidence.score)),
                ("status".into(), json!(evidence.status)),
            ]),
        );
        Ok((index, evidence, observations))
    }

    async fn execute_probes(
        &self,
        strategy_name: &str,
        probes: Vec<OutboundProbe>,
        transport: &dyn ProbeTransport,
        global_backoff: Arc<Mutex<Option<Instant>>>,
        concurrency: Arc<Semaphore>,
        observer: Option<Arc<dyn RuntimeObserver>>,
    ) -> Vec<Result<ProbeObservation, CoreError>> {
        let mut completed = stream::iter(probes.into_iter().enumerate())
            .map(|(index, probe)| {
                let global_backoff = Arc::clone(&global_backoff);
                let concurrency = Arc::clone(&concurrency);
                let observer = observer.clone();
                async move {
                    self.execute_with_retry(
                        strategy_name,
                        &probe,
                        transport,
                        &global_backoff,
                        &concurrency,
                        observer.as_deref(),
                    )
                    .await
                    .map(|observation| (index, Ok(observation)))
                    .unwrap_or_else(|error| (index, Err(error)))
                }
            })
            .buffer_unordered(self.config.max_concurrent.max(1))
            .collect::<Vec<_>>()
            .await;
        completed.sort_by_key(|(index, _)| *index);
        completed
            .into_iter()
            .map(|(_, observation)| observation)
            .collect()
    }

    async fn execute_with_retry(
        &self,
        strategy_name: &str,
        probe: &OutboundProbe,
        transport: &dyn ProbeTransport,
        global_backoff: &Mutex<Option<Instant>>,
        concurrency: &Semaphore,
        observer: Option<&dyn RuntimeObserver>,
    ) -> Result<ProbeObservation, CoreError> {
        // A numeric-fingerprint probe is one long completion rather than a small
        // structural question, so it gets its own floor; the mode deadline still
        // caps the whole detection.
        let budget = if probe.kind == crate::ProbeKind::NumericFingerprint {
            self.config
                .request_timeout
                .max(Duration::from_secs(NUMERIC_FINGERPRINT_TIMEOUT_SECONDS))
        } else {
            self.config.request_timeout
        };
        let deadline = Instant::now() + budget;
        let mut last_error = None;
        let mut backoff_count = 0;
        for attempt in 0..=self.config.max_retries {
            let backoff_ms = pending_backoff_ms(global_backoff).await;
            if backoff_ms > 0 {
                emit_runtime(
                    observer,
                    "probe",
                    "probe_backoff_wait",
                    RuntimeEventStatus::Warning,
                    "Probe is waiting for the upstream backoff window",
                    probe_event_details(
                        strategy_name,
                        probe,
                        attempt,
                        self.config.max_retries,
                        [("waitMs".into(), json!(backoff_ms))],
                    ),
                );
            }
            if tokio::time::timeout_at(deadline, wait_for_backoff(global_backoff))
                .await
                .is_err()
            {
                break;
            }
            let permit = match tokio::time::timeout_at(deadline, concurrency.acquire()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(error)) => return Err(CoreError::Transport(error.to_string())),
                Err(_) => break,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(permit);
                break;
            }
            emit_runtime(
                observer,
                "probe",
                "probe_attempt_started",
                RuntimeEventStatus::Running,
                "Outbound probe attempt started",
                probe_event_details(
                    strategy_name,
                    probe,
                    attempt,
                    self.config.max_retries,
                    [("remainingMs".into(), json!(remaining.as_millis() as u64))],
                ),
            );
            let attempt_started = Instant::now();
            let result = match tokio::time::timeout_at(
                deadline,
                transport.execute(probe, remaining),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    last_error = Some(CoreError::Transport(format!(
                        "probe exhausted its {:?} attempt budget",
                        self.config.request_timeout
                    )));
                    emit_runtime(
                        observer,
                        "probe",
                        "probe_attempt_failed",
                        RuntimeEventStatus::Error,
                        "Outbound probe attempt timed out",
                        probe_event_details(
                            strategy_name,
                            probe,
                            attempt,
                            self.config.max_retries,
                            [(
                                "durationMs".into(),
                                json!(attempt_started.elapsed().as_millis() as u64),
                            )],
                        ),
                    );
                    drop(permit);
                    break;
                }
            };
            drop(permit);
            match result {
                Ok(observation)
                    if matches!(observation.status_code, 429 | 503)
                        && attempt < self.config.max_retries =>
                {
                    let delay = retry_delay(&observation, self.config.retry_backoff, attempt);
                    set_global_backoff(global_backoff, delay).await;
                    backoff_count += 1;
                    emit_runtime(
                        observer,
                        "probe",
                        "probe_retry_scheduled",
                        RuntimeEventStatus::Warning,
                        "Upstream throttled the probe; a retry was scheduled",
                        probe_event_details(
                            strategy_name,
                            probe,
                            attempt,
                            self.config.max_retries,
                            observation_event_details(
                                &observation,
                                [
                                    (
                                        "durationMs".into(),
                                        json!(attempt_started.elapsed().as_millis() as u64),
                                    ),
                                    ("retryAfterMs".into(), json!(delay.as_millis() as u64)),
                                ],
                            ),
                        ),
                    );
                    last_error = Some(CoreError::Transport(format!(
                        "upstream returned HTTP {}",
                        observation.status_code
                    )));
                }
                Ok(mut observation) => {
                    observation.retry_count = attempt;
                    observation.backoff_count = backoff_count;
                    emit_runtime(
                        observer,
                        "probe",
                        "probe_attempt_completed",
                        if (200..400).contains(&observation.status_code) {
                            RuntimeEventStatus::Success
                        } else {
                            RuntimeEventStatus::Warning
                        },
                        "Outbound probe attempt completed",
                        probe_event_details(
                            strategy_name,
                            probe,
                            attempt,
                            self.config.max_retries,
                            observation_event_details(
                                &observation,
                                [(
                                    "durationMs".into(),
                                    json!(attempt_started.elapsed().as_millis() as u64),
                                )],
                            ),
                        ),
                    );
                    return Ok(observation);
                }
                Err(error) => {
                    last_error = Some(error);
                    if attempt < self.config.max_retries {
                        let delay = exponential_delay(self.config.retry_backoff, attempt);
                        set_global_backoff(global_backoff, delay).await;
                        backoff_count += 1;
                        emit_runtime(
                            observer,
                            "probe",
                            "probe_retry_scheduled",
                            RuntimeEventStatus::Warning,
                            "Probe transport failed; a retry was scheduled",
                            probe_event_details(
                                strategy_name,
                                probe,
                                attempt,
                                self.config.max_retries,
                                [
                                    (
                                        "durationMs".into(),
                                        json!(attempt_started.elapsed().as_millis() as u64),
                                    ),
                                    ("retryAfterMs".into(), json!(delay.as_millis() as u64)),
                                ],
                            ),
                        );
                    } else {
                        emit_runtime(
                            observer,
                            "probe",
                            "probe_attempt_failed",
                            RuntimeEventStatus::Error,
                            "Probe transport failed after the final attempt",
                            probe_event_details(
                                strategy_name,
                                probe,
                                attempt,
                                self.config.max_retries,
                                [(
                                    "durationMs".into(),
                                    json!(attempt_started.elapsed().as_millis() as u64),
                                )],
                            ),
                        );
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            CoreError::Transport(format!(
                "probe exhausted its {:?} attempt budget",
                self.config.request_timeout
            ))
        }))
    }

    pub fn report(
        &self,
        request: ProbeRequest,
        evidence: Vec<DetectorEvidence>,
        observations: Vec<ProbeObservation>,
    ) -> DetectionReport {
        let valid: Vec<_> = evidence
            .iter()
            .filter(|item| !matches!(item.status, EvidenceStatus::Skip | EvidenceStatus::Error))
            .collect();
        let weight_sum: f64 = valid.iter().map(|item| item.weight).sum();
        let total_score = if weight_sum > 0.0 {
            valid
                .iter()
                .map(|item| item.score * item.weight)
                .sum::<f64>()
                / weight_sum
        } else {
            0.0
        };
        // Coverage is derived from the same evidence set and the same
        // verified-weight denominator as `total_score`; it never changes the
        // score or the verdict, only states how much weight was verified.
        let applicable_weight: f64 = evidence.iter().map(|item| item.weight).sum();
        let unverified_count = evidence
            .iter()
            .filter(|item| matches!(item.status, EvidenceStatus::Skip | EvidenceStatus::Error))
            .count();
        let coverage = EvidenceCoverage {
            verified_weight: weight_sum,
            applicable_weight,
            ratio: if applicable_weight > 0.0 {
                (weight_sum / applicable_weight * 10_000.0).round() / 10_000.0
            } else {
                0.0
            },
            unverified_count,
        };
        let has_critical = valid
            .iter()
            .any(|item| item.severity == EvidenceSeverity::Critical);
        let rules = self
            .config
            .rule_bundle
            .as_ref()
            .expect("detect rejects missing Core rules");
        let raw_verdict = if total_score >= rules.rules.engine.verified_threshold {
            Verdict::Verified
        } else if total_score >= rules.rules.engine.inconclusive_threshold {
            Verdict::Inconclusive
        } else {
            Verdict::Rejected
        };
        let verdict = if has_critical && raw_verdict == Verdict::Verified {
            Verdict::Inconclusive
        } else {
            raw_verdict
        };
        let tier = match request.protocol {
            Protocol::Anthropic
                if evidence.iter().any(|item| {
                    item.name == "reasoning_attestation"
                        && item.status == EvidenceStatus::Pass
                        && item
                            .details
                            .get("continuationValidated")
                            .and_then(serde_json::Value::as_bool)
                            == Some(true)
                }) =>
            {
                DetectionTier::Cryptographic
            }
            Protocol::Anthropic | Protocol::Openai => DetectionTier::Protocol,
            Protocol::Gemini => DetectionTier::Behavioral,
        };
        let tier_message = match tier {
            DetectionTier::Cryptographic => &rules.rules.engine.tier_messages.cryptographic,
            DetectionTier::Protocol => &rules.rules.engine.tier_messages.protocol,
            DetectionTier::Behavioral => &rules.rules.engine.tier_messages.behavioral,
        };

        let mut report = DetectionReport {
            id: Ulid::new().to_string(),
            created_at: Utc::now(),
            core: core_build_info(),
            rules: rules.provenance.clone(),
            target: DetectionTarget {
                base_url: request.base_url,
                api_key_masked: mask_api_key(&request.api_key),
                model: request.model,
                protocol: request.protocol,
            },
            mode: request.mode,
            total_score: (total_score * 10.0).round() / 10.0,
            coverage,
            verdict,
            tier,
            tier_message: tier_message.clone(),
            evidence,
            performance: aggregate_performance(&observations),
            context_audit: crate::probe::summarize_context_audit(
                &observations,
                &rules.rules.evaluation.context,
            ),
            presentation: None,
            section_selection: None,
        };
        report.section_selection = resolved_section_selection(&rules.rules, &request.sections);
        report.presentation = Some(report_presentation(&report));
        report
    }
}

/// Records an explicit section selection in the report.
///
/// A default detection keeps the report shape of earlier releases, so consumers
/// that never select sections observe no change.
fn resolved_section_selection(
    rules: &CoreRules,
    requested: &[String],
) -> Option<ReportSectionSelection> {
    let selection = rules.resolve_sections(requested).ok().flatten()?;
    if selection.default_selection {
        return None;
    }
    Some(ReportSectionSelection {
        requested: selection.requested,
        not_selected: selection.not_selected,
    })
}

fn probe_event_details<I>(
    strategy_name: &str,
    probe: &OutboundProbe,
    attempt: usize,
    max_retries: usize,
    extra: I,
) -> BTreeMap<String, Value>
where
    I: IntoIterator<Item = (String, Value)>,
{
    let mut details = BTreeMap::from([
        ("strategy".into(), json!(strategy_name)),
        ("probeKind".into(), json!(probe.kind)),
        ("attempt".into(), json!(attempt + 1)),
        ("maxAttempts".into(), json!(max_retries + 1)),
    ]);
    if let Some(challenge_id) = probe.challenge_id.as_deref() {
        details.insert("challengeId".into(), json!(challenge_id));
    }
    if let Some(context) = probe.context.as_ref() {
        details.extend([
            ("contextLevel".into(), json!(context.level)),
            ("controlledUnits".into(), json!(context.controlled_units)),
            ("requestBodyBytes".into(), json!(context.request_body_bytes)),
            ("messageCount".into(), json!(context.message_count)),
            (
                "requestFingerprint".into(),
                json!(context.request_fingerprint),
            ),
        ]);
    }
    details.extend(extra);
    details
}

fn observation_event_details<I>(observation: &ProbeObservation, extra: I) -> BTreeMap<String, Value>
where
    I: IntoIterator<Item = (String, Value)>,
{
    let mut details = BTreeMap::from([
        ("httpStatus".into(), json!(observation.status_code)),
        ("latencyMs".into(), json!(observation.latency_ms)),
        ("inputTokens".into(), json!(observation.usage.input_tokens)),
        (
            "outputTokens".into(),
            json!(observation.usage.output_tokens),
        ),
        (
            "cacheReadInputTokens".into(),
            json!(observation.usage.cache_read_input_tokens),
        ),
        (
            "cacheCreationInputTokens".into(),
            json!(observation.usage.cache_creation_input_tokens),
        ),
    ]);
    details.extend(extra);
    details
}

fn collect_probe_results(
    results: Vec<Result<ProbeObservation, CoreError>>,
) -> (Vec<ProbeObservation>, Vec<String>) {
    let mut observations = Vec::new();
    let mut errors = Vec::new();
    for result in results {
        match result {
            Ok(observation) => observations.push(observation),
            Err(error) => errors.push(error.to_string()),
        }
    }
    (observations, errors)
}

fn attach_execution_errors(
    mut evidence: DetectorEvidence,
    errors: &[String],
    request: &ProbeRequest,
) -> DetectorEvidence {
    if errors.is_empty() {
        return evidence;
    }
    evidence
        .details
        .insert("executionErrors".into(), serde_json::json!(errors));
    evidence
        .details
        .insert("failedProbeCount".into(), serde_json::json!(errors.len()));
    let rules = crate::rules::rules_from_request(request)
        .expect("Engine installs validated Core rules before executing strategies");
    let evaluation = &rules.evaluation.execution_errors;
    if evidence.status == EvidenceStatus::Skip {
        evidence.status = EvidenceStatus::Error;
        evidence.basis = crate::EvidenceBasis::Observed;
        evidence.confidence = None;
        evidence.score = 0.0;
        evidence.weight = 0.0;
        evidence.severity = EvidenceSeverity::Major;
        evidence.summary = evaluation.failed_summary.clone();
    } else {
        evidence.status = EvidenceStatus::Warn;
        evidence.severity = evidence.severity.max(EvidenceSeverity::Minor);
        evidence.confidence = evidence
            .confidence
            .map(|value| value * evaluation.confidence_multiplier);
        evidence
            .summary
            .push_str(&evaluation.partial_summary_suffix);
    }
    evidence
}

async fn wait_for_backoff(global_backoff: &Mutex<Option<Instant>>) {
    let deadline = *global_backoff.lock().await;
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    }
}

async fn pending_backoff_ms(global_backoff: &Mutex<Option<Instant>>) -> u64 {
    global_backoff
        .lock()
        .await
        .map(|deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64
        })
        .unwrap_or(0)
}

async fn set_global_backoff(global_backoff: &Mutex<Option<Instant>>, delay: Duration) {
    let candidate = Instant::now() + delay;
    let mut deadline = global_backoff.lock().await;
    if deadline.is_none_or(|current| candidate > current) {
        *deadline = Some(candidate);
    }
}

fn exponential_delay(base: Duration, attempt: usize) -> Duration {
    base.saturating_mul(2_u32.saturating_pow(attempt.min(8) as u32))
        .min(Duration::from_secs(30))
}

fn retry_delay(observation: &ProbeObservation, base: Duration, attempt: usize) -> Duration {
    observation
        .response_headers
        .get("retry-after")
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| exponential_delay(base, attempt))
        .min(Duration::from_secs(30))
}

fn aggregate_performance(observations: &[ProbeObservation]) -> PerformanceMetrics {
    let request_count = observations.len();
    let total_latency_ms = observations.iter().map(|item| item.latency_ms).sum();
    let ttft_ms = observations.iter().filter_map(|item| item.ttft_ms).min();
    let usage = observations
        .iter()
        .fold(UsageMetrics::default(), |mut total, item| {
            total.input_tokens += item.usage.input_tokens;
            total.output_tokens += item.usage.output_tokens;
            total.cache_read_input_tokens += item.usage.cache_read_input_tokens;
            total.cache_creation_input_tokens += item.usage.cache_creation_input_tokens;
            total
        });
    let generation_ms = observations
        .iter()
        .map(|item| item.latency_ms.saturating_sub(item.ttft_ms.unwrap_or(0)))
        .sum::<u64>();
    let tokens_per_second = if generation_ms > 0 && usage.output_tokens > 0 {
        Some(usage.output_tokens as f64 / (generation_ms as f64 / 1000.0))
    } else {
        None
    };
    PerformanceMetrics {
        request_count,
        total_latency_ms,
        average_latency_ms: if request_count > 0 {
            total_latency_ms / request_count as u64
        } else {
            0
        },
        ttft_ms,
        tokens_per_second,
        retry_count: observations.iter().map(|item| item.retry_count).sum(),
        backoff_count: observations.iter().map(|item| item.backoff_count).sum(),
        usage,
    }
}

#[cfg(test)]
mod tests {
    use super::Engine;
    use crate::{
        CORE_CAPABILITY_PROFILE, CoreError, EngineConfig, EvidenceCategory, EvidenceSeverity,
        EvidenceStatus, OutboundProbe, ProbeKind, ProbeMode, ProbeObservation, ProbeRequest,
        ProbeTransport, Protocol, UsageMetrics, Verdict,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    struct FixtureTransport;

    #[async_trait]
    impl ProbeTransport for FixtureTransport {
        async fn execute(
            &self,
            probe: &OutboundProbe,
            _timeout: Duration,
        ) -> Result<ProbeObservation, CoreError> {
            let text = probe.context.as_ref().map_or_else(
                || "Deterministic evidence matters because reproducible observations support reliable comparisons.".into(),
                |metadata| {
                    if metadata.expects_exact_echo {
                        json!({
                            "auditId": metadata.audit_id,
                            "beginMarker": metadata.begin_marker(),
                            "endMarker": metadata.end_marker(),
                            "controlledUnits": metadata.controlled_units,
                            "controlledContext": metadata.controlled_context(),
                        })
                    } else {
                        json!({
                            "auditId": metadata.audit_id,
                            "controlledUnits": metadata.controlled_units,
                            "received": true,
                        })
                    }
                    .to_string()
                },
            );
            let input_tokens = probe
                .context
                .as_ref()
                .map_or(16, |metadata| metadata.visible_input_token_estimate + 24);
            let response = json!({
                "id": "msg_demo",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-4-6",
                "content": [{
                    "type": "thinking",
                    "signature": "s".repeat(128),
                    "thinking": "fixture reasoning"
                }, {"type": "text", "text": text}],
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": {"input_tokens": input_tokens, "output_tokens": 12}
            });
            Ok(ProbeObservation {
                kind: probe.kind,
                challenge_id: probe.challenge_id.clone(),
                status_code: 200,
                latency_ms: 120,
                ttft_ms: Some(45),
                response,
                text,
                usage: UsageMetrics {
                    input_tokens,
                    output_tokens: 12,
                    ..UsageMetrics::default()
                },
                response_headers: Default::default(),
                stream_events: Vec::new(),
                retry_count: 0,
                backoff_count: 0,
                context: probe.context.clone(),
            })
        }
    }

    #[tokio::test]
    async fn a_resolved_fingerprint_bank_reaches_the_identity_evidence() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../SanBiao");
        let repository =
            crate::RuleRepositoryConfig::new("http://127.0.0.1:1/manifest.json", None, false)
                .unwrap()
                .with_fallback_directory(Some(root));
        let report = Engine::new(EngineConfig {
            rule_repository: Some(repository),
            ..EngineConfig::default()
        })
        .detect(
            ProbeRequest {
                base_url: "https://api.example.com".into(),
                api_key: "sk-secret-value".into(),
                model: "claude-sonnet-4-6".into(),
                protocol: Protocol::Anthropic,
                mode: ProbeMode::Quick,
                parameters: Default::default(),
                sections: Vec::new(),
            },
            &FixtureTransport,
        )
        .await
        .expect("fixture detection succeeds");
        let identity = report
            .evidence
            .iter()
            .find(|item| item.name == "identity")
            .expect("identity evidence");
        // The fixture transport returns prose, so the second probe ran but no
        // number could be parsed: the counts are reported, the attribution is
        // marked inconclusive, and no model is claimed.
        assert_eq!(identity.details["numericExpectedCount"], json!(320));
        assert_eq!(identity.details["numericParsedCount"], json!(0));
        assert_eq!(identity.details["attributionInconclusive"], json!(true));
        assert!(!identity.details.contains_key("attributedModel"));
        assert_eq!(report.performance.request_count, 8);
    }

    #[tokio::test]
    async fn engine_produces_masked_verified_report() {
        let report = Engine::default()
            .detect(
                ProbeRequest {
                    base_url: "https://api.example.com".into(),
                    api_key: "sk-secret-value".into(),
                    model: "claude-sonnet-4-6".into(),
                    protocol: Protocol::Anthropic,
                    mode: ProbeMode::Quick,
                    parameters: Default::default(),
                    sections: Vec::new(),
                },
                &FixtureTransport,
            )
            .await
            .expect("fixture detection succeeds");
        assert_eq!(report.verdict, Verdict::Verified);
        assert!(report.id.parse::<ulid::Ulid>().is_ok());
        assert_eq!(report.core.name, "TheStandard");
        assert_eq!(report.core.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(report.core.report_schema_version, 7);
        assert_eq!(report.core.capability_profile, CORE_CAPABILITY_PROFILE);
        assert!(!report.core.capabilities.is_empty());
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("secret-value")
        );
        assert_eq!(report.performance.request_count, 7);
        let presentation = report
            .presentation
            .as_ref()
            .expect("presentation is present");
        assert_eq!(presentation.language, "en");
        assert!(presentation.views.iter().any(|view| view.id == "evidence"));
        assert!(
            serde_json::to_string(presentation)
                .unwrap()
                .contains("reasoning attestation")
        );
        let context = report.context_audit.expect("context audit is present");
        assert!(context.controlled_context_confirmed);
        assert_eq!(context.estimated_fixed_overhead_tokens, Some(24));
    }

    fn coverage_evidence(
        name: &str,
        status: EvidenceStatus,
        score: f64,
        weight: f64,
    ) -> crate::DetectorEvidence {
        crate::DetectorEvidence {
            name: name.into(),
            display_name: name.into(),
            category: EvidenceCategory::Protocol,
            status,
            severity: EvidenceSeverity::Info,
            basis: crate::EvidenceBasis::Observed,
            confidence: Some(0.8),
            score,
            weight,
            summary: "coverage fixture".into(),
            details: Default::default(),
        }
    }

    #[test]
    fn coverage_uses_the_score_denominator_and_never_moves_the_verdict() {
        let engine = Engine::new(EngineConfig::default());
        let evidence = vec![
            coverage_evidence("identity", EvidenceStatus::Pass, 100.0, 10.0),
            coverage_evidence("behavior_scenarios", EvidenceStatus::Warn, 60.0, 5.0),
            // A zero-weight informational detector is verified but adds nothing.
            coverage_evidence("knowledge_cutoff", EvidenceStatus::Pass, 0.0, 0.0),
            coverage_evidence("cache_reuse", EvidenceStatus::Skip, 0.0, 3.0),
            coverage_evidence("context", EvidenceStatus::Error, 0.0, 2.0),
        ];
        let report = engine.report(
            ProbeRequest {
                base_url: "https://example.com".into(),
                api_key: "secret".into(),
                model: "claude-sonnet-4-6".into(),
                protocol: Protocol::Anthropic,
                mode: ProbeMode::Standard,
                parameters: Default::default(),
                sections: Vec::new(),
            },
            evidence,
            Vec::new(),
        );
        // (100 * 10 + 60 * 5) / 15, unchanged by skipped or errored detectors.
        assert_eq!(report.total_score, 86.7);
        assert_eq!(report.coverage.verified_weight, 15.0);
        assert_eq!(report.coverage.applicable_weight, 20.0);
        assert_eq!(report.coverage.ratio, 0.75);
        assert_eq!(report.coverage.unverified_count, 2);
        assert_eq!(report.verdict, Verdict::Verified);

        let value = serde_json::to_value(&report).expect("report serializes");
        assert_eq!(value["coverage"]["verifiedWeight"], json!(15.0));
        assert_eq!(value["coverage"]["applicableWeight"], json!(20.0));
        assert_eq!(value["coverage"]["ratio"], json!(0.75));
        assert_eq!(value["coverage"]["unverifiedCount"], json!(2));

        let presentation = value["presentation"].clone();
        let coverage_section = presentation["views"]
            .as_array()
            .expect("views")
            .iter()
            .find(|view| view["id"] == "overview")
            .and_then(|view| {
                view["sections"]
                    .as_array()?
                    .iter()
                    .find(|section| section["id"] == "coverage")
            })
            .expect("overview coverage section");
        assert_eq!(coverage_section["layout"], "key_value");
        let keys = coverage_section["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .map(|field| field["key"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        for expected in [
            "coverage-ratio",
            "verified-weight",
            "applicable-weight",
            "unverified-detectors",
            "coverage-note",
        ] {
            assert!(keys.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[test]
    fn empty_coverage_ratio_is_zero() {
        let engine = Engine::new(EngineConfig::default());
        let report = engine.report(
            ProbeRequest {
                base_url: "https://example.com".into(),
                api_key: "secret".into(),
                model: "claude-sonnet-4-6".into(),
                protocol: Protocol::Anthropic,
                mode: ProbeMode::Standard,
                parameters: Default::default(),
                sections: Vec::new(),
            },
            vec![coverage_evidence(
                "cache_reuse",
                EvidenceStatus::Skip,
                0.0,
                0.0,
            )],
            Vec::new(),
        );
        assert_eq!(report.coverage.applicable_weight, 0.0);
        assert_eq!(report.coverage.ratio, 0.0);
        assert_eq!(report.coverage.unverified_count, 1);
    }

    #[test]
    fn critical_evidence_caps_verified_score() {
        let engine = Engine::new(EngineConfig::default());
        let evidence = vec![crate::DetectorEvidence {
            name: "signature".into(),
            display_name: "Signature".into(),
            category: EvidenceCategory::Authenticity,
            status: EvidenceStatus::Fail,
            severity: EvidenceSeverity::Critical,
            basis: crate::EvidenceBasis::Observed,
            confidence: Some(0.9),
            score: 90.0,
            weight: 1.0,
            summary: "Critical mismatch".into(),
            details: Default::default(),
        }];
        let observations = vec![ProbeObservation {
            kind: ProbeKind::ReasoningAttestation,
            challenge_id: None,
            status_code: 200,
            latency_ms: 10,
            ttft_ms: None,
            response: json!({}),
            text: String::new(),
            response_headers: Default::default(),
            stream_events: Vec::new(),
            usage: UsageMetrics::default(),
            retry_count: 0,
            backoff_count: 0,
            context: None,
        }];
        let report = engine.report(
            ProbeRequest {
                base_url: "https://example.com".into(),
                api_key: "secret".into(),
                model: "gpt-5".into(),
                protocol: Protocol::Openai,
                mode: ProbeMode::Quick,
                parameters: Default::default(),
                sections: Vec::new(),
            },
            evidence,
            observations,
        );
        assert_eq!(report.verdict, Verdict::Inconclusive);
    }

    struct PartialConsistencyTransport {
        consistency_attempts: AtomicUsize,
    }

    #[async_trait]
    impl ProbeTransport for PartialConsistencyTransport {
        async fn execute(
            &self,
            probe: &OutboundProbe,
            _timeout: Duration,
        ) -> Result<ProbeObservation, CoreError> {
            if probe.kind == ProbeKind::Consistency
                && self.consistency_attempts.fetch_add(1, Ordering::SeqCst) > 0
            {
                return Err(CoreError::Transport(
                    "second consistency sample failed".into(),
                ));
            }

            Ok(ProbeObservation {
                kind: probe.kind,
                challenge_id: probe.challenge_id.clone(),
                status_code: 200,
                latency_ms: 10,
                ttft_ms: Some(4),
                response: json!({
                    "id": "msg_fixture",
                    "type": "message",
                    "model": "claude-sonnet-4-6",
                    "content": [],
                    "usage": {}
                }),
                text: "Stable evidence supports reliable comparisons.".into(),
                response_headers: Default::default(),
                stream_events: Vec::new(),
                usage: UsageMetrics::default(),
                retry_count: 0,
                backoff_count: 0,
                context: probe.context.clone(),
            })
        }
    }

    #[tokio::test]
    async fn failed_probe_samples_are_reported_without_aborting_the_detection() {
        let transport = PartialConsistencyTransport {
            consistency_attempts: AtomicUsize::new(0),
        };
        let result = Engine::new(EngineConfig {
            max_retries: 1,
            retry_backoff: Duration::ZERO,
            ..EngineConfig::default()
        })
        .detect(
            ProbeRequest {
                base_url: "https://api.example.com".into(),
                api_key: "sk-secret-value".into(),
                model: "claude-sonnet-4-6".into(),
                protocol: Protocol::Anthropic,
                mode: ProbeMode::Standard,
                parameters: Default::default(),
                sections: Vec::new(),
            },
            &transport,
        )
        .await;

        let report = result.expect("other evidence remains reportable");
        let consistency = report
            .evidence
            .iter()
            .find(|item| item.name == "consistency")
            .expect("consistency evidence");
        assert_eq!(consistency.status, EvidenceStatus::Warn);
        assert_eq!(consistency.details["failedProbeCount"], 1);
        assert_eq!(transport.consistency_attempts.load(Ordering::SeqCst), 3);
    }

    struct HangingContextTransport;

    #[async_trait]
    impl ProbeTransport for HangingContextTransport {
        async fn execute(
            &self,
            probe: &OutboundProbe,
            timeout: Duration,
        ) -> Result<ProbeObservation, CoreError> {
            if probe.kind == ProbeKind::Context && probe.context.is_some() {
                tokio::time::sleep(timeout.saturating_add(Duration::from_secs(1))).await;
            }
            FixtureTransport.execute(probe, timeout).await
        }
    }

    #[tokio::test]
    async fn timed_out_strategy_does_not_erase_completed_evidence() {
        let report = Engine::new(EngineConfig {
            request_timeout: Duration::from_millis(20),
            max_retries: 3,
            retry_backoff: Duration::ZERO,
            standard_timeout: Duration::from_millis(250),
            ..EngineConfig::default()
        })
        .detect(
            ProbeRequest {
                base_url: "https://api.example.com".into(),
                api_key: "sk-secret-value".into(),
                model: "gpt-5".into(),
                protocol: Protocol::Openai,
                mode: ProbeMode::Standard,
                parameters: Default::default(),
                sections: Vec::new(),
            },
            &HangingContextTransport,
        )
        .await
        .expect("completed evidence should produce a partial report");

        assert!(report.performance.request_count > 0);
        let context = report
            .evidence
            .iter()
            .find(|item| item.name == "context")
            .expect("context evidence remains visible");
        assert_eq!(context.status, EvidenceStatus::Error);
        assert_eq!(context.details["failedProbeCount"], 3);
        assert!(
            !serde_json::to_string(&report)
                .expect("report serializes")
                .contains("secret-value")
        );
    }
}
