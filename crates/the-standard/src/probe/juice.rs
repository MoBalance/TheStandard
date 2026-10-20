//! Empirical reasoning-budget ("juice") fingerprinting for GPT and non-GPT targets.
//!
//! This detector deliberately treats visible budget values as weak, inferred
//! evidence. Values can be changed by a provider or fabricated by a relay, so
//! they never promote a report to the cryptographic tier and are never enough
//! to establish model identity on their own.

use super::{OutboundProbe, ProbeStrategy, strategies::build_probe};
use crate::{
    CoreError, DetectorEvidence, EvidenceBasis, EvidenceCategory, EvidenceSeverity, EvidenceStatus,
    ProbeKind, ProbeObservation, ProbeRequest, Protocol,
    rules::{JuiceRules, rules_from_request},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use ulid::Ulid;
use url::Url;

const MAX_NORMALIZED_VALUE_LENGTH: usize = 16;

/// Build and classify a bounded set of reasoning-budget probes.
pub struct ReasoningBudgetStrategy;

impl ProbeStrategy for ReasoningBudgetStrategy {
    fn name(&self) -> &'static str {
        "reasoning_budget_fingerprint"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        if request
            .parameters
            .get("juiceFingerprintEnabled")
            .and_then(Value::as_bool)
            == Some(false)
        {
            return Ok(Vec::new());
        }
        let Some(bundle) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        let rules = &bundle.strategies.reasoning_budget_fingerprint;

        if !rules.is_gpt_model(&request.model) {
            return build_non_gpt_xml_probes(request, rules);
        }

        if rules.gpt_protocol != protocol_name(request.protocol) {
            return Ok(Vec::new());
        }

        let mut probes = Vec::new();
        for entry in rules.plan(request.mode) {
            for sample_index in 0..entry.samples {
                let template = &rules.templates[sample_index];
                let sample_id = Ulid::new().to_string();
                let prompt = render_prompt(rules, &entry.effort, template, &sample_id);
                let mut probe = build_probe(request, ProbeKind::ReasoningBudget, &prompt)?;
                let mut url = Url::parse(&probe.url)
                    .map_err(|error| CoreError::InvalidEndpoint(error.to_string()))?;
                let path = url.path();
                let response_path = path
                    .strip_suffix("/chat/completions")
                    .map(|prefix| format!("{prefix}/responses"))
                    .unwrap_or_else(|| format!("{}/responses", path.trim_end_matches('/')));
                url.set_path(&response_path);
                probe.url = url.to_string();
                probe.body = json!({
                    "model": request.model,
                    "input": [{
                        "role": "user",
                        "content": [{"type": "input_text", "text": prompt}]
                    }],
                    "reasoning": {"effort": entry.effort},
                    "max_output_tokens": rules.max_output_tokens,
                    "store": false,
                });
                probe.challenge_id = Some(format!(
                    "juice:{}:{}:{sample_id}",
                    entry.effort, template.id
                ));
                probe.demo_response = rules.demo.effort_responses.get(&entry.effort).cloned();
                probes.push(probe);
            }
        }
        Ok(probes)
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(bundle) = rules_from_request(request) else {
            return unavailable_rules_evidence();
        };
        let rules = &bundle.strategies.reasoning_budget_fingerprint;
        let samples = observations
            .iter()
            .filter(|observation| observation.kind == ProbeKind::ReasoningBudget)
            .map(|observation| classify_sample(observation, rules))
            .collect::<Vec<_>>();
        if samples.is_empty() {
            return evidence(
                rules,
                EvidenceStatus::Skip,
                EvidenceSeverity::Info,
                0.0,
                0.0,
                &rules.skipped_summary,
                BTreeMap::from([
                    ("schemaVersion".into(), json!(1)),
                    ("sampleCount".into(), json!(0)),
                    ("ruleBundleStatus".into(), json!("active")),
                    (
                        "calibrationRevision".into(),
                        json!(rules.calibration.revision),
                    ),
                    (
                        "calibrationCompletedAt".into(),
                        json!(rules.calibration.completed_at),
                    ),
                    ("calibrationMethod".into(), json!(rules.calibration.method)),
                    (
                        "calibrationIndependentRuns".into(),
                        json!(rules.calibration.independent_runs),
                    ),
                    ("limitations".into(), json!(rules.limitations)),
                ]),
            );
        }

        if samples.iter().any(|sample| sample.xml_probe) {
            return analyze_non_gpt_guard(&samples, rules, &request.model);
        }

        let valid = samples
            .iter()
            .filter(|sample| sample.value.is_some())
            .count();
        let unknown = samples
            .iter()
            .filter(|sample| matches!(sample.status, "unknown" | "invalid"))
            .count();
        let failed = samples
            .iter()
            .filter(|sample| sample.status == "http_error")
            .count();
        let high_values = samples
            .iter()
            .filter(|sample| {
                sample.effort == rules.primary_effort
                    && sample.value.is_some()
                    && !sample.matches.is_empty()
            })
            .collect::<Vec<_>>();
        let high_intersection = high_values
            .iter()
            .map(|sample| sample.matches.iter().cloned().collect::<BTreeSet<_>>())
            .reduce(|left, right| left.intersection(&right).cloned().collect())
            .unwrap_or_default();
        let primary = (high_values.len() >= rules.primary_minimum_samples
            && high_intersection.len() == 1)
            .then(|| high_intersection.iter().next().cloned())
            .flatten();
        let mixed = high_values.len() >= 2 && high_intersection.is_empty()
            || primary.as_ref().is_some_and(|family| {
                samples.iter().any(|sample| {
                    sample.value.is_some()
                        && sample.effort != rules.primary_effort
                        && !sample.matches.is_empty()
                        && !sample.matches.contains(family)
                })
            });
        let support = primary.as_ref().is_some_and(|family| {
            samples.iter().any(|sample| {
                sample.effort != rules.primary_effort && sample.matches.contains(family)
            })
        });
        let observed_families = samples
            .iter()
            .flat_map(|sample| sample.matches.iter().cloned())
            .collect::<BTreeSet<_>>();
        let (status, severity, outcome, primary_family) = if mixed {
            (
                EvidenceStatus::Warn,
                EvidenceSeverity::Major,
                &rules.scoring.mixed,
                None,
            )
        } else if let Some(family) = primary {
            (
                EvidenceStatus::Pass,
                EvidenceSeverity::Info,
                if support {
                    &rules.scoring.supported_primary
                } else {
                    &rules.scoring.primary_only
                },
                Some(family),
            )
        } else if valid == 0 {
            (
                EvidenceStatus::Warn,
                EvidenceSeverity::Minor,
                &rules.scoring.no_numeric,
                None,
            )
        } else {
            (
                EvidenceStatus::Warn,
                EvidenceSeverity::Minor,
                &rules.scoring.ambiguous,
                None,
            )
        };
        let primary_family_calibration_state = primary_family
            .as_deref()
            .and_then(|family| rules.family_calibration_state(family));

        let efforts = rules
            .families
            .iter()
            .flat_map(|family| family.matches.iter().map(|matcher| matcher.effort.clone()))
            .chain(
                rules
                    .plan(request.mode)
                    .iter()
                    .map(|entry| entry.effort.clone()),
            )
            .collect::<BTreeSet<_>>();
        let effort_details = efforts
            .into_iter()
            .map(|effort| {
                let matching = samples
                    .iter()
                    .filter(|sample| sample.effort == effort)
                    .collect::<Vec<_>>();
                (
                    effort,
                    json!({
                        "sampleCount": matching.len(),
                        "validNumericSamples": matching.iter().filter(|sample| sample.value.is_some()).count(),
                        "values": matching.iter().filter_map(|sample| sample.value.clone()).collect::<Vec<_>>(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let sample_details = samples
            .iter()
            .map(|sample| sample.details(&request.model))
            .collect::<Vec<_>>();
        let route_details = route_diagnostics(&samples, &request.model);
        let usage_details = usage_diagnostics(&samples);
        evidence(
            rules,
            status,
            severity,
            outcome.score,
            rules.scoring.fingerprint_weight,
            &outcome.summary,
            BTreeMap::from([
                ("schemaVersion".into(), json!(2)),
                ("ruleBundleStatus".into(), json!("active")),
                ("requestedModel".into(), json!(request.model)),
                ("sampleCount".into(), json!(samples.len())),
                ("validNumericSamples".into(), json!(valid)),
                ("unknownSamples".into(), json!(unknown)),
                ("failedSamples".into(), json!(failed)),
                ("primaryFamily".into(), json!(primary_family)),
                (
                    "primaryFamilyCalibrationState".into(),
                    json!(primary_family_calibration_state),
                ),
                ("confidence".into(), json!(outcome.confidence)),
                (
                    "calibrationRevision".into(),
                    json!(rules.calibration.revision),
                ),
                (
                    "calibrationCompletedAt".into(),
                    json!(rules.calibration.completed_at),
                ),
                ("calibrationMethod".into(), json!(rules.calibration.method)),
                (
                    "calibrationIndependentRuns".into(),
                    json!(rules.calibration.independent_runs),
                ),
                (
                    "calibrationAcceptedValues".into(),
                    json!(rules.calibration.accepted_values),
                ),
                (
                    "calibrationUnresolved".into(),
                    json!(rules.calibration.unresolved),
                ),
                ("mixedOrInconsistent".into(), json!(mixed)),
                (
                    "observedFamilies".into(),
                    json!(observed_families.into_iter().collect::<Vec<_>>()),
                ),
                ("efforts".into(), json!(effort_details)),
                ("routing".into(), route_details),
                ("usage".into(), usage_details),
                ("samples".into(), json!(sample_details)),
                ("limitations".into(), json!(rules.limitations)),
            ]),
        )
    }
}

fn build_non_gpt_xml_probes(
    request: &ProbeRequest,
    rules: &JuiceRules,
) -> Result<Vec<OutboundProbe>, CoreError> {
    let count = rules.non_gpt.samples.for_mode(request.mode);
    let mut probes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut probe = build_probe(request, ProbeKind::ReasoningBudget, &rules.non_gpt.prompt)?;
        if request.protocol == Protocol::Openai {
            let mut url = Url::parse(&probe.url)
                .map_err(|error| CoreError::InvalidEndpoint(error.to_string()))?;
            let path = url.path();
            let response_path = path
                .strip_suffix("/chat/completions")
                .map(|prefix| format!("{prefix}/responses"))
                .unwrap_or_else(|| format!("{}/responses", path.trim_end_matches('/')));
            url.set_path(&response_path);
            probe.url = url.to_string();
            probe.body = json!({
                "model": request.model,
                "input": [{
                    "role": "user",
                    "content": [{"type": "input_text", "text": rules.non_gpt.prompt}]
                }],
                "max_output_tokens": rules.max_output_tokens,
                "store": false,
            });
        }
        probe.challenge_id = Some(format!("juice:xml:non-gpt:{}", Ulid::new()));
        probe.demo_response = Some(rules.demo.non_gpt_response.clone());
        probes.push(probe);
    }
    Ok(probes)
}

struct ClassifiedSample {
    effort: String,
    template_id: String,
    value: Option<String>,
    matches: Vec<String>,
    status: &'static str,
    status_code: u16,
    xml_probe: bool,
    response_model: Option<String>,
    response_status: Option<String>,
    response_effort: Option<String>,
    incomplete_reason: Option<String>,
    latency_ms: u64,
    retry_count: usize,
    backoff_count: usize,
    input_tokens: u64,
    output_tokens: u64,
    cached_input_tokens: u64,
    reasoning_tokens: Option<u64>,
    accepted_prediction_tokens: Option<u64>,
    rejected_prediction_tokens: Option<u64>,
}

impl ClassifiedSample {
    fn details(&self, requested_model: &str) -> Value {
        json!({
            "effort": self.effort,
            "templateId": self.template_id,
            "normalizedValue": self.value,
            "matches": self.matches,
            "status": self.status,
            "statusCode": self.status_code,
            "responseModel": self.response_model,
            "routeAlias": self.response_model.as_deref().is_some_and(|model| model != requested_model),
            "responseStatus": self.response_status,
            "responseEffort": self.response_effort,
            "incompleteReason": self.incomplete_reason,
            "latencyMs": self.latency_ms,
            "retryCount": self.retry_count,
            "backoffCount": self.backoff_count,
            "usage": {
                "inputTokens": self.input_tokens,
                "outputTokens": self.output_tokens,
                "cachedInputTokens": self.cached_input_tokens,
                "reasoningTokens": self.reasoning_tokens,
                "acceptedPredictionTokens": self.accepted_prediction_tokens,
                "rejectedPredictionTokens": self.rejected_prediction_tokens,
            },
        })
    }
}

fn analyze_non_gpt_guard(
    samples: &[ClassifiedSample],
    rules: &JuiceRules,
    requested_model: &str,
) -> DetectorEvidence {
    let numeric = samples
        .iter()
        .filter_map(|sample| sample.value.as_deref())
        .collect::<Vec<_>>();
    let positive = numeric
        .iter()
        .copied()
        .filter(|value| *value != "0")
        .collect::<Vec<_>>();
    let zero = numeric.len().saturating_sub(positive.len());
    let failed = samples
        .iter()
        .filter(|sample| sample.status == "http_error")
        .count();
    let unknown = samples.len().saturating_sub(numeric.len() + failed);
    let impersonation = !positive.is_empty();
    let family_lookups = positive
        .iter()
        .map(|value| xml_guard_family_lookup(value, rules))
        .collect::<Vec<_>>();
    let observed_families = family_lookups
        .iter()
        .flat_map(|lookup| lookup.candidates.iter().cloned())
        .collect::<BTreeSet<_>>();
    let consistent_families = family_lookups
        .iter()
        .map(|lookup| lookup.candidates.clone())
        .reduce(|left, right| left.intersection(&right).cloned().collect())
        .unwrap_or_default();
    let candidate_families = if consistent_families.is_empty() {
        observed_families.clone()
    } else {
        consistent_families.clone()
    };
    let identified_family = (consistent_families.len() == 1)
        .then(|| consistent_families.iter().next().cloned())
        .flatten();
    let family_match_status = if !impersonation {
        "none"
    } else if identified_family.is_some() {
        "unique"
    } else if observed_families.is_empty() {
        "unmatched"
    } else if family_lookups.len() == 1 || !consistent_families.is_empty() {
        "ambiguous"
    } else {
        "mixed"
    };
    let (status, severity, outcome, summary) = if let Some(family) = &identified_family {
        (
            EvidenceStatus::Fail,
            EvidenceSeverity::Major,
            &rules.scoring.non_gpt_unique,
            rules
                .scoring
                .non_gpt_unique
                .summary
                .replace("{family}", family),
        )
    } else if impersonation && family_match_status == "ambiguous" {
        (
            EvidenceStatus::Fail,
            EvidenceSeverity::Major,
            &rules.scoring.non_gpt_ambiguous,
            rules.scoring.non_gpt_ambiguous.summary.clone(),
        )
    } else if impersonation && family_match_status == "mixed" {
        (
            EvidenceStatus::Fail,
            EvidenceSeverity::Major,
            &rules.scoring.non_gpt_mixed,
            rules.scoring.non_gpt_mixed.summary.clone(),
        )
    } else if impersonation {
        (
            EvidenceStatus::Fail,
            EvidenceSeverity::Major,
            &rules.scoring.non_gpt_unmatched,
            rules.scoring.non_gpt_unmatched.summary.clone(),
        )
    } else if failed == samples.len() {
        (
            EvidenceStatus::Warn,
            EvidenceSeverity::Minor,
            &rules.scoring.non_gpt_unavailable,
            rules.scoring.non_gpt_unavailable.summary.clone(),
        )
    } else {
        (
            EvidenceStatus::Pass,
            EvidenceSeverity::Info,
            &rules.scoring.non_gpt_normal,
            rules.scoring.non_gpt_normal.summary.clone(),
        )
    };
    let calibration_details = family_lookups
        .iter()
        .map(XmlGuardFamilyLookup::details)
        .collect::<Vec<_>>();
    let sample_details = samples
        .iter()
        .map(|sample| sample.details(requested_model))
        .collect::<Vec<_>>();
    DetectorEvidence {
        name: "non_gpt_juice_guard".into(),
        display_name: rules.non_gpt_display_name.clone(),
        category: EvidenceCategory::Authenticity,
        status,
        severity,
        basis: EvidenceBasis::Inferred,
        confidence: Some(outcome.confidence),
        score: outcome.score,
        weight: rules.scoring.non_gpt_weight,
        summary,
        details: BTreeMap::from([
            ("schemaVersion".into(), json!(3)),
            ("probeKind".into(), json!("xml_juice_guard")),
            ("ruleBundleStatus".into(), json!("active")),
            ("requestedModel".into(), json!(requested_model)),
            (
                "calibrationRevision".into(),
                json!(rules.calibration.revision),
            ),
            (
                "calibrationCompletedAt".into(),
                json!(rules.calibration.completed_at),
            ),
            ("calibrationMethod".into(), json!(rules.calibration.method)),
            (
                "calibrationIndependentRuns".into(),
                json!(rules.calibration.independent_runs),
            ),
            (
                "calibrationAcceptedValues".into(),
                json!(rules.calibration.accepted_values),
            ),
            (
                "calibrationUnresolved".into(),
                json!(rules.calibration.unresolved),
            ),
            ("sampleCount".into(), json!(samples.len())),
            ("numericSamples".into(), json!(numeric.len())),
            ("positiveNumericSamples".into(), json!(positive.len())),
            ("zeroSamples".into(), json!(zero)),
            ("unknownSamples".into(), json!(unknown)),
            ("failedSamples".into(), json!(failed)),
            ("gptImpersonationDetected".into(), json!(impersonation)),
            ("observedValues".into(), json!(numeric)),
            ("familyMatchStatus".into(), json!(family_match_status)),
            ("identifiedModelFamily".into(), json!(identified_family)),
            (
                "candidateModelFamilies".into(),
                json!(candidate_families.iter().cloned().collect::<Vec<_>>()),
            ),
            (
                "observedModelFamilies".into(),
                json!(observed_families.iter().cloned().collect::<Vec<_>>()),
            ),
            ("calibrationMatches".into(), json!(calibration_details)),
            (
                "routing".into(),
                route_diagnostics(samples, requested_model),
            ),
            ("usage".into(), usage_diagnostics(samples)),
            ("samples".into(), json!(sample_details)),
            ("limitations".into(), json!(rules.limitations)),
        ]),
    }
}

struct XmlGuardFamilyLookup {
    value: String,
    candidates: BTreeSet<String>,
    effort_matches: Vec<Value>,
}

impl XmlGuardFamilyLookup {
    fn details(&self) -> Value {
        json!({
            "normalizedValue": self.value,
            "candidateFamilies": self.candidates,
            "effortMatches": self.effort_matches,
        })
    }
}

fn xml_guard_family_lookup(value: &str, rules: &JuiceRules) -> XmlGuardFamilyLookup {
    let mut candidates = BTreeSet::new();
    let efforts = rules
        .families
        .iter()
        .flat_map(|family| family.matches.iter().map(|matcher| matcher.effort.clone()))
        .collect::<BTreeSet<_>>();
    let effort_matches = efforts
        .into_iter()
        .filter_map(|effort| {
            let families = rules.families_for(&effort, value);
            if families.is_empty() {
                return None;
            }
            candidates.extend(families.iter().cloned());
            Some(json!({
                "effort": effort,
                "families": families,
            }))
        })
        .collect();
    XmlGuardFamilyLookup {
        value: value.into(),
        candidates,
        effort_matches,
    }
}

fn classify_sample(observation: &ProbeObservation, rules: &JuiceRules) -> ClassifiedSample {
    let (effort, template_id, xml_probe) = parse_challenge_id(observation.challenge_id.as_deref())
        .unwrap_or((rules.primary_effort.clone(), "unknown".into(), false));
    let status_code = observation.status_code;
    let response_model = bounded_response_string(observation.response.get("model"));
    let response_status = bounded_response_string(observation.response.get("status"));
    let response_effort =
        bounded_response_string(observation.response.pointer("/reasoning/effort"));
    let incomplete_reason =
        bounded_response_string(observation.response.pointer("/incomplete_details/reason"));
    let reasoning_tokens =
        usage_extension_u64(observation, "/openai/outputTokensDetails/reasoning_tokens");
    let accepted_prediction_tokens = usage_extension_u64(
        observation,
        "/openai/outputTokensDetails/accepted_prediction_tokens",
    );
    let rejected_prediction_tokens = usage_extension_u64(
        observation,
        "/openai/outputTokensDetails/rejected_prediction_tokens",
    );
    let base = |value, matches, status| ClassifiedSample {
        effort: effort.clone(),
        template_id: template_id.clone(),
        value,
        matches,
        status,
        status_code,
        xml_probe,
        response_model: response_model.clone(),
        response_status: response_status.clone(),
        response_effort: response_effort.clone(),
        incomplete_reason: incomplete_reason.clone(),
        latency_ms: observation.latency_ms,
        retry_count: observation.retry_count,
        backoff_count: observation.backoff_count,
        input_tokens: observation.usage.input_tokens,
        output_tokens: observation.usage.output_tokens,
        cached_input_tokens: observation.usage.cache_read_input_tokens,
        reasoning_tokens,
        accepted_prediction_tokens,
        rejected_prediction_tokens,
    };
    if !(200..300).contains(&status_code) {
        return base(None, Vec::new(), "http_error");
    }
    let Some(value) = normalize_decimal(&observation.text) else {
        return base(
            None,
            Vec::new(),
            if observation.text.trim().is_empty() {
                "unknown"
            } else {
                "invalid"
            },
        );
    };
    let matches = rules.families_for(&effort, &value);
    let status = if matches.is_empty() {
        "unknown"
    } else {
        "valid"
    };
    base(Some(value), matches, status)
}

fn bounded_response_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 160)
        .map(ToOwned::to_owned)
}

fn usage_extension_u64(observation: &ProbeObservation, pointer: &str) -> Option<u64> {
    observation
        .usage
        .provider_extensions
        .as_ref()
        .and_then(|value| value.pointer(pointer))
        .and_then(Value::as_u64)
}

fn route_diagnostics(samples: &[ClassifiedSample], requested_model: &str) -> Value {
    let response_models = samples
        .iter()
        .filter_map(|sample| sample.response_model.clone())
        .collect::<BTreeSet<_>>();
    let response_efforts = samples
        .iter()
        .filter_map(|sample| sample.response_effort.clone())
        .collect::<BTreeSet<_>>();
    let alias_samples = samples
        .iter()
        .filter(|sample| {
            sample
                .response_model
                .as_deref()
                .is_some_and(|model| model != requested_model)
        })
        .count();
    let status_codes =
        samples
            .iter()
            .fold(BTreeMap::<String, usize>::new(), |mut counts, sample| {
                *counts.entry(sample.status_code.to_string()).or_default() += 1;
                counts
            });
    json!({
        "requestedModel": requested_model,
        "responseModels": response_models,
        "responseEfforts": response_efforts,
        "routeAliasObserved": alias_samples > 0,
        "routeAliasSamples": alias_samples,
        "statusCodes": status_codes,
        "retryCount": samples.iter().map(|sample| sample.retry_count).sum::<usize>(),
        "backoffCount": samples.iter().map(|sample| sample.backoff_count).sum::<usize>(),
    })
}

fn usage_diagnostics(samples: &[ClassifiedSample]) -> Value {
    let reasoning = samples
        .iter()
        .filter_map(|sample| sample.reasoning_tokens)
        .collect::<Vec<_>>();
    let accepted_prediction = samples
        .iter()
        .filter_map(|sample| sample.accepted_prediction_tokens)
        .collect::<Vec<_>>();
    let rejected_prediction = samples
        .iter()
        .filter_map(|sample| sample.rejected_prediction_tokens)
        .collect::<Vec<_>>();
    json!({
        "inputTokens": samples.iter().map(|sample| sample.input_tokens).sum::<u64>(),
        "outputTokens": samples.iter().map(|sample| sample.output_tokens).sum::<u64>(),
        "cachedInputTokens": samples.iter().map(|sample| sample.cached_input_tokens).sum::<u64>(),
        "reasoningTokens": (!reasoning.is_empty()).then(|| reasoning.iter().sum::<u64>()),
        "reasoningTokenSamples": reasoning,
        "acceptedPredictionTokens": (!accepted_prediction.is_empty()).then(|| accepted_prediction.iter().sum::<u64>()),
        "rejectedPredictionTokens": (!rejected_prediction.is_empty()).then(|| rejected_prediction.iter().sum::<u64>()),
    })
}

fn parse_challenge_id(id: Option<&str>) -> Option<(String, String, bool)> {
    let parts = id?.split(':').collect::<Vec<_>>();
    if parts.len() < 3 || parts[0] != "juice" {
        return None;
    }
    if parts[1] == "xml" {
        return Some(("xml".into(), parts[2].to_owned(), true));
    }
    Some((parts[1].to_owned(), parts[2].to_owned(), false))
}

fn normalize_decimal(text: &str) -> Option<String> {
    let value = text.trim();
    if value.is_empty() || value.len() > MAX_NORMALIZED_VALUE_LENGTH || value.starts_with('+') {
        return None;
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || value.bytes().filter(|byte| *byte == b'.').count() > 1
        || value == "."
    {
        return None;
    }
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    if integer.is_empty() && fraction.is_empty() {
        return None;
    }
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        Some(integer.to_owned())
    } else {
        Some(format!("{integer}.{fraction}"))
    }
}

fn render_prompt(
    rules: &JuiceRules,
    effort: &str,
    template: &crate::rules::JuiceTemplate,
    sample_id: &str,
) -> String {
    rules
        .prompt_template
        .replace("{sampleId}", sample_id)
        .replace("{transformation}", &template.transformation)
        .replace("{effort}", effort)
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Anthropic => "anthropic",
        Protocol::Openai => "openai",
        Protocol::Gemini => "gemini",
    }
}

fn unavailable_rules_evidence() -> DetectorEvidence {
    DetectorEvidence {
        name: "reasoning_budget_fingerprint".into(),
        display_name: "Reasoning budget fingerprint".into(),
        category: EvidenceCategory::Authenticity,
        status: EvidenceStatus::Error,
        severity: EvidenceSeverity::Major,
        basis: EvidenceBasis::Unsupported,
        confidence: None,
        score: 0.0,
        weight: 0.0,
        summary: "The versioned Core rule bundle is unavailable; this detector was not executed."
            .into(),
        details: BTreeMap::from([
            ("schemaVersion".into(), json!(1)),
            ("ruleBundleStatus".into(), json!("unavailable")),
        ]),
    }
}

fn evidence(
    rules: &JuiceRules,
    status: EvidenceStatus,
    severity: EvidenceSeverity,
    score: f64,
    weight: f64,
    summary: &str,
    details: BTreeMap<String, Value>,
) -> DetectorEvidence {
    DetectorEvidence {
        name: "reasoning_budget_fingerprint".into(),
        display_name: rules.display_name.clone(),
        category: EvidenceCategory::Authenticity,
        status,
        severity,
        basis: if status == EvidenceStatus::Skip {
            EvidenceBasis::Unsupported
        } else {
            EvidenceBasis::Inferred
        },
        confidence: details.get("confidence").and_then(Value::as_f64),
        score,
        weight,
        summary: summary.into(),
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::{ReasoningBudgetStrategy, normalize_decimal};
    use crate::{
        CORE_CAPABILITY_PROFILE, CoreRuleBundle, ProbeKind, ProbeMode, ProbeObservation,
        ProbeRequest, ProbeStrategy, Protocol, rules::install_rule_bundle,
    };
    use serde_json::{Value, json};
    use std::{path::PathBuf, sync::Arc, time::Duration};

    fn test_bundle() -> Arc<CoreRuleBundle> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../SanBiao/rules/the-standard/stable.json");
        Arc::new(
            CoreRuleBundle::from_document(&std::fs::read(path).unwrap(), None)
                .expect("shared Knowledge rule fixture"),
        )
    }

    fn non_gpt_prompt() -> String {
        test_bundle()
            .rules
            .strategies
            .reasoning_budget_fingerprint
            .non_gpt
            .prompt
            .clone()
    }

    fn request(mode: ProbeMode) -> ProbeRequest {
        let mut request = ProbeRequest {
            base_url: "https://example.com/v1".into(),
            api_key: "secret-key".into(),
            model: "gpt-5.6-sol".into(),
            protocol: Protocol::Openai,
            mode,
            parameters: Default::default(),
            sections: Vec::new(),
        };
        let bundle = test_bundle();
        install_rule_bundle(&mut request, Some(&bundle));
        request
    }

    fn non_gpt_request(protocol: Protocol, mode: ProbeMode) -> ProbeRequest {
        ProbeRequest {
            model: "claude-sonnet-4-6".into(),
            protocol,
            ..request(mode)
        }
    }

    fn observation(id: &str, status: u16, text: &str) -> ProbeObservation {
        let mut item =
            ProbeObservation::fixture(ProbeKind::ReasoningBudget, status, json!({}), text);
        item.challenge_id = Some(id.into());
        item
    }

    fn routed_observation(id: &str, text: &str) -> ProbeObservation {
        let mut item = observation(id, 200, text);
        item.latency_ms = 321;
        item.retry_count = 2;
        item.backoff_count = 1;
        item.response = json!({
            "model": "gpt-5.5",
            "status": "completed",
            "reasoning": {"effort": "xhigh"}
        });
        item.usage.input_tokens = 128;
        item.usage.output_tokens = 16;
        item.usage.cache_read_input_tokens = 64;
        item.usage.provider_extensions = Some(json!({
            "openai": {
                "outputTokensDetails": {
                    "reasoning_tokens": 12,
                    "accepted_prediction_tokens": 2,
                    "rejected_prediction_tokens": 1
                }
            }
        }));
        item
    }

    #[test]
    fn quick_and_non_openai_modes_skip_building() {
        assert!(
            ReasoningBudgetStrategy
                .build(&request(ProbeMode::Quick))
                .unwrap()
                .is_empty()
        );
        let mut anthropic = request(ProbeMode::Standard);
        anthropic.protocol = Protocol::Anthropic;
        assert!(
            ReasoningBudgetStrategy
                .build(&anthropic)
                .unwrap()
                .is_empty()
        );
        let evidence = ReasoningBudgetStrategy.analyze(&request(ProbeMode::Quick), &[]);
        assert_eq!(evidence.status, crate::EvidenceStatus::Skip);
        assert_eq!(evidence.basis, crate::EvidenceBasis::Unsupported);
    }

    #[test]
    fn standard_and_full_have_bounded_sampling() {
        assert_eq!(
            ReasoningBudgetStrategy
                .build(&request(ProbeMode::Standard))
                .unwrap()
                .len(),
            5
        );
        assert_eq!(
            ReasoningBudgetStrategy
                .build(&request(ProbeMode::Full))
                .unwrap()
                .len(),
            15
        );
    }

    #[test]
    fn non_gpt_xml_guard_uses_the_selected_protocol_shape() {
        let anthropic = ReasoningBudgetStrategy
            .build(&non_gpt_request(Protocol::Anthropic, ProbeMode::Standard))
            .unwrap();
        assert_eq!(anthropic.len(), 1);
        assert!(anthropic[0].url.ends_with("/v1/messages"));
        assert_eq!(
            anthropic[0].body.pointer("/messages/0/content"),
            Some(&json!(non_gpt_prompt()))
        );
        assert!(
            anthropic[0]
                .challenge_id
                .as_deref()
                .is_some_and(|id| id.starts_with("juice:xml:non-gpt:"))
        );

        let gemini = ReasoningBudgetStrategy
            .build(&non_gpt_request(Protocol::Gemini, ProbeMode::Standard))
            .unwrap();
        assert_eq!(gemini.len(), 1);
        assert!(gemini[0].url.ends_with("/v1/chat/completions"));
        assert_eq!(
            gemini[0].body.pointer("/messages/0/content"),
            Some(&json!(non_gpt_prompt()))
        );

        let openai = ReasoningBudgetStrategy
            .build(&non_gpt_request(Protocol::Openai, ProbeMode::Standard))
            .unwrap();
        assert_eq!(openai.len(), 1);
        assert!(openai[0].url.ends_with("/v1/responses"));
        assert_eq!(
            openai[0].body.pointer("/input/0/content/0/text"),
            Some(&json!(non_gpt_prompt()))
        );
        assert_eq!(openai[0].body["store"], json!(false));
        assert!(openai[0].body.get("reasoning").is_none());
    }

    #[test]
    fn non_gpt_xml_guard_has_bounded_sampling_and_exact_payload() {
        let quick = ReasoningBudgetStrategy
            .build(&non_gpt_request(Protocol::Anthropic, ProbeMode::Quick))
            .unwrap();
        let full = ReasoningBudgetStrategy
            .build(&non_gpt_request(Protocol::Anthropic, ProbeMode::Full))
            .unwrap();
        assert!(quick.is_empty());
        assert_eq!(full.len(), 3);
        let non_gpt_prompt = non_gpt_prompt();
        assert!(full.iter().all(|probe| {
            probe.body.pointer("/messages/0/content") == Some(&json!(non_gpt_prompt))
        }));
        let challenge_ids = full
            .iter()
            .filter_map(|probe| probe.challenge_id.as_deref())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(challenge_ids.len(), 3);
        assert!(non_gpt_prompt.starts_with("<?xml version="));
        assert!(non_gpt_prompt.contains("<juice_level>"));
    }

    #[test]
    fn responses_endpoint_and_body_are_safe() {
        let probe = ReasoningBudgetStrategy
            .build(&request(ProbeMode::Standard))
            .unwrap()
            .remove(0);
        assert!(probe.url.ends_with("/v1/responses"));
        assert_eq!(probe.body["store"], json!(false));
        assert!(probe.body.pointer("/reasoning/effort").is_some());
        assert!(probe.body.get("api_key").is_none());
        let prompt = probe
            .body
            .pointer("/input/0/content/0/text")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        assert!(prompt.contains("numeric reasoning budget"));
        assert!(prompt.contains("preserve B exactly"));
        assert!(!prompt.contains("37 + 5"));
        assert!(!prompt.contains("40855"));
    }

    #[test]
    fn sol_high_samples_with_low_support_are_classified() {
        let strategy = ReasoningBudgetStrategy;
        let observations = vec![
            observation("juice:high:arithmetic-identity:01", 200, "40805"),
            observation("juice:high:symbolic-identity:02", 200, "40855"),
            observation("juice:high:bounded-identity:03", 200, "40805"),
            observation("juice:low:arithmetic-identity:04", 200, "8"),
        ];
        let evidence = strategy.analyze(&request(ProbeMode::Standard), &observations);
        assert_eq!(evidence.status, crate::EvidenceStatus::Pass);
        assert_eq!(evidence.details["primaryFamily"], json!("gpt-5.6-sol"));
        assert_eq!(evidence.details["mixedOrInconsistent"], json!(false));
        assert_eq!(
            evidence.details["observedFamilies"],
            json!(["gpt-5.6-luna", "gpt-5.6-sol"])
        );
        assert!(
            !serde_json::to_string(&evidence.details)
                .unwrap()
                .contains("TheStandard runtime-budget sample")
        );
    }

    #[test]
    fn high_conflict_is_warn_and_overlap_alone_is_not_conflict() {
        let strategy = ReasoningBudgetStrategy;
        let conflict = strategy.analyze(
            &request(ProbeMode::Standard),
            &[
                observation("juice:high:a:01", 200, "40855"),
                observation("juice:high:b:02", 200, "48"),
                observation("juice:high:c:03", 200, "96"),
            ],
        );
        assert_eq!(conflict.details["mixedOrInconsistent"], json!(true));
        assert_eq!(conflict.status, crate::EvidenceStatus::Warn);
        let overlap = strategy.analyze(
            &request(ProbeMode::Standard),
            &[observation("juice:low:a:01", 200, "8")],
        );
        assert_eq!(overlap.details["mixedOrInconsistent"], json!(false));
    }

    #[test]
    fn uncalibrated_reasoning_token_scale_values_are_not_identity_candidates() {
        let strategy = ReasoningBudgetStrategy;
        let evidence = strategy.analyze(
            &request(ProbeMode::Standard),
            &[
                observation("juice:high:a:01", 200, "40850"),
                observation("juice:high:b:02", 200, "9677"),
                observation("juice:high:c:03", 200, "40850"),
                observation("juice:low:d:04", 200, "8"),
            ],
        );
        assert_eq!(evidence.details["primaryFamily"], json!(null));
        assert_eq!(evidence.status, crate::EvidenceStatus::Warn);
        assert_eq!(
            evidence.details["observedFamilies"],
            json!(["gpt-5.6-luna", "gpt-5.6-sol"])
        );
    }

    #[test]
    fn enabled_calibrated_high_families_require_no_raw_answer_storage() {
        let strategy = ReasoningBudgetStrategy;
        let cases = [
            ("48", "juice:low:a:04", "8", "gpt-5.6-luna"),
            ("96", "juice:low:a:04", "12", "gpt-5.5-or-gpt-5.4-family"),
        ];
        for (high, supporting_id, supporting, expected) in cases {
            let observations = vec![
                observation("juice:high:a:01", 200, high),
                observation("juice:high:b:02", 200, high),
                observation("juice:high:c:03", 200, high),
                observation(supporting_id, 200, supporting),
            ];
            let evidence = strategy.analyze(&request(ProbeMode::Standard), &observations);
            assert_eq!(evidence.details["primaryFamily"], json!(expected));
            assert_eq!(evidence.status, crate::EvidenceStatus::Pass);
            let serialized = serde_json::to_string(&evidence.details).unwrap();
            assert!(!serialized.contains("Evaluate"));
            assert!(!serialized.contains("secret-key"));
        }
    }

    #[test]
    fn unstable_and_historical_families_do_not_drive_classification() {
        let strategy = ReasoningBudgetStrategy;
        for value in ["32", "64"] {
            let evidence = strategy.analyze(
                &request(ProbeMode::Standard),
                &[
                    observation("juice:high:a:01", 200, value),
                    observation("juice:high:b:02", 200, value),
                    observation("juice:high:c:03", 200, value),
                ],
            );
            assert_eq!(evidence.details["primaryFamily"], Value::Null);
            assert_eq!(evidence.details["observedFamilies"], json!([]));
            assert_eq!(evidence.status, crate::EvidenceStatus::Warn);
        }
    }

    #[test]
    fn canonical_fractional_sol_observation_is_classified() {
        let strategy = ReasoningBudgetStrategy;
        let evidence = strategy.analyze(
            &request(ProbeMode::Full),
            &[observation(
                "juice:low:arithmetic-identity:01",
                200,
                "8.855",
            )],
        );
        assert_eq!(evidence.details["observedFamilies"], json!(["gpt-5.6-sol"]));
        assert_eq!(evidence.details["samples"][0]["status"], json!("valid"));
    }

    #[test]
    fn report_exposes_route_and_usage_diagnostics_without_raw_prompt_data() {
        let evidence = ReasoningBudgetStrategy.analyze(
            &request(ProbeMode::Full),
            &[routed_observation(
                "juice:xhigh:arithmetic-identity:01",
                "768",
            )],
        );
        assert_eq!(evidence.details["schemaVersion"], json!(2));
        assert_eq!(
            evidence.details["routing"]["routeAliasObserved"],
            json!(true)
        );
        assert_eq!(
            evidence.details["routing"]["responseModels"],
            json!(["gpt-5.5"])
        );
        assert_eq!(evidence.details["routing"]["retryCount"], json!(2));
        assert_eq!(evidence.details["usage"]["reasoningTokens"], json!(12));
        assert_eq!(
            evidence.details["samples"][0]["responseEffort"],
            json!("xhigh")
        );
        assert_eq!(
            evidence.details["samples"][0]["usage"]["cachedInputTokens"],
            json!(64)
        );
        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains("secret-key"));
        assert!(!serialized.contains("runtime-budget sample"));
    }

    #[test]
    fn parser_accepts_decimal_and_rejects_narrative() {
        assert_eq!(normalize_decimal(" 008.8550 "), Some("8.855".into()));
        assert_eq!(normalize_decimal("40\n"), Some("40".into()));
        assert_eq!(normalize_decimal("40 tokens"), None);
        assert_eq!(normalize_decimal("1e3"), None);
    }

    #[test]
    fn non_gpt_numeric_juice_exposure_fails_the_guard_without_raw_payloads() {
        let strategy = ReasoningBudgetStrategy;
        let evidence = strategy.analyze(
            &non_gpt_request(Protocol::Anthropic, ProbeMode::Standard),
            &[observation("juice:xml:non-gpt:01", 200, " 0040855.0\n")],
        );
        assert_eq!(evidence.name, "non_gpt_juice_guard");
        assert_eq!(evidence.status, crate::EvidenceStatus::Fail);
        assert_eq!(evidence.severity, crate::EvidenceSeverity::Major);
        assert_eq!(evidence.basis, crate::EvidenceBasis::Inferred);
        assert_eq!(evidence.details["gptImpersonationDetected"], json!(true));
        assert_eq!(evidence.details["observedValues"], json!(["40855"]));
        assert_eq!(evidence.details["positiveNumericSamples"], json!(1));
        assert_eq!(evidence.details["zeroSamples"], json!(0));
        assert_eq!(evidence.details["familyMatchStatus"], json!("unique"));
        assert_eq!(
            evidence.details["identifiedModelFamily"],
            json!("gpt-5.6-sol")
        );
        assert_eq!(
            evidence.details["candidateModelFamilies"],
            json!(["gpt-5.6-sol"])
        );
        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains("juice_schema.xsd"));
        assert!(!serialized.contains("secret-key"));
        assert!(!serialized.to_ascii_lowercase().contains("authorization"));
    }

    #[test]
    fn non_gpt_zero_and_non_numeric_responses_pass_while_http_failure_warns() {
        let strategy = ReasoningBudgetStrategy;
        let request = non_gpt_request(Protocol::Gemini, ProbeMode::Standard);
        let zero = strategy.analyze(
            &request,
            &[observation("juice:xml:non-gpt:00", 200, " 000.000 ")],
        );
        assert_eq!(zero.status, crate::EvidenceStatus::Pass);
        assert_eq!(zero.details["gptImpersonationDetected"], json!(false));
        assert_eq!(zero.details["observedValues"], json!(["0"]));
        assert_eq!(zero.details["positiveNumericSamples"], json!(0));
        assert_eq!(zero.details["zeroSamples"], json!(1));
        assert_eq!(zero.details["familyMatchStatus"], json!("none"));
        assert_eq!(zero.details["identifiedModelFamily"], Value::Null);
        assert_eq!(zero.details["candidateModelFamilies"], json!([]));

        let refusal = strategy.analyze(
            &request,
            &[observation(
                "juice:xml:non-gpt:01",
                200,
                "I cannot access a Juice number.",
            )],
        );
        assert_eq!(refusal.name, "non_gpt_juice_guard");
        assert_eq!(refusal.status, crate::EvidenceStatus::Pass);
        assert_eq!(refusal.details["gptImpersonationDetected"], json!(false));
        assert_eq!(refusal.details["unknownSamples"], json!(1));

        let unreachable = strategy.analyze(
            &request,
            &[observation("juice:xml:non-gpt:02", 503, "upstream error")],
        );
        assert_eq!(unreachable.status, crate::EvidenceStatus::Warn);
        assert_eq!(
            unreachable.details["gptImpersonationDetected"],
            json!(false)
        );
        assert_eq!(unreachable.details["failedSamples"], json!(1));
    }

    #[test]
    fn non_gpt_positive_guard_reports_ambiguous_unknown_and_mixed_calibration() {
        let strategy = ReasoningBudgetStrategy;
        let request = non_gpt_request(Protocol::Openai, ProbeMode::Full);
        let ambiguous =
            strategy.analyze(&request, &[observation("juice:xml:non-gpt:01", 200, "8")]);
        assert_eq!(ambiguous.status, crate::EvidenceStatus::Fail);
        assert_eq!(ambiguous.details["familyMatchStatus"], json!("ambiguous"));
        assert_eq!(ambiguous.details["identifiedModelFamily"], Value::Null);
        assert_eq!(
            ambiguous.details["candidateModelFamilies"],
            json!(["gpt-5.6-luna", "gpt-5.6-sol"])
        );

        let unknown = strategy.analyze(&request, &[observation("juice:xml:non-gpt:02", 200, "41")]);
        assert_eq!(unknown.status, crate::EvidenceStatus::Fail);
        assert_eq!(unknown.details["familyMatchStatus"], json!("unmatched"));
        assert_eq!(unknown.details["candidateModelFamilies"], json!([]));

        let mixed = strategy.analyze(
            &request,
            &[
                observation("juice:xml:non-gpt:03", 200, "40855"),
                observation("juice:xml:non-gpt:04", 200, "768"),
                observation("juice:xml:non-gpt:05", 200, "0"),
            ],
        );
        assert_eq!(mixed.status, crate::EvidenceStatus::Fail);
        assert_eq!(mixed.details["familyMatchStatus"], json!("mixed"));
        assert_eq!(mixed.details["identifiedModelFamily"], Value::Null);
        assert_eq!(
            mixed.details["candidateModelFamilies"],
            json!(["gpt-5.5-or-gpt-5.4-family", "gpt-5.6-luna", "gpt-5.6-sol"])
        );
        assert_eq!(mixed.details["positiveNumericSamples"], json!(2));
        assert_eq!(mixed.details["zeroSamples"], json!(1));
    }

    #[tokio::test]
    async fn engine_demo_report_contains_inferred_juice_evidence() {
        let engine = crate::Engine::new(crate::EngineConfig {
            standard_timeout: Duration::from_secs(10),
            rule_bundle: Some(test_bundle()),
            ..crate::EngineConfig::default()
        });
        let report = engine
            .detect(request(ProbeMode::Standard), &crate::DemoTransport)
            .await
            .expect("demo detection");
        let juice = report
            .evidence
            .iter()
            .find(|item| item.name == "reasoning_budget_fingerprint")
            .expect("juice evidence");
        assert_eq!(juice.basis, crate::EvidenceBasis::Inferred);
        assert_eq!(juice.details["primaryFamily"], json!("gpt-5.6-sol"));
        assert_eq!(report.tier, crate::DetectionTier::Protocol);
        assert_eq!(report.core.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(report.core.capability_profile, CORE_CAPABILITY_PROFILE);
        assert_eq!(juice.details["calibrationRevision"], json!("2026.08.15.1"));
        assert_eq!(
            juice.details["primaryFamilyCalibrationState"],
            json!("partial")
        );
        let relay = report
            .evidence
            .iter()
            .find(|item| item.name == "relay_payload_integrity")
            .expect("relay integrity evidence");
        assert!(relay.details.contains_key("observationsExamined"));
    }

    #[tokio::test]
    async fn engine_demo_non_gpt_report_contains_xml_guard_evidence() {
        let engine = crate::Engine::new(crate::EngineConfig {
            standard_timeout: Duration::from_secs(10),
            rule_bundle: Some(test_bundle()),
            ..crate::EngineConfig::default()
        });
        let report = engine
            .detect(
                non_gpt_request(Protocol::Anthropic, ProbeMode::Standard),
                &crate::DemoTransport,
            )
            .await
            .expect("demo non-GPT detection");
        let guard = report
            .evidence
            .iter()
            .find(|item| item.name == "non_gpt_juice_guard")
            .expect("non-GPT Juice guard evidence");
        assert_eq!(guard.status, crate::EvidenceStatus::Pass);
        assert_eq!(guard.details["gptImpersonationDetected"], json!(false));
        assert_eq!(report.core.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(guard.details["calibrationRevision"], json!("2026.08.15.1"));
    }
}
