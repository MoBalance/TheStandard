use super::{OutboundProbe, ProbeStrategy};
use crate::{
    ContextAuditSample, ContextAuditSummary, ContextEchoStatus, ContextOverheadAssessment,
    ContextProbeMetadata, CoreError, DetectorEvidence, EvidenceBasis, EvidenceCategory,
    EvidenceSeverity, EvidenceStatus, ProbeKind, ProbeObservation, ProbeRequest, Protocol,
    fingerprint::{
        NUMERIC_PROBE_MAX_TOKENS, NUMERIC_PROBE_PROMPT, attribution_details, bank_from_request,
    },
    rules::{IdentityProbeRules, ReasoningAttestationRules, rules_from_request},
    signature::{extract_text_fingerprint, similarity},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use ulid::Ulid;
use url::Url;

pub struct IdentityStrategy;
pub struct ReasoningAttestationStrategy;
pub struct ProtocolStrategy;
pub struct ContextAuditStrategy;
pub struct ConsistencyStrategy;

impl ProbeStrategy for IdentityStrategy {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        let identity = &rules.probes.identity;
        let family = expected_model_family(&request.model, Some(identity));
        let provider = inferred_provider(&request.model, Some(identity)).unwrap_or_default();
        let mut probe = build_probe(request, ProbeKind::Identity, &identity.prompt)?;
        probe.demo_response = Some(
            identity
                .demo_response_template
                .replace("{model}", &request.model)
                .replace("{family}", &family)
                .replace("{provider}", &provider),
        );
        let mut probes = vec![probe];
        // A resolved numeric bank earns a second identity observation. Without
        // one the detector keeps its single probe and emits no attribution.
        if bank_from_request(request).is_some() {
            let mut numeric =
                build_probe(request, ProbeKind::NumericFingerprint, NUMERIC_PROBE_PROMPT)?;
            numeric.body["max_tokens"] = json!(NUMERIC_PROBE_MAX_TOKENS);
            probes.push(numeric);
        }
        Ok(probes)
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("identity", EvidenceCategory::Authenticity);
        };
        let evaluation = &rules.evaluation.identity;
        let Some(observation) = observations
            .iter()
            .find(|observation| observation.kind == ProbeKind::Identity)
        else {
            return skipped(
                "identity",
                &evaluation.display_name,
                EvidenceCategory::Authenticity,
                &rules.evaluation.skipped_summary,
            );
        };
        let declared_model = observation
            .response
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let identity_rules = &rules.probes.identity;
        let expected_family = expected_model_family(&request.model, Some(identity_rules));
        let expected_provider = request
            .parameters
            .get("expectedProvider")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .or_else(|| inferred_provider(&request.model, Some(identity_rules)));
        let metadata_matches =
            !declared_model.is_empty() && declared_model.to_lowercase().contains(&expected_family);
        let self_report = observation.text.to_ascii_lowercase();
        let self_report_matches =
            !expected_family.is_empty() && self_report.contains(&expected_family);
        let provider_matches = expected_provider
            .as_deref()
            .map(|provider| self_report.contains(provider));
        let status_ok = (200..300).contains(&observation.status_code);
        let score = if status_ok {
            (if metadata_matches {
                evaluation.metadata_points
            } else {
                0.0
            }) + (if self_report_matches {
                evaluation.self_report_points
            } else {
                0.0
            }) + match provider_matches {
                Some(true) => evaluation.provider_points,
                Some(false) => 0.0,
                None if self_report_matches => evaluation.provider_points,
                None => 0.0,
            }
        } else {
            0.0
        };
        let mut details = BTreeMap::from([
            ("declaredModel".into(), json!(declared_model)),
            ("expectedModelFamily".into(), json!(expected_family)),
            ("expectedProvider".into(), json!(expected_provider)),
            ("metadataMatches".into(), json!(metadata_matches)),
            ("selfReportMatches".into(), json!(self_report_matches)),
            ("providerMatches".into(), json!(provider_matches)),
            ("selfReport".into(), json!(observation.text)),
        ]);
        // Attribution is informational: it rides along with the identity
        // details and never touches the score, the status or the severity.
        details.extend(numeric_attribution(request, observations));
        evidence_with_basis(
            EvidenceSpec {
                name: "identity",
                display_name: &evaluation.display_name,
                category: EvidenceCategory::Authenticity,
                status: rules.evaluation.grade.status(score),
                severity: rules.evaluation.grade.severity(score),
                score,
                weight: evaluation.weight,
                summary: if metadata_matches
                    && self_report_matches
                    && provider_matches != Some(false)
                {
                    &evaluation.matched_summary
                } else if metadata_matches || self_report_matches {
                    &evaluation.partial_summary
                } else {
                    &evaluation.mismatch_summary
                },
            },
            details,
            EvidenceBasis::Inferred,
            Some(evaluation.confidence),
        )
    }
}

fn expected_model_family(model: &str, rules: Option<&IdentityProbeRules>) -> String {
    let lower = model.trim().to_ascii_lowercase();
    rules
        .and_then(|rules| {
            rules
                .families
                .iter()
                .find(|family| lower.contains(&family.marker))
        })
        .map(|family| family.marker.clone())
        .unwrap_or_else(|| {
            lower
                .split(['-', ':', '/'])
                .next()
                .unwrap_or_default()
                .to_owned()
        })
}

fn inferred_provider(model: &str, rules: Option<&IdentityProbeRules>) -> Option<String> {
    let lower = model.to_ascii_lowercase();
    rules
        .and_then(|rules| {
            rules
                .families
                .iter()
                .find(|family| lower.contains(&family.marker))
        })
        .map(|family| family.provider.clone())
}

/// Numeric model attribution for the identity evidence.
///
/// Returns an empty map when no numeric bank was resolved or when the second
/// probe did not run, so an unavailable bank never shows up as a zero or a
/// null attribution.
fn numeric_attribution(
    request: &ProbeRequest,
    observations: &[ProbeObservation],
) -> BTreeMap<String, Value> {
    let Some(bank) = bank_from_request(request) else {
        return BTreeMap::new();
    };
    let Some(observation) = observations
        .iter()
        .find(|observation| observation.kind == ProbeKind::NumericFingerprint)
    else {
        return BTreeMap::new();
    };
    attribution_details(&bank, &observation.text)
}

impl ProbeStrategy for ReasoningAttestationStrategy {
    fn name(&self) -> &'static str {
        "reasoning_attestation"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        if request.protocol != Protocol::Anthropic {
            return Ok(Vec::new());
        }
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        let attestation = &rules.probes.reasoning_attestation;
        let mut probe = build_probe(
            request,
            ProbeKind::ReasoningAttestation,
            &attestation.prompt,
        )?;
        configure_reasoning_probe(&mut probe, &request.model, attestation);
        probe.demo_response = Some(attestation.demo_response.clone());
        Ok(vec![probe])
    }

    fn follow_up(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> Result<Vec<OutboundProbe>, CoreError> {
        if request
            .parameters
            .get("strictAttestation")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        let attestation = &rules.probes.reasoning_attestation;
        let Some(first) = observations.first() else {
            return Ok(Vec::new());
        };
        let Some(content) = first.response.get("content").and_then(Value::as_array) else {
            return Ok(Vec::new());
        };
        let has_attestation = content.iter().any(|block| {
            matches!(
                block.get("type").and_then(Value::as_str),
                Some("thinking" | "redacted_thinking")
            ) && (block
                .get("signature")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
                || block
                    .get("data")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty()))
        });
        if !has_attestation {
            return Ok(Vec::new());
        }
        let mut probe = build_probe(
            request,
            ProbeKind::ReasoningAttestation,
            &attestation.follow_up_prompt,
        )?;
        probe.body["max_tokens"] = json!(attestation.follow_up_max_tokens);
        probe.body["messages"] = json!([
            {"role": "user", "content": attestation.prompt},
            {"role": "assistant", "content": content},
            {"role": "user", "content": attestation.follow_up_prompt}
        ]);
        probe
            .body
            .as_object_mut()
            .expect("request body is an object")
            .remove("thinking");
        probe
            .body
            .as_object_mut()
            .expect("request body is an object")
            .remove("output_config");
        probe.demo_response = Some(attestation.demo_follow_up_response.clone());
        Ok(vec![probe])
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("reasoning_attestation", EvidenceCategory::Authenticity);
        };
        let evaluation = &rules.evaluation.reasoning_attestation;
        let Some(observation) = observations.first() else {
            return skipped(
                "reasoning_attestation",
                &evaluation.display_name,
                EvidenceCategory::Authenticity,
                &rules.evaluation.skipped_summary,
            );
        };
        let fingerprint = extract_text_fingerprint(&observation.text);
        let (reasoning_block_present, signature, protected) =
            reasoning_attestation(&observation.response);
        let continuation_attempted = observations.len() > 1;
        let continuation_validated = observations
            .get(1)
            .is_some_and(|item| (200..300).contains(&item.status_code));
        let attestation_length = signature.map(str::len).or_else(|| protected.map(str::len));
        let shape_plausible = signature
            .is_some_and(|value| opaque_attestation_shape(value, evaluation.minimum_opaque_length))
            || protected.is_some_and(|value| {
                opaque_attestation_shape(value, evaluation.minimum_opaque_length)
            });

        let outcome = if continuation_validated {
            &evaluation.validated
        } else if reasoning_block_present && shape_plausible {
            &evaluation.plausible_unvalidated
        } else if reasoning_block_present {
            &evaluation.malformed
        } else {
            &evaluation.missing
        };
        let basis = if continuation_validated || !shape_plausible {
            EvidenceBasis::Observed
        } else {
            EvidenceBasis::Inferred
        };

        match request.protocol {
            Protocol::Anthropic => evidence_with_basis(
                EvidenceSpec {
                    name: "reasoning_attestation",
                    display_name: &evaluation.display_name,
                    category: EvidenceCategory::Authenticity,
                    status: rules.evaluation.grade.status(outcome.score),
                    severity: outcome.severity,
                    score: outcome.score,
                    weight: evaluation.weight,
                    summary: &outcome.summary,
                },
                BTreeMap::from([
                    (
                        "reasoningBlockPresent".into(),
                        json!(reasoning_block_present),
                    ),
                    ("attestationLength".into(), json!(attestation_length)),
                    ("attestationShapePlausible".into(), json!(shape_plausible)),
                    (
                        "continuationAttempted".into(),
                        json!(continuation_attempted),
                    ),
                    (
                        "continuationValidated".into(),
                        json!(continuation_validated),
                    ),
                    ("fingerprint".into(), json!(fingerprint)),
                ]),
                basis,
                Some(outcome.confidence),
            ),
            _ => skipped(
                "reasoning_attestation",
                &evaluation.display_name,
                EvidenceCategory::Authenticity,
                &rules.evaluation.skipped_summary,
            ),
        }
    }
}

fn reasoning_attestation(response: &Value) -> (bool, Option<&str>, Option<&str>) {
    let mut present = false;
    let mut signature = None;
    let mut protected = None;
    if let Some(blocks) = response.get("content").and_then(Value::as_array) {
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("thinking") => {
                    present = true;
                    signature =
                        signature.or_else(|| block.get("signature").and_then(Value::as_str));
                }
                Some("redacted_thinking") => {
                    present = true;
                    protected = protected.or_else(|| block.get("data").and_then(Value::as_str));
                }
                _ => {}
            }
        }
    }
    (present, signature, protected)
}

fn configure_reasoning_probe(
    probe: &mut OutboundProbe,
    model: &str,
    rules: &ReasoningAttestationRules,
) {
    let lower = model.to_ascii_lowercase();
    if rules
        .adaptive_model_markers
        .iter()
        .any(|marker| lower.contains(marker))
    {
        probe.body["max_tokens"] = json!(rules.adaptive_max_tokens);
        probe.body["thinking"] = json!({"type": "adaptive", "display": "summarized"});
        probe.body["output_config"] = json!({"effort": "high"});
    } else {
        probe.body["max_tokens"] = json!(rules.default_max_tokens);
        probe.body["thinking"] =
            json!({"type": "enabled", "budget_tokens": rules.default_budget_tokens});
    }
}

fn opaque_attestation_shape(value: &str, minimum_length: usize) -> bool {
    value.len() >= minimum_length
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
}

impl ProbeStrategy for ProtocolStrategy {
    fn name(&self) -> &'static str {
        "protocol"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let _ = request;
        Ok(Vec::new())
    }

    fn observes_all(&self) -> bool {
        true
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("protocol", EvidenceCategory::Protocol);
        };
        let evaluation = &rules.evaluation.protocol;
        if !observations
            .iter()
            .any(|item| item.status_code != 429 && item.status_code != 503)
        {
            return skipped(
                "protocol",
                &evaluation.display_name,
                EvidenceCategory::Protocol,
                &rules.evaluation.skipped_summary,
            );
        }
        let audits = observations
            .iter()
            .map(|item| audit_response_contract(request.protocol, item))
            .collect::<Vec<_>>();
        let checks = audits.iter().map(|audit| audit.check_count).sum::<usize>();
        let failures = audits
            .iter()
            .map(|audit| audit.failures.len())
            .sum::<usize>();
        let stream_samples = observations
            .iter()
            .filter(|item| !item.stream_events.is_empty())
            .count();
        let score = if checks == 0 {
            0.0
        } else {
            ((checks - failures.min(checks)) as f64 / checks as f64 * 100.0).round()
        };
        let passed = failures == 0
            && observations
                .iter()
                .all(|item| (200..300).contains(&item.status_code));
        evidence_with_basis(
            EvidenceSpec {
                name: "protocol",
                display_name: &evaluation.display_name,
                category: EvidenceCategory::Protocol,
                status: if passed {
                    EvidenceStatus::Pass
                } else {
                    EvidenceStatus::Fail
                },
                severity: if passed {
                    EvidenceSeverity::Info
                } else {
                    EvidenceSeverity::Major
                },
                score,
                weight: evaluation.weight,
                summary: if passed {
                    &evaluation.passed_summary
                } else {
                    &evaluation.failed_summary
                },
            },
            BTreeMap::from([
                ("observedResponses".into(), json!(observations.len())),
                ("streamSamples".into(), json!(stream_samples)),
                ("checks".into(), json!(checks)),
                (
                    "failures".into(),
                    json!(
                        audits
                            .iter()
                            .flat_map(|audit| audit.failures.clone())
                            .collect::<Vec<_>>()
                    ),
                ),
                (
                    "contentTypes".into(),
                    json!(
                        audits
                            .iter()
                            .flat_map(|audit| audit.content_types.clone())
                            .collect::<Vec<_>>()
                    ),
                ),
            ]),
            EvidenceBasis::Observed,
            Some(
                if observations.len() >= evaluation.high_confidence_minimum_samples {
                    evaluation.high_confidence
                } else {
                    evaluation.base_confidence
                },
            ),
        )
    }
}

struct ProtocolAudit {
    check_count: usize,
    failures: Vec<String>,
    content_types: Vec<String>,
}

fn audit_response_contract(protocol: Protocol, observation: &ProbeObservation) -> ProtocolAudit {
    let mut check_count = 1;
    let mut failures = Vec::new();
    let mut content_types = Vec::new();
    if !(200..300).contains(&observation.status_code) {
        failures.push(format!("HTTP {} response", observation.status_code));
        return ProtocolAudit {
            check_count,
            failures,
            content_types,
        };
    }
    let response = &observation.response;
    match protocol {
        Protocol::Anthropic => {
            let scalar_checks = [
                ("id", response.get("id").is_some_and(Value::is_string)),
                (
                    "type",
                    response.get("type").and_then(Value::as_str) == Some("message"),
                ),
                (
                    "role",
                    response.get("role").and_then(Value::as_str) == Some("assistant"),
                ),
                ("model", response.get("model").is_some_and(Value::is_string)),
                (
                    "content",
                    response.get("content").is_some_and(Value::is_array),
                ),
                ("usage", response.get("usage").is_some_and(Value::is_object)),
                (
                    "stop_reason",
                    matches!(
                        response.get("stop_reason").and_then(Value::as_str),
                        Some("end_turn" | "max_tokens" | "stop_sequence" | "tool_use")
                    ),
                ),
                (
                    "stop_sequence",
                    response
                        .get("stop_sequence")
                        .is_some_and(|value| value.is_null() || value.is_string()),
                ),
            ];
            check_count += scalar_checks.len();
            failures.extend(
                scalar_checks
                    .into_iter()
                    .filter(|(_, valid)| !valid)
                    .map(|(name, _)| format!("invalid or missing {name}")),
            );
            if let Some(blocks) = response.get("content").and_then(Value::as_array) {
                for block in blocks {
                    check_count += 1;
                    let kind = block
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("missing");
                    content_types.push(kind.into());
                    let valid = match kind {
                        "text" => block.get("text").is_some_and(Value::is_string),
                        "tool_use" => {
                            block.get("id").is_some_and(Value::is_string)
                                && block.get("name").is_some_and(Value::is_string)
                                && block.get("input").is_some_and(Value::is_object)
                                && block.get("caller").is_none_or(valid_tool_caller)
                        }
                        "thinking" => {
                            block.get("thinking").is_some_and(Value::is_string)
                                && block.get("signature").is_some_and(Value::is_string)
                        }
                        "redacted_thinking" => block.get("data").is_some_and(Value::is_string),
                        "server_tool_use" => {
                            block.get("id").is_some_and(Value::is_string)
                                && block.get("name").is_some_and(Value::is_string)
                                && block.get("input").is_some_and(Value::is_object)
                        }
                        "web_search_tool_result" => {
                            block.get("tool_use_id").is_some_and(Value::is_string)
                                && block.get("content").is_some_and(Value::is_array)
                        }
                        _ => true,
                    };
                    if !valid {
                        failures.push(format!("malformed {kind} content block"));
                    }
                }
            }
            check_count += 2;
            if response
                .pointer("/usage/input_tokens")
                .and_then(Value::as_u64)
                .is_none()
            {
                failures.push("invalid or missing usage.input_tokens".into());
            }
            if response
                .pointer("/usage/output_tokens")
                .and_then(Value::as_u64)
                .is_none()
            {
                failures.push("invalid or missing usage.output_tokens".into());
            }
            for key in ["cache_read_input_tokens", "cache_creation_input_tokens"] {
                if let Some(value) = response.pointer(&format!("/usage/{key}")) {
                    check_count += 1;
                    if value.as_u64().is_none() {
                        failures.push(format!("invalid usage.{key}"));
                    }
                }
            }
            if let Some(container) = response.get("container") {
                check_count += 1;
                if !container.is_object()
                    || !container.get("id").is_some_and(Value::is_string)
                    || !container.get("expires_at").is_some_and(Value::is_string)
                {
                    failures.push("malformed container metadata".into());
                }
            }
        }
        Protocol::Openai if observation.kind == ProbeKind::ReasoningBudget => {
            for (name, valid) in [
                ("id", response.get("id").is_some_and(Value::is_string)),
                ("model", response.get("model").is_some_and(Value::is_string)),
                (
                    "output",
                    response.get("output").is_some_and(Value::is_array),
                ),
                ("usage", response.get("usage").is_some_and(Value::is_object)),
                (
                    "output_text",
                    response
                        .get("output")
                        .and_then(Value::as_array)
                        .is_some_and(|outputs| {
                            outputs.iter().any(|output| {
                                output.get("content").and_then(Value::as_array).is_some_and(
                                    |content| {
                                        content.iter().any(|block| {
                                            block.get("type").and_then(Value::as_str)
                                                == Some("output_text")
                                                && block.get("text").is_some_and(Value::is_string)
                                        })
                                    },
                                )
                            })
                        }),
                ),
            ] {
                check_count += 1;
                if !valid {
                    failures.push(format!("invalid or missing Responses API {name}"));
                }
            }
        }
        Protocol::Openai | Protocol::Gemini => {
            for (name, valid) in [
                ("id", response.get("id").is_some_and(Value::is_string)),
                ("model", response.get("model").is_some_and(Value::is_string)),
                (
                    "choices",
                    response.get("choices").is_some_and(Value::is_array),
                ),
                ("usage", response.get("usage").is_some_and(Value::is_object)),
            ] {
                check_count += 1;
                if !valid {
                    failures.push(format!("invalid or missing {name}"));
                }
            }
        }
    }
    if !observation.stream_events.is_empty() {
        let stream_failures = audit_stream_sequence(protocol, &observation.stream_events);
        check_count += 1;
        failures.extend(stream_failures);
    }
    ProtocolAudit {
        check_count,
        failures,
        content_types,
    }
}

fn audit_stream_sequence(
    protocol: Protocol,
    events: &[crate::StreamEventObservation],
) -> Vec<String> {
    if protocol != Protocol::Anthropic {
        return Vec::new();
    }
    let mut failures = Vec::new();
    for event in events {
        if event.data.get("unparsedData").is_some() {
            failures.push(format!("{} carried invalid JSON data", event.event));
        }
        if event.event == "error" {
            let error_type = event
                .data
                .pointer("/error/type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            failures.push(format!("upstream stream error: {error_type}"));
        }
    }
    let ordered = events
        .iter()
        .filter(|event| !matches!(event.event.as_str(), "ping" | "error"))
        .map(|event| event.event.as_str())
        .collect::<Vec<_>>();
    if ordered.first() != Some(&"message_start") {
        failures.push("stream did not start with message_start".into());
    }
    if ordered.last() != Some(&"message_stop") {
        failures.push("stream did not end with message_stop".into());
    }
    let mut open_blocks = 0_i32;
    let mut block_count = 0_usize;
    let mut message_delta_count = 0_usize;
    let mut message_started = false;
    let mut message_stopped = false;
    for event in ordered {
        if message_stopped {
            failures.push(format!("{event} arrived after message_stop"));
            continue;
        }
        match event {
            "message_start" if message_started => {
                failures.push("message_start was repeated or out of order".into())
            }
            "message_start" => message_started = true,
            "content_block_start" if message_delta_count > 0 => {
                failures.push("content block started after message_delta".into())
            }
            "content_block_start" => {
                open_blocks += 1;
                block_count += 1;
            }
            "content_block_delta" if open_blocks == 0 => {
                failures.push("content delta arrived outside a block".into())
            }
            "content_block_delta" if message_delta_count > 0 => {
                failures.push("content delta arrived after message_delta".into())
            }
            "content_block_stop" if open_blocks == 0 => {
                failures.push("content block stopped before it started".into())
            }
            "content_block_stop" => open_blocks -= 1,
            "message_delta" if open_blocks != 0 => {
                message_delta_count += 1;
                failures.push("message_delta arrived with an open content block".into())
            }
            "message_delta" => message_delta_count += 1,
            "message_stop" if open_blocks != 0 => {
                failures.push("message stopped with an open content block".into())
            }
            "message_stop" => message_stopped = true,
            _ => {}
        }
    }
    if block_count == 0 {
        failures.push("stream contained no content block".into());
    }
    if message_delta_count != 1 {
        failures.push(format!(
            "stream contained {message_delta_count} message_delta events"
        ));
    }
    failures
}

pub(super) fn valid_tool_caller(value: &Value) -> bool {
    value.is_object()
        || matches!(
            value.as_str(),
            Some("direct" | "code_execution_20250825" | "code_execution_20260120")
        )
}

impl ProbeStrategy for ContextAuditStrategy {
    fn name(&self) -> &'static str {
        "context"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        let audit_id = Ulid::new().to_string();
        let context_rules = &rules.probes.context;
        let levels = context_rules.gradient_units.for_mode(request.mode);
        levels
            .iter()
            .enumerate()
            .map(|(level, controlled_units)| {
                build_context_probe(
                    request,
                    &audit_id,
                    level,
                    *controlled_units,
                    levels.len(),
                    context_rules,
                )
            })
            .collect()
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("context", EvidenceCategory::Capability);
        };
        let evaluation = &rules.evaluation.context;
        let Some(summary) = summarize_context_audit(observations, evaluation) else {
            return skipped(
                "context",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &rules.evaluation.skipped_summary,
            );
        };

        let echo_exact = summary.final_echo_status == ContextEchoStatus::Exact;
        let growth_ok = summary.monotonic_growth.unwrap_or(false)
            && summary.growth_ratio.is_some_and(|ratio| {
                (evaluation.growth_ratio_minimum..=evaluation.growth_ratio_maximum).contains(&ratio)
            });
        let fit_ok = summary
            .fit_confidence
            .is_some_and(|confidence| confidence >= evaluation.fit_confidence_minimum);

        let outcome = if !echo_exact {
            &evaluation.echo_mismatch
        } else if !summary.usage_available {
            &evaluation.usage_unavailable
        } else if !growth_ok || !fit_ok {
            &evaluation.gradient_mismatch
        } else {
            match summary.overhead_assessment {
                ContextOverheadAssessment::Expected => &evaluation.expected,
                ContextOverheadAssessment::Elevated => &evaluation.elevated,
                ContextOverheadAssessment::High => &evaluation.high,
                ContextOverheadAssessment::Unknown => &evaluation.unknown,
            }
        };

        evidence_with_basis(
            EvidenceSpec {
                name: "context",
                display_name: &evaluation.display_name,
                category: EvidenceCategory::Capability,
                status: rules.evaluation.grade.status(outcome.score),
                severity: outcome.severity,
                score: outcome.score,
                weight: evaluation.weight,
                summary: &outcome.summary,
            },
            BTreeMap::from([
                ("sampleCount".into(), json!(summary.sample_count)),
                (
                    "controlledUnitLevels".into(),
                    json!(
                        summary
                            .samples
                            .iter()
                            .map(|sample| sample.controlled_units)
                            .collect::<Vec<_>>()
                    ),
                ),
                (
                    "reportedInputTokens".into(),
                    json!(
                        summary
                            .samples
                            .iter()
                            .map(|sample| sample.reported_input_tokens)
                            .collect::<Vec<_>>()
                    ),
                ),
                ("monotonicGrowth".into(), json!(summary.monotonic_growth)),
                ("growthRatio".into(), json!(summary.growth_ratio)),
                ("fitConfidence".into(), json!(summary.fit_confidence)),
                (
                    "estimatedFixedOverheadTokens".into(),
                    json!(summary.estimated_fixed_overhead_tokens),
                ),
                (
                    "overheadAssessment".into(),
                    json!(summary.overhead_assessment),
                ),
                ("finalEchoStatus".into(), json!(summary.final_echo_status)),
                (
                    "controlledContextConfirmed".into(),
                    json!(summary.controlled_context_confirmed),
                ),
                (
                    "independentRequests".into(),
                    json!(summary.independent_requests),
                ),
                (
                    "uniqueRequestFingerprints".into(),
                    json!(summary.unique_request_fingerprints),
                ),
                (
                    "cumulativeHistorySuspected".into(),
                    json!(summary.cumulative_history_suspected),
                ),
                ("cacheHitObserved".into(), json!(summary.cache_hit_observed)),
                (
                    "accountingInterpretation".into(),
                    json!(summary.accounting_interpretation),
                ),
            ]),
            EvidenceBasis::Inferred,
            Some(outcome.confidence),
        )
    }
}

impl ProbeStrategy for ConsistencyStrategy {
    fn name(&self) -> &'static str {
        "consistency"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        let consistency = &rules.probes.consistency;
        (0..consistency.samples.for_mode(request.mode))
            .map(|_| {
                let mut probe = build_probe(request, ProbeKind::Consistency, &consistency.prompt)?;
                let model = request.model.to_ascii_lowercase();
                if !consistency
                    .deterministic_sampling_excluded_model_markers
                    .iter()
                    .any(|marker| model.contains(marker))
                {
                    probe.body["temperature"] = json!(0);
                }
                probe.demo_response = Some(consistency.demo_response.clone());
                Ok(probe)
            })
            .collect()
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("consistency", EvidenceCategory::Authenticity);
        };
        let evaluation = &rules.evaluation.consistency;
        if observations.is_empty() {
            return skipped(
                "consistency",
                &evaluation.display_name,
                EvidenceCategory::Authenticity,
                &rules.evaluation.skipped_summary,
            );
        }
        let declared_models = observations
            .iter()
            .filter_map(|observation| observation.response.get("model").and_then(Value::as_str))
            .collect::<Vec<_>>();
        let route_matches = !declared_models.is_empty()
            && declared_models
                .iter()
                .all(|declared| model_route_matches(&request.model, declared));
        let fingerprints: Vec<_> = observations
            .iter()
            .map(|observation| extract_text_fingerprint(&observation.text))
            .collect();
        let mut comparisons = Vec::new();
        for pair in fingerprints.windows(2) {
            comparisons.push(similarity(&pair[0], &pair[1]));
        }
        let average = if comparisons.is_empty() {
            None
        } else {
            Some(comparisons.iter().sum::<f64>() / comparisons.len() as f64)
        };
        let output_counts = observations
            .iter()
            .map(|item| item.usage.output_tokens as f64)
            .collect::<Vec<_>>();
        let relative_dispersion = relative_standard_deviation(&output_counts);
        let stability_score = average
            .map(|value| value * evaluation.similarity_points)
            .unwrap_or(0.0)
            + relative_dispersion
                .map(|value| (1.0 - value.min(1.0)) * evaluation.output_stability_points)
                .unwrap_or(0.0);
        let score = if observations.len() == 1 {
            if route_matches {
                evaluation.single_route_match_score
            } else {
                0.0
            }
        } else {
            (if route_matches {
                evaluation.repeated_route_points
            } else {
                0.0
            }) + stability_score * evaluation.stability_multiplier
        };
        evidence_with_basis(
            EvidenceSpec {
                name: "consistency",
                display_name: &evaluation.display_name,
                category: EvidenceCategory::Authenticity,
                status: rules.evaluation.grade.status(score),
                severity: rules.evaluation.grade.severity(score),
                score,
                weight: evaluation.weight,
                summary: &evaluation.summary,
            },
            BTreeMap::from([
                ("sampleCount".into(), json!(observations.len())),
                ("requestedModel".into(), json!(request.model)),
                ("declaredModels".into(), json!(declared_models)),
                ("routeMatches".into(), json!(route_matches)),
                ("averageSimilarity".into(), json!(average)),
                (
                    "relativeOutputDispersion".into(),
                    json!(relative_dispersion),
                ),
            ]),
            EvidenceBasis::Inferred,
            Some(
                if observations.len() >= evaluation.high_confidence_minimum_samples {
                    evaluation.high_confidence
                } else {
                    evaluation.base_confidence
                },
            ),
        )
    }
}

fn model_route_matches(requested: &str, declared: &str) -> bool {
    let requested = requested.trim().to_ascii_lowercase();
    let declared = declared.trim().to_ascii_lowercase();
    !requested.is_empty()
        && !declared.is_empty()
        && (requested == declared
            || requested
                .strip_prefix(&declared)
                .is_some_and(|suffix| suffix.starts_with('-'))
            || declared
                .strip_prefix(&requested)
                .is_some_and(|suffix| suffix.starts_with('-')))
}

fn relative_standard_deviation(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean <= f64::EPSILON {
        return None;
    }
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / values.len() as f64;
    Some((variance.sqrt() / mean * 1_000.0).round() / 1_000.0)
}

pub(crate) fn build_probe(
    request: &ProbeRequest,
    kind: ProbeKind,
    prompt: &str,
) -> Result<OutboundProbe, CoreError> {
    let mut base = Url::parse(&request.base_url)
        .map_err(|error| CoreError::InvalidEndpoint(error.to_string()))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(CoreError::InvalidEndpoint(
            "only http and https targets are accepted".into(),
        ));
    }

    let base_has_v1 = base.path().trim_end_matches('/').ends_with("/v1");
    let (path, headers, body) = match request.protocol {
        Protocol::Anthropic => {
            let mut body = json!({
                "model": request.model,
                "max_tokens": 160,
                "messages": [{ "role": "user", "content": prompt }]
            });
            if kind == ProbeKind::ReasoningAttestation {
                body["max_tokens"] = json!(1200);
                body["thinking"] = json!({ "type": "enabled", "budget_tokens": 1024 });
            }
            (
                if base_has_v1 {
                    "messages"
                } else {
                    "v1/messages"
                },
                BTreeMap::from([
                    ("x-api-key".into(), request.api_key.clone()),
                    ("anthropic-version".into(), "2023-06-01".into()),
                    ("content-type".into(), "application/json".into()),
                ]),
                body,
            )
        }
        Protocol::Openai | Protocol::Gemini => (
            if base_has_v1 {
                "chat/completions"
            } else {
                "v1/chat/completions"
            },
            BTreeMap::from([
                (
                    "authorization".into(),
                    format!("Bearer {}", request.api_key),
                ),
                ("content-type".into(), "application/json".into()),
            ]),
            json!({
                "model": request.model,
                "max_tokens": 160,
                "messages": [{ "role": "user", "content": prompt }]
            }),
        ),
    };
    if !base.path().ends_with('/') {
        let normalized = format!("{}/", base.path().trim_end_matches('/'));
        base.set_path(&normalized);
    }
    let url = base
        .join(path)
        .map_err(|error| CoreError::InvalidEndpoint(error.to_string()))?;
    Ok(OutboundProbe {
        kind,
        challenge_id: None,
        url: url.to_string(),
        headers,
        body,
        context: None,
        demo_response: None,
        demo_tool_arguments: None,
    })
}

fn build_context_probe(
    request: &ProbeRequest,
    audit_id: &str,
    level: usize,
    controlled_units: usize,
    total_levels: usize,
    rules: &crate::rules::ContextProbeRules,
) -> Result<OutboundProbe, CoreError> {
    let metadata_seed = ContextProbeMetadata {
        audit_id: audit_id.into(),
        level,
        controlled_units,
        controlled_bytes: 0,
        visible_input_token_estimate: 0,
        expects_exact_echo: level + 1 == total_levels,
        request_body_bytes: 0,
        message_count: 0,
        request_fingerprint: String::new(),
        independent_request: true,
    };
    let controlled_context = metadata_seed.controlled_context();
    let response_instruction = if metadata_seed.expects_exact_echo {
        &rules.final_instruction
    } else {
        &rules.intermediate_instruction
    };
    let prompt = rules
        .prompt_template
        .replace("{responseInstruction}", response_instruction)
        .replace("{auditId}", audit_id)
        .replace("{level}", &level.to_string())
        .replace("{controlledUnits}", &controlled_units.to_string())
        .replace("{beginMarker}", &metadata_seed.begin_marker())
        .replace("{controlledContext}", &controlled_context)
        .replace("{endMarker}", &metadata_seed.end_marker());
    let mut probe = build_probe(request, ProbeKind::Context, &prompt)?;
    let output_budget = if metadata_seed.expects_exact_echo {
        ((controlled_context.len() as u64).div_ceil(rules.final_bytes_per_token)
            + rules.final_base_tokens)
            .clamp(rules.final_minimum_tokens, rules.final_maximum_tokens)
    } else {
        rules.intermediate_max_tokens
    };
    probe.body["max_tokens"] = json!(output_budget);
    let serialized_body =
        serde_json::to_vec(&probe.body).map_err(|error| CoreError::Parse(error.to_string()))?;
    let message_count = probe
        .body
        .get("messages")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let metadata = ContextProbeMetadata {
        controlled_bytes: controlled_context.len(),
        visible_input_token_estimate: estimate_visible_tokens(&prompt),
        request_body_bytes: serialized_body.len(),
        message_count,
        request_fingerprint: sha256_fingerprint(&serialized_body),
        independent_request: message_count == 1,
        ..metadata_seed
    };
    probe.context = Some(metadata);
    Ok(probe)
}

fn sha256_fingerprint(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn estimate_visible_tokens(text: &str) -> u64 {
    let ascii_bytes = text.bytes().filter(u8::is_ascii).count() as u64;
    let non_ascii_chars = text
        .chars()
        .filter(|character| !character.is_ascii())
        .count() as u64;
    ascii_bytes.div_ceil(4) + non_ascii_chars
}

pub fn summarize_context_audit(
    observations: &[ProbeObservation],
    rules: &crate::rule_evaluation::ContextEvaluationRules,
) -> Option<ContextAuditSummary> {
    let mut context_observations: Vec<_> = observations
        .iter()
        .filter(|observation| observation.kind == ProbeKind::Context)
        .filter_map(|observation| {
            observation
                .context
                .as_ref()
                .map(|metadata| (metadata, observation))
        })
        .collect();
    context_observations.sort_by_key(|(metadata, _)| metadata.level);
    if context_observations.is_empty() {
        return None;
    }

    let samples = context_observations
        .iter()
        .map(|(metadata, observation)| {
            let reported =
                (observation.usage.input_tokens > 0).then_some(observation.usage.input_tokens);
            ContextAuditSample {
                level: metadata.level,
                controlled_units: metadata.controlled_units,
                controlled_bytes: metadata.controlled_bytes,
                visible_input_token_estimate: metadata.visible_input_token_estimate,
                reported_input_tokens: reported,
                estimated_input_overhead_tokens: reported
                    .map(|reported| reported as i64 - metadata.visible_input_token_estimate as i64),
                exact_echo_requested: metadata.expects_exact_echo,
                request_body_bytes: metadata.request_body_bytes,
                message_count: metadata.message_count,
                request_fingerprint: metadata.request_fingerprint.clone(),
                independent_request: metadata.independent_request,
                cache_read_input_tokens: observation.usage.cache_read_input_tokens,
                cache_creation_input_tokens: observation.usage.cache_creation_input_tokens,
            }
        })
        .collect::<Vec<_>>();
    let token_pairs = samples
        .iter()
        .filter_map(|sample| {
            sample
                .reported_input_tokens
                .map(|reported| (sample.visible_input_token_estimate as f64, reported as f64))
        })
        .collect::<Vec<_>>();
    let usage_available = token_pairs.len() == samples.len();
    let monotonic_growth =
        (token_pairs.len() >= 2).then(|| token_pairs.windows(2).all(|pair| pair[1].1 > pair[0].1));
    let regression = linear_regression(&token_pairs);
    let estimated_fixed_overhead_tokens =
        regression.map(|(_, intercept, _)| intercept.round() as i64);
    let overhead_assessment = match estimated_fixed_overhead_tokens {
        Some(overhead) if overhead < -rules.expected_overhead_maximum => {
            ContextOverheadAssessment::Unknown
        }
        Some(overhead) if overhead <= rules.expected_overhead_maximum => {
            ContextOverheadAssessment::Expected
        }
        Some(overhead) if overhead <= rules.elevated_overhead_maximum => {
            ContextOverheadAssessment::Elevated
        }
        Some(_) => ContextOverheadAssessment::High,
        None => ContextOverheadAssessment::Unknown,
    };
    let (final_metadata, final_observation) = context_observations.last()?;
    let final_echo_status =
        validate_controlled_context_echo(final_metadata, &final_observation.text);
    let independent_requests = samples
        .iter()
        .all(|sample| sample.independent_request && sample.message_count == 1);
    let unique_request_fingerprints = samples
        .iter()
        .map(|sample| sample.request_fingerprint.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        == samples.len();
    let cache_hit_observed = samples
        .iter()
        .any(|sample| sample.cache_read_input_tokens > 0 || sample.cache_creation_input_tokens > 0);
    let cumulative_history_suspected =
        cumulative_accounting_suspected(&samples, rules.cumulative_growth_ratio_threshold);
    let accounting_interpretation = if !usage_available {
        "upstream_usage_unavailable"
    } else if !independent_requests {
        "client_history_present"
    } else if cumulative_history_suspected == Some(true) {
        "superlinear_reported_growth"
    } else if cache_hit_observed {
        "provider_cache_tokens_reported"
    } else {
        "independent_linear_payload_growth"
    }
    .to_owned();

    Some(ContextAuditSummary {
        sample_count: samples.len(),
        samples,
        usage_available,
        monotonic_growth,
        growth_ratio: regression.map(|(slope, _, _)| round_metric(slope)),
        fit_confidence: regression.map(|(_, _, confidence)| round_metric(confidence)),
        estimated_fixed_overhead_tokens,
        overhead_assessment,
        final_echo_status,
        controlled_context_confirmed: final_echo_status == ContextEchoStatus::Exact,
        independent_requests,
        unique_request_fingerprints,
        cumulative_history_suspected,
        cache_hit_observed,
        accounting_interpretation,
    })
}

fn cumulative_accounting_suspected(
    samples: &[ContextAuditSample],
    growth_ratio_threshold: f64,
) -> Option<bool> {
    if samples.len() < 3
        || samples
            .iter()
            .any(|sample| sample.reported_input_tokens.is_none())
    {
        return None;
    }
    let growth_ratios = samples
        .windows(2)
        .filter_map(|pair| {
            let visible_growth = pair[1]
                .visible_input_token_estimate
                .checked_sub(pair[0].visible_input_token_estimate)?;
            let reported_growth = pair[1]
                .reported_input_tokens?
                .checked_sub(pair[0].reported_input_tokens?)?;
            (visible_growth > 0).then_some(reported_growth as f64 / visible_growth as f64)
        })
        .collect::<Vec<_>>();
    if growth_ratios.len() < 2 {
        return None;
    }
    let first = growth_ratios[0];
    let last = *growth_ratios.last()?;
    Some(first > 0.0 && last > first * growth_ratio_threshold)
}

fn validate_controlled_context_echo(
    metadata: &ContextProbeMetadata,
    response_text: &str,
) -> ContextEchoStatus {
    let Ok(value) = serde_json::from_str::<Value>(response_text.trim()) else {
        return if response_text.trim().is_empty() {
            ContextEchoStatus::Unavailable
        } else {
            ContextEchoStatus::Mismatch
        };
    };
    let matches = value.get("auditId").and_then(Value::as_str) == Some(&metadata.audit_id)
        && value.get("beginMarker").and_then(Value::as_str)
            == Some(metadata.begin_marker().as_str())
        && value.get("endMarker").and_then(Value::as_str) == Some(metadata.end_marker().as_str())
        && value.get("controlledUnits").and_then(Value::as_u64)
            == Some(metadata.controlled_units as u64)
        && value.get("controlledContext").and_then(Value::as_str)
            == Some(metadata.controlled_context().as_str());
    if matches {
        ContextEchoStatus::Exact
    } else {
        ContextEchoStatus::Mismatch
    }
}

fn linear_regression(points: &[(f64, f64)]) -> Option<(f64, f64, f64)> {
    if points.len() < 2 {
        return None;
    }
    let count = points.len() as f64;
    let mean_x = points.iter().map(|(x, _)| x).sum::<f64>() / count;
    let mean_y = points.iter().map(|(_, y)| y).sum::<f64>() / count;
    let variance_x = points
        .iter()
        .map(|(x, _)| (x - mean_x).powi(2))
        .sum::<f64>();
    if variance_x <= f64::EPSILON {
        return None;
    }
    let covariance = points
        .iter()
        .map(|(x, y)| (x - mean_x) * (y - mean_y))
        .sum::<f64>();
    let slope = covariance / variance_x;
    let intercept = mean_y - slope * mean_x;
    let total_y = points
        .iter()
        .map(|(_, y)| (y - mean_y).powi(2))
        .sum::<f64>();
    let residual = points
        .iter()
        .map(|(x, y)| (y - (slope * x + intercept)).powi(2))
        .sum::<f64>();
    let confidence = if total_y <= f64::EPSILON {
        0.0
    } else {
        (1.0 - residual / total_y).clamp(0.0, 1.0)
    };
    Some((slope, intercept, confidence))
}

fn round_metric(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

struct EvidenceSpec<'a> {
    name: &'a str,
    display_name: &'a str,
    category: EvidenceCategory,
    status: EvidenceStatus,
    severity: EvidenceSeverity,
    score: f64,
    weight: f64,
    summary: &'a str,
}

fn evidence(spec: EvidenceSpec<'_>, details: BTreeMap<String, Value>) -> DetectorEvidence {
    let status = spec.status;
    let score = spec.score;
    evidence_with_basis(
        spec,
        details,
        if status == EvidenceStatus::Skip {
            EvidenceBasis::Unsupported
        } else {
            EvidenceBasis::Inferred
        },
        (status != EvidenceStatus::Skip).then_some(score / 100.0),
    )
}

fn evidence_with_basis(
    spec: EvidenceSpec<'_>,
    details: BTreeMap<String, Value>,
    basis: EvidenceBasis,
    confidence: Option<f64>,
) -> DetectorEvidence {
    DetectorEvidence {
        name: spec.name.into(),
        display_name: spec.display_name.into(),
        category: spec.category,
        status: spec.status,
        severity: spec.severity,
        basis,
        confidence,
        score: spec.score,
        weight: spec.weight,
        summary: spec.summary.into(),
        details,
    }
}

fn skipped(
    name: &str,
    display_name: &str,
    category: EvidenceCategory,
    summary: &str,
) -> DetectorEvidence {
    evidence(
        EvidenceSpec {
            name,
            display_name,
            category,
            status: EvidenceStatus::Skip,
            severity: EvidenceSeverity::Info,
            score: 0.0,
            weight: 0.0,
            summary,
        },
        BTreeMap::new(),
    )
}

fn unavailable(name: &str, category: EvidenceCategory) -> DetectorEvidence {
    DetectorEvidence {
        name: name.into(),
        display_name: name.into(),
        category,
        status: EvidenceStatus::Error,
        severity: EvidenceSeverity::Critical,
        basis: EvidenceBasis::Unsupported,
        confidence: None,
        score: 0.0,
        weight: 0.0,
        summary: "A validated Core rule bundle was not installed.".into(),
        details: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ContextAuditStrategy, IdentityStrategy, ProbeStrategy, ReasoningAttestationStrategy,
        audit_stream_sequence, summarize_context_audit,
    };
    use crate::{
        ContextEchoStatus, ContextOverheadAssessment, EvidenceBasis, EvidenceSeverity,
        EvidenceStatus, ProbeKind, ProbeMode, ProbeObservation, ProbeRequest, Protocol,
        StreamEventObservation, UsageMetrics,
    };
    use serde_json::json;
    use std::collections::BTreeSet;

    fn request(mode: ProbeMode) -> ProbeRequest {
        ProbeRequest {
            base_url: "https://example.com".into(),
            api_key: "secret".into(),
            model: "claude-sonnet-4-6".into(),
            protocol: Protocol::Anthropic,
            mode,
            parameters: Default::default(),
            sections: Vec::new(),
        }
    }

    fn context_observations(
        request: &ProbeRequest,
        fixed_overhead: u64,
        final_echo_matches: bool,
    ) -> Vec<ProbeObservation> {
        let probes = ContextAuditStrategy
            .build(request)
            .expect("context probes build");
        probes
            .into_iter()
            .map(|probe| {
                let metadata = probe.context.expect("context metadata");
                let text = if metadata.expects_exact_echo {
                    json!({
                        "auditId": metadata.audit_id,
                        "beginMarker": metadata.begin_marker(),
                        "endMarker": metadata.end_marker(),
                        "controlledUnits": metadata.controlled_units,
                        "controlledContext": if final_echo_matches {
                            metadata.controlled_context()
                        } else {
                            "relay-modified-context".into()
                        },
                    })
                    .to_string()
                } else {
                    json!({
                        "auditId": metadata.audit_id,
                        "controlledUnits": metadata.controlled_units,
                        "received": true,
                    })
                    .to_string()
                };
                ProbeObservation {
                    kind: ProbeKind::Context,
                    challenge_id: None,
                    status_code: 200,
                    latency_ms: 10,
                    ttft_ms: None,
                    response: json!({}),
                    text,
                    usage: UsageMetrics {
                        input_tokens: metadata.visible_input_token_estimate + fixed_overhead,
                        output_tokens: 12,
                        ..UsageMetrics::default()
                    },
                    response_headers: Default::default(),
                    stream_events: Vec::new(),
                    retry_count: 0,
                    backoff_count: 0,
                    context: Some(metadata),
                }
            })
            .collect()
    }

    #[test]
    fn missing_anthropic_signature_is_critical() {
        let request = request(ProbeMode::Standard);
        let observation = ProbeObservation {
            kind: ProbeKind::ReasoningAttestation,
            challenge_id: None,
            status_code: 200,
            latency_ms: 10,
            ttft_ms: None,
            response: json!({ "content": [{"type": "text", "text": "hello"}] }),
            text: "hello".into(),
            response_headers: Default::default(),
            stream_events: Vec::new(),
            usage: UsageMetrics::default(),
            retry_count: 0,
            backoff_count: 0,
            context: None,
        };
        let result = ReasoningAttestationStrategy.analyze(&request, &[observation]);
        assert_eq!(result.severity, crate::EvidenceSeverity::Critical);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn identity_reports_provider_conflicts_separately_from_model_metadata() {
        let request = request(ProbeMode::Quick);
        let observation = ProbeObservation::fixture(
            ProbeKind::Identity,
            200,
            json!({"model": "claude-sonnet-4-6"}),
            "I am Claude, provided by OpenAI.",
        );
        let evidence = IdentityStrategy.analyze(&request, &[observation]);
        assert_eq!(evidence.details["metadataMatches"], true);
        assert_eq!(evidence.details["selfReportMatches"], true);
        assert_eq!(evidence.details["providerMatches"], false);
        assert!(evidence.score < 100.0);
    }

    #[test]
    fn unrelated_data_does_not_count_as_a_reasoning_attestation() {
        let request = request(ProbeMode::Standard);
        let observation = ProbeObservation::fixture(
            ProbeKind::ReasoningAttestation,
            200,
            json!({
                "content": [
                    {"type": "thinking", "thinking": "summary"},
                    {"type": "tool_result", "data": "A".repeat(128)}
                ]
            }),
            "1073",
        );
        let evidence = ReasoningAttestationStrategy.analyze(&request, &[observation]);
        assert_eq!(evidence.status, EvidenceStatus::Fail);
        assert_eq!(evidence.details["attestationShapePlausible"], false);
    }

    #[test]
    fn stream_audit_tolerates_ping_but_rejects_errors_and_missing_message_delta() {
        let valid = vec![
            StreamEventObservation {
                event: "message_start".into(),
                elapsed_ms: 1,
                data: json!({}),
            },
            StreamEventObservation {
                event: "ping".into(),
                elapsed_ms: 2,
                data: json!({}),
            },
            StreamEventObservation {
                event: "content_block_start".into(),
                elapsed_ms: 3,
                data: json!({}),
            },
            StreamEventObservation {
                event: "content_block_delta".into(),
                elapsed_ms: 4,
                data: json!({}),
            },
            StreamEventObservation {
                event: "content_block_stop".into(),
                elapsed_ms: 5,
                data: json!({}),
            },
            StreamEventObservation {
                event: "message_delta".into(),
                elapsed_ms: 6,
                data: json!({}),
            },
            StreamEventObservation {
                event: "message_stop".into(),
                elapsed_ms: 7,
                data: json!({}),
            },
        ];
        assert!(audit_stream_sequence(Protocol::Anthropic, &valid).is_empty());

        let invalid = vec![
            StreamEventObservation {
                event: "message_start".into(),
                elapsed_ms: 1,
                data: json!({}),
            },
            StreamEventObservation {
                event: "content_block_start".into(),
                elapsed_ms: 2,
                data: json!({}),
            },
            StreamEventObservation {
                event: "content_block_stop".into(),
                elapsed_ms: 3,
                data: json!({}),
            },
            StreamEventObservation {
                event: "error".into(),
                elapsed_ms: 4,
                data: json!({"error": {"type": "overloaded"}}),
            },
            StreamEventObservation {
                event: "message_stop".into(),
                elapsed_ms: 5,
                data: json!({}),
            },
        ];
        let failures = audit_stream_sequence(Protocol::Anthropic, &invalid);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("stream error"))
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("0 message_delta"))
        );
    }

    #[test]
    fn reasoning_probe_selects_model_compatible_configuration() {
        for (model, expected_type, expected_max_tokens) in [
            ("claude-opus-4-7", "adaptive", 16_000),
            ("claude-sonnet-4-6", "enabled", 4_096),
            ("claude-haiku-4-5", "enabled", 4_096),
        ] {
            let mut request = request(ProbeMode::Quick);
            request.model = model.into();
            let probes = ReasoningAttestationStrategy.build(&request).unwrap();
            assert_eq!(probes[0].body["thinking"]["type"], expected_type);
            assert_eq!(probes[0].body["max_tokens"], expected_max_tokens);
        }
    }

    #[test]
    fn strict_attestation_builds_a_continuation_and_promotes_only_after_acceptance() {
        let mut request = request(ProbeMode::Quick);
        request
            .parameters
            .insert("strictAttestation".into(), json!(true));
        let first = ProbeObservation {
            latency_ms: 10,
            response: json!({
                "content": [
                    {"type": "thinking", "thinking": "summary", "signature": "A".repeat(96)},
                    {"type": "text", "text": "1073"}
                ]
            }),
            ..ProbeObservation::fixture(ProbeKind::ReasoningAttestation, 200, json!({}), "1073")
        };
        let follow_up = ReasoningAttestationStrategy
            .follow_up(&request, std::slice::from_ref(&first))
            .unwrap();
        assert_eq!(follow_up.len(), 1);
        assert_eq!(follow_up[0].body["messages"].as_array().unwrap().len(), 3);
        assert!(follow_up[0].body.get("thinking").is_none());

        let before = ReasoningAttestationStrategy.analyze(&request, std::slice::from_ref(&first));
        assert_eq!(before.status, EvidenceStatus::Warn);
        assert_eq!(before.details["continuationValidated"], false);

        let accepted = ProbeObservation::fixture(
            ProbeKind::ReasoningAttestation,
            200,
            json!({"content": [{"type": "text", "text": "confirmed"}]}),
            "confirmed",
        );
        let after = ReasoningAttestationStrategy.analyze(&request, &[first, accepted]);
        assert_eq!(after.status, EvidenceStatus::Pass);
        assert_eq!(after.basis, EvidenceBasis::Observed);
        assert_eq!(after.details["continuationValidated"], true);
    }

    #[test]
    fn context_gradient_is_bounded_by_probe_mode_and_echoes_only_at_the_end() {
        for (mode, expected_units) in [
            (ProbeMode::Quick, vec![0, 24]),
            (ProbeMode::Standard, vec![0, 24, 64]),
            (ProbeMode::Full, vec![0, 24, 64, 128]),
        ] {
            let probes = ContextAuditStrategy
                .build(&request(mode))
                .expect("context probes build");
            assert_eq!(
                probes
                    .iter()
                    .map(|probe| probe.context.as_ref().unwrap().controlled_units)
                    .collect::<Vec<_>>(),
                expected_units
            );
            assert!(probes.iter().all(|probe| probe.kind == ProbeKind::Context));
            assert!(probes.iter().all(|probe| {
                probe.body["messages"]
                    .as_array()
                    .is_some_and(|messages| messages.len() == 1 && messages[0]["role"] == "user")
            }));
            assert!(probes.iter().all(|probe| {
                let metadata = probe.context.as_ref().unwrap();
                metadata.independent_request
                    && metadata.message_count == 1
                    && metadata.request_body_bytes > metadata.controlled_bytes
                    && metadata.request_fingerprint.starts_with("sha256:")
            }));
            assert_eq!(
                probes
                    .iter()
                    .map(|probe| probe.context.as_ref().unwrap().request_fingerprint.as_str())
                    .collect::<BTreeSet<_>>()
                    .len(),
                probes.len()
            );
            assert!(
                probes[..probes.len() - 1]
                    .iter()
                    .all(|probe| probe.body["max_tokens"] == 96)
            );
            assert!(
                probes
                    .last()
                    .unwrap()
                    .context
                    .as_ref()
                    .unwrap()
                    .expects_exact_echo
            );
            assert!(
                probes.last().unwrap().body["messages"][0]["content"]
                    .as_str()
                    .unwrap()
                    .contains("Do not reveal, quote, or describe any system")
            );
        }
    }

    #[test]
    fn context_audit_estimates_fixed_input_overhead_and_confirms_exact_echo() {
        let request = request(ProbeMode::Standard);
        let observations = context_observations(&request, 72, true);
        let rules = crate::rules::rules_from_request(&request).unwrap();
        let summary = summarize_context_audit(&observations, &rules.evaluation.context)
            .expect("audit summary");

        assert_eq!(summary.sample_count, 3);
        assert_eq!(summary.monotonic_growth, Some(true));
        assert_eq!(summary.growth_ratio, Some(1.0));
        assert_eq!(summary.fit_confidence, Some(1.0));
        assert_eq!(summary.estimated_fixed_overhead_tokens, Some(72));
        assert_eq!(
            summary.overhead_assessment,
            ContextOverheadAssessment::Elevated
        );
        assert_eq!(summary.final_echo_status, ContextEchoStatus::Exact);
        assert!(summary.controlled_context_confirmed);
        assert!(summary.independent_requests);
        assert!(summary.unique_request_fingerprints);
        assert_eq!(summary.cumulative_history_suspected, Some(false));
        assert!(!summary.cache_hit_observed);
        assert_eq!(
            summary.accounting_interpretation,
            "independent_linear_payload_growth"
        );

        let evidence = ContextAuditStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Warn);
        assert_eq!(evidence.severity, EvidenceSeverity::Minor);
        assert_eq!(evidence.score, 76.0);
        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains(&observations[2].context.as_ref().unwrap().audit_id));
        assert!(!serialized.contains("amber_cobalt_lumen_vector"));
    }

    #[test]
    fn context_audit_rejects_a_modified_final_controlled_context() {
        let request = request(ProbeMode::Standard);
        let observations = context_observations(&request, 24, false);
        let rules = crate::rules::rules_from_request(&request).unwrap();
        let summary = summarize_context_audit(&observations, &rules.evaluation.context)
            .expect("audit summary");
        assert_eq!(summary.final_echo_status, ContextEchoStatus::Mismatch);
        assert!(!summary.controlled_context_confirmed);

        let evidence = ContextAuditStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Fail);
        assert_eq!(evidence.severity, EvidenceSeverity::Major);
        assert_eq!(evidence.score, 24.0);
    }

    #[test]
    fn context_audit_flags_high_fixed_overhead_consistent_with_an_added_prompt() {
        let request = request(ProbeMode::Standard);
        let observations = context_observations(&request, 220, true);
        let rules = crate::rules::rules_from_request(&request).unwrap();
        let summary = summarize_context_audit(&observations, &rules.evaluation.context)
            .expect("audit summary");
        assert_eq!(summary.estimated_fixed_overhead_tokens, Some(220));
        assert_eq!(summary.overhead_assessment, ContextOverheadAssessment::High);

        let evidence = ContextAuditStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Warn);
        assert_eq!(evidence.severity, EvidenceSeverity::Major);
        assert_eq!(evidence.score, 58.0);
    }

    #[test]
    fn context_audit_flags_non_monotonic_reported_input_usage() {
        let request = request(ProbeMode::Standard);
        let mut observations = context_observations(&request, 24, true);
        observations[1].usage.input_tokens = observations[0].usage.input_tokens - 1;
        let rules = crate::rules::rules_from_request(&request).unwrap();
        let summary = summarize_context_audit(&observations, &rules.evaluation.context)
            .expect("audit summary");
        assert_eq!(summary.monotonic_growth, Some(false));

        let evidence = ContextAuditStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Warn);
        assert_eq!(evidence.severity, EvidenceSeverity::Major);
        assert_eq!(evidence.score, 52.0);
    }

    fn install_synthetic_bank(request: &mut ProbeRequest) {
        request.parameters.insert(
            crate::fingerprint::BANK_PARAMETER_KEY.into(),
            serde_json::to_value(crate::fingerprint::fixtures::synthetic_bank()).unwrap(),
        );
    }

    #[test]
    fn a_resolved_numeric_bank_adds_a_second_identity_probe() {
        let mut request = request(ProbeMode::Standard);
        assert_eq!(IdentityStrategy.build(&request).unwrap().len(), 1);

        install_synthetic_bank(&mut request);
        let probes = IdentityStrategy.build(&request).unwrap();
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0].kind, ProbeKind::Identity);
        assert_eq!(probes[1].kind, ProbeKind::NumericFingerprint);
        assert_eq!(
            probes[1].body["messages"][0]["content"],
            json!(crate::fingerprint::NUMERIC_PROBE_PROMPT)
        );
        assert_eq!(
            probes[1].body["max_tokens"],
            json!(crate::fingerprint::NUMERIC_PROBE_MAX_TOKENS)
        );
    }

    #[test]
    fn numeric_attribution_never_changes_the_identity_score() {
        let mut request = request(ProbeMode::Standard);
        install_synthetic_bank(&mut request);
        let identity = ProbeObservation::fixture(
            ProbeKind::Identity,
            200,
            json!({"model": "claude-sonnet-4-6"}),
            "I am Claude, provided by Anthropic.",
        );
        let baseline = IdentityStrategy.analyze(&request, std::slice::from_ref(&identity));
        assert!(!baseline.details.contains_key("attributedModel"));

        let numeric = ProbeObservation::fixture(
            ProbeKind::NumericFingerprint,
            200,
            json!({}),
            crate::fingerprint::fixtures::synthetic_sequence(1, 320),
        );
        let evidence = IdentityStrategy.analyze(&request, &[identity, numeric]);
        assert_eq!(evidence.score, baseline.score);
        assert_eq!(evidence.status, baseline.status);
        assert_eq!(evidence.severity, baseline.severity);
        assert_eq!(evidence.details["attributedModel"], json!("alpha-model"));
        assert_eq!(evidence.details["attributedFamily"], json!("alpha"));
        assert_eq!(evidence.details["numericParsedCount"], json!(320));
        assert_eq!(evidence.details["numericExpectedCount"], json!(320));
        assert_eq!(evidence.details["attributionInconclusive"], json!(false));
        assert!(evidence.details["attributionProbability"].as_f64().unwrap() > 0.6);
        assert_eq!(
            evidence.details["attributionCandidates"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
