use super::{
    OutboundProbe, ProbeStrategy,
    strategies::{build_probe, valid_tool_caller},
};
use crate::{
    CoreError, DetectorEvidence, EvidenceBasis, EvidenceCategory, EvidenceSeverity, EvidenceStatus,
    ProbeKind, ProbeMode, ProbeObservation, ProbeRequest, Protocol,
    rules::{BehaviorExpectation, KnowledgeProbeRules, rules_from_request},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use ulid::Ulid;

pub struct BehaviorScenarioStrategy;
pub struct KnowledgeChallengeStrategy;
pub struct DocumentUnderstandingStrategy;
pub struct ToolContractStrategy;
pub struct ResponseIntegrityStrategy;
pub struct RelayPayloadIntegrityStrategy;
pub struct IdentifierStrategy;

impl ProbeStrategy for BehaviorScenarioStrategy {
    fn name(&self) -> &'static str {
        "behavior_scenarios"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .behavior_scenarios
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        rules
            .probes
            .behavior_scenarios
            .iter()
            .map(|scenario| {
                let mut probe = build_probe(request, ProbeKind::Behavior, &scenario.prompt)?;
                probe.challenge_id = Some(format!("behavior:{}", scenario.id));
                probe.demo_response = Some(scenario.demo_response.clone());
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
            return unavailable("behavior_scenarios", EvidenceCategory::Authenticity);
        };
        let evaluation = &rules.evaluation.behavior_scenarios;
        if observations.is_empty() {
            return unsupported(
                "behavior_scenarios",
                &evaluation.display_name,
                EvidenceCategory::Authenticity,
                &rules.evaluation.skipped_summary,
            );
        }
        let outcomes = rules
            .probes
            .behavior_scenarios
            .iter()
            .map(|scenario| {
                let observation = scenario_observation(observations, &scenario.id);
                let passed = observation.is_some_and(|item| {
                    behavior_expectation_matches(&scenario.expectation, &item.text)
                });
                json!({"id": scenario.id, "observed": observation.is_some(), "passed": passed})
            })
            .collect::<Vec<_>>();
        let passed = outcomes
            .iter()
            .filter(|value| value.get("passed").and_then(Value::as_bool) == Some(true))
            .count();
        let score = passed as f64 / outcomes.len() as f64 * 100.0;
        result(
            "behavior_scenarios",
            &evaluation.display_name,
            EvidenceCategory::Authenticity,
            rules.evaluation.grade.status(score),
            rules.evaluation.grade.severity(score),
            score,
            evaluation.weight,
            &evaluation.summary,
            BTreeMap::from([
                ("scenarioCount".into(), json!(outcomes.len())),
                ("passedScenarios".into(), json!(passed)),
                ("outcomes".into(), json!(outcomes)),
            ]),
            EvidenceBasis::Inferred,
            Some(evaluation.confidence),
        )
    }
}

fn scenario_observation<'a>(
    observations: &'a [ProbeObservation],
    id: &str,
) -> Option<&'a ProbeObservation> {
    let expected = format!("behavior:{id}");
    observations
        .iter()
        .find(|item| item.challenge_id.as_deref() == Some(expected.as_str()))
}

fn behavior_expectation_matches(expectation: &BehaviorExpectation, text: &str) -> bool {
    match expectation {
        BehaviorExpectation::PrefixWithoutTerms {
            prefix,
            forbidden_terms,
        } => {
            let normalized = text.trim_start().to_ascii_lowercase();
            normalized.starts_with(&prefix.to_ascii_lowercase())
                && forbidden_terms
                    .iter()
                    .all(|term| !normalized.contains(&term.to_ascii_lowercase()))
        }
        BehaviorExpectation::ExactText { value } => text.trim() == value,
        BehaviorExpectation::JsonFields { fields } => serde_json::from_str::<Value>(text.trim())
            .is_ok_and(|value| {
                fields
                    .iter()
                    .all(|(key, expected)| value.get(key) == Some(expected))
            }),
        BehaviorExpectation::ContainsAny { terms } => {
            let normalized = text.to_ascii_lowercase();
            terms
                .iter()
                .any(|term| normalized.contains(&term.to_ascii_lowercase()))
        }
    }
}

#[derive(Clone)]
struct KnowledgeChallenge {
    id: String,
    prompt: String,
    expected_terms: Vec<String>,
    uncertainty_terms: Vec<String>,
}

impl ProbeStrategy for KnowledgeChallengeStrategy {
    fn name(&self) -> &'static str {
        "knowledge_challenges"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .knowledge_challenges
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        let challenges = selected_knowledge_challenges(request)?;
        let independent = if request.mode == ProbeMode::Full {
            challenges
                .len()
                .min(rules.evaluation.knowledge_challenges.full_independent_limit)
        } else {
            challenges.len()
        };
        let mut probes = challenges
            .iter()
            .take(independent)
            .enumerate()
            .map(|(index, challenge)| {
                let mut probe = build_probe(request, ProbeKind::Knowledge, &challenge.prompt)?;
                probe.challenge_id = Some(format!("knowledge:{index}"));
                probe.demo_response = Some(rules.probes.knowledge.demo_response.clone());
                Ok(probe)
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        if independent < challenges.len() {
            let items = challenges
                .iter()
                .enumerate()
                .skip(independent)
                .map(|(index, challenge)| json!({"index": index, "question": challenge.prompt}))
                .collect::<Vec<_>>();
            let prompt = rules.probes.knowledge.batch_template.replace(
                "{items}",
                &serde_json::to_string(&items).expect("knowledge batch is serializable"),
            );
            let mut probe = build_probe(request, ProbeKind::Knowledge, &prompt)?;
            probe.challenge_id = Some("knowledge:batch".into());
            probe.demo_response = Some("[]".into());
            probes.push(probe);
        }
        Ok(probes)
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("knowledge_challenges", EvidenceCategory::Authenticity);
        };
        let evaluation = &rules.evaluation.knowledge_challenges;
        let Ok(challenges) = selected_knowledge_challenges(request) else {
            return knowledge_unavailable(
                request,
                EvidenceStatus::Error,
                "knowledge_challenges",
                &evaluation.evidence.display_name,
                EvidenceCategory::Authenticity,
                &evaluation.invalid_pack_summary,
            );
        };
        if challenges.is_empty() || observations.is_empty() {
            let registry_error = request
                .parameters
                .get("knowledgePackResolution")
                .and_then(|value| value.get("error"))
                .and_then(Value::as_str);
            let status = if registry_error.is_some() {
                EvidenceStatus::Error
            } else {
                EvidenceStatus::Skip
            };
            let summary = match request
                .parameters
                .get("knowledgePackResolution")
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
            {
                Some("not_found") => &evaluation.not_found_summary,
                Some("disabled") => &evaluation.disabled_summary,
                Some("error") => &evaluation.registry_error_summary,
                _ => &evaluation.missing_summary,
            };
            return knowledge_unavailable(
                request,
                status,
                "knowledge_challenges",
                &evaluation.evidence.display_name,
                EvidenceCategory::Authenticity,
                summary,
            );
        }
        let batch_answers = observations
            .iter()
            .find(|item| item.challenge_id.as_deref() == Some("knowledge:batch"))
            .map(|item| parse_knowledge_batch(&item.text))
            .unwrap_or_default();
        let outcomes = challenges
            .iter()
            .enumerate()
            .map(|(index, challenge)| {
                let challenge_id = format!("knowledge:{index}");
                let answer = observations
                    .iter()
                    .find(|item| item.challenge_id.as_deref() == Some(challenge_id.as_str()))
                    .map(|item| item.text.as_str())
                    .or_else(|| batch_answers.get(&index).map(String::as_str))
                    .or_else(|| {
                        observations
                            .iter()
                            .all(|item| item.challenge_id.is_none())
                            .then(|| observations.get(index).map(|item| item.text.as_str()))
                            .flatten()
                    });
                let lower = answer.unwrap_or_default().to_ascii_lowercase();
                let expected = answer.is_some()
                    && challenge
                        .expected_terms
                        .iter()
                        .all(|term| lower.contains(&term.to_ascii_lowercase()));
                let uncertain = answer.is_some()
                    && challenge
                        .uncertainty_terms
                        .iter()
                        .any(|term| lower.contains(&term.to_ascii_lowercase()));
                json!({"id": challenge.id, "observed": answer.is_some(), "passed": expected && !uncertain, "expectedMatched": expected, "uncertaintyDetected": uncertain})
            })
            .collect::<Vec<_>>();
        let passed = outcomes
            .iter()
            .filter(|item| item.get("passed").and_then(Value::as_bool) == Some(true))
            .count();
        let score = passed as f64 / outcomes.len() as f64 * 100.0;
        result(
            "knowledge_challenges",
            &evaluation.evidence.display_name,
            EvidenceCategory::Authenticity,
            rules.evaluation.grade.status(score),
            rules.evaluation.grade.severity(score),
            score,
            evaluation.evidence.weight,
            &evaluation.evidence.summary,
            BTreeMap::from([
                ("challengeCount".into(), json!(outcomes.len())),
                ("passedChallenges".into(), json!(passed)),
                (
                    "packId".into(),
                    request
                        .parameters
                        .get("knowledgePackId")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "packVersion".into(),
                    request
                        .parameters
                        .get("knowledgePackVersion")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "packChannel".into(),
                    request
                        .parameters
                        .get("knowledgePackChannel")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "packDigest".into(),
                    request
                        .parameters
                        .get("knowledgePackDigest")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "resolution".into(),
                    request
                        .parameters
                        .get("knowledgePackResolution")
                        .cloned()
                        .unwrap_or_else(|| json!({"source": "request", "status": "provided"})),
                ),
                ("outcomes".into(), json!(outcomes)),
            ]),
            EvidenceBasis::Inferred,
            Some(evaluation.evidence.confidence),
        )
    }
}

fn knowledge_unavailable(
    request: &ProbeRequest,
    status: EvidenceStatus,
    name: &str,
    display_name: &str,
    category: EvidenceCategory,
    summary: &str,
) -> DetectorEvidence {
    result(
        name,
        display_name,
        category,
        status,
        EvidenceSeverity::Info,
        0.0,
        0.0,
        summary,
        BTreeMap::from([(
            "resolution".into(),
            request
                .parameters
                .get("knowledgePackResolution")
                .cloned()
                .unwrap_or_else(|| json!({"source": "request", "status": "not_provided"})),
        )]),
        EvidenceBasis::Unsupported,
        None,
    )
}

fn selected_knowledge_challenges(
    request: &ProbeRequest,
) -> Result<Vec<KnowledgeChallenge>, CoreError> {
    let Some(rules) = rules_from_request(request) else {
        return Ok(Vec::new());
    };
    let evaluation = &rules.evaluation.knowledge_challenges;
    let limit = if request.mode == ProbeMode::Full {
        evaluation.full_limit
    } else {
        evaluation.standard_limit
    };
    Ok(knowledge_challenges(
        request,
        &rules.probes.knowledge,
        &evaluation.default_uncertainty_terms,
    )?
    .into_iter()
    .take(limit)
    .collect())
}

fn parse_knowledge_batch(text: &str) -> BTreeMap<usize, String> {
    serde_json::from_str::<Value>(text.trim())
        .ok()
        .and_then(|value| value.as_array().cloned())
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some((
                item.get("index")?.as_u64()? as usize,
                item.get("answer")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

fn knowledge_challenges(
    request: &ProbeRequest,
    rules: &KnowledgeProbeRules,
    default_uncertainty_terms: &[String],
) -> Result<Vec<KnowledgeChallenge>, CoreError> {
    let Some(items) = request
        .parameters
        .get("knowledgeChallenges")
        .and_then(Value::as_array)
    else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let prompt = item
                .get("prompt")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            let expected_terms = string_array(item.get("expectedTerms"));
            if prompt.is_empty() || prompt.len() > 1_500 || expected_terms.is_empty() {
                return Err(CoreError::Parse(format!(
                    "invalid knowledge challenge at index {index}"
                )));
            }
            Ok(KnowledgeChallenge {
                id: item
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("challenge")
                    .to_owned(),
                prompt: format!("{} {prompt}", rules.question_prefix),
                expected_terms,
                uncertainty_terms: {
                    let terms = string_array(item.get("uncertaintyTerms"));
                    if terms.is_empty() {
                        default_uncertainty_terms.to_vec()
                    } else {
                        terms
                    }
                },
            })
        })
        .collect()
}

impl ProbeStrategy for DocumentUnderstandingStrategy {
    fn name(&self) -> &'static str {
        "document_understanding"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .document_understanding
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        let document_prompt = &rules.probes.document_prompt;
        let marker = format!("THE-STANDARD-DOC-{}", Ulid::new());
        let pdf = minimal_pdf(&marker);
        let mut probe = build_probe(request, ProbeKind::Document, document_prompt)?;
        probe.body["messages"] = json!([{
            "role": "user",
            "content": [
                {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": BASE64.encode(pdf)}},
                {"type": "text", "text": document_prompt}
            ]
        }]);
        probe.challenge_id = Some(marker);
        Ok(vec![probe])
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("document_understanding", EvidenceCategory::Capability);
        };
        let evaluation = &rules.evaluation.document_understanding;
        let Some(observation) = observations.first() else {
            return unsupported(
                "document_understanding",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &evaluation.unsupported_summary,
            );
        };
        let marker = observation.challenge_id.as_deref();
        let recovered = marker.is_some_and(|marker| observation.text.contains(marker));
        let accepted = (200..300).contains(&observation.status_code);
        let outcome = if recovered {
            &evaluation.recovered
        } else if accepted {
            &evaluation.accepted_without_marker
        } else {
            &evaluation.rejected
        };
        result(
            "document_understanding",
            &evaluation.display_name,
            EvidenceCategory::Capability,
            rules.evaluation.grade.status(outcome.score),
            rules.evaluation.grade.severity(outcome.score),
            outcome.score,
            evaluation.weight,
            &outcome.summary,
            BTreeMap::from([
                ("mediaType".into(), json!("application/pdf")),
                ("httpAccepted".into(), json!(accepted)),
                ("markerRecovered".into(), json!(recovered)),
            ]),
            EvidenceBasis::Observed,
            Some(outcome.confidence),
        )
    }
}

impl ProbeStrategy for ToolContractStrategy {
    fn name(&self) -> &'static str {
        "tool_contract"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .tool_contract
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        let contract = &rules.probes.tool_contract;
        let strict = rules
            .probes
            .activation
            .tool_strict
            .enabled(request.mode, request.protocol);
        let tool_name = format!(
            "the_standard_record_{}",
            Ulid::new().to_string().to_ascii_lowercase()
        );
        let prompt = contract
            .prompt
            .replace("{region}", &contract.region)
            .replace("{priority}", &contract.priority.to_string());
        let mut probe = build_probe(request, ProbeKind::ToolContract, &prompt)?;
        match request.protocol {
            Protocol::Anthropic => {
                probe.body["tools"] = json!([{
                    "name": tool_name,
                    "description": contract.description,
                    "strict": strict,
                    "input_schema": {"type": "object", "properties": {
                        "region": {"type": "string", "enum": contract.region_options},
                        "priority": {"type": "integer", "minimum": contract.priority_minimum, "maximum": contract.priority_maximum}
                    }, "required": ["region", "priority"], "additionalProperties": false}
                }]);
                probe.body["tool_choice"] = json!({"type": "tool", "name": tool_name});
            }
            Protocol::Openai => {
                probe.body["tools"] = json!([{"type": "function", "function": {
                    "name": tool_name,
                    "description": contract.description,
                    "strict": strict,
                    "parameters": {"type": "object", "properties": {
                        "region": {"type": "string", "enum": contract.region_options},
                        "priority": {"type": "integer", "minimum": contract.priority_minimum, "maximum": contract.priority_maximum}
                    }, "required": ["region", "priority"], "additionalProperties": false}
                }}]);
                probe.body["tool_choice"] =
                    json!({"type": "function", "function": {"name": tool_name}});
            }
            Protocol::Gemini => {}
        }
        probe.challenge_id = Some(tool_name);
        probe.demo_tool_arguments = Some(json!({
            "region": contract.region,
            "priority": contract.priority,
        }));
        Ok(vec![probe])
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("tool_contract", EvidenceCategory::Capability);
        };
        let evaluation = &rules.evaluation.tool_contract;
        let Some(observation) = observations.first() else {
            return unsupported(
                "tool_contract",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &rules.evaluation.skipped_summary,
            );
        };
        let contract = Some(&rules.probes.tool_contract);
        let expected_name = observation.challenge_id.clone().unwrap_or_default();
        let (identifier, name, arguments, finish_reason, caller) = match request.protocol {
            Protocol::Anthropic => {
                let block = observation
                    .response
                    .get("content")
                    .and_then(Value::as_array)
                    .and_then(|items| {
                        items.iter().find(|item| {
                            item.get("type").and_then(Value::as_str) == Some("tool_use")
                        })
                    });
                (
                    block
                        .and_then(|item| item.get("id"))
                        .and_then(Value::as_str),
                    block
                        .and_then(|item| item.get("name"))
                        .and_then(Value::as_str),
                    block.and_then(|item| item.get("input")).cloned(),
                    observation
                        .response
                        .get("stop_reason")
                        .and_then(Value::as_str),
                    block.and_then(|item| item.get("caller")).cloned(),
                )
            }
            Protocol::Openai => {
                let call = observation
                    .response
                    .pointer("/choices/0/message/tool_calls/0");
                let arguments = call
                    .and_then(|item| item.pointer("/function/arguments"))
                    .and_then(Value::as_str)
                    .and_then(|value| serde_json::from_str::<Value>(value).ok());
                (
                    call.and_then(|item| item.get("id")).and_then(Value::as_str),
                    call.and_then(|item| item.pointer("/function/name"))
                        .and_then(Value::as_str),
                    arguments,
                    observation
                        .response
                        .pointer("/choices/0/finish_reason")
                        .and_then(Value::as_str),
                    None,
                )
            }
            Protocol::Gemini => (None, None, None, None, None),
        };
        let identifier_valid = identifier.is_some_and(|value| match request.protocol {
            Protocol::Anthropic => value.starts_with("toolu_"),
            Protocol::Openai => !value.trim().is_empty(),
            Protocol::Gemini => false,
        });
        let name_valid = name == Some(expected_name.as_str());
        let arguments_valid = arguments.as_ref().is_some_and(|value| {
            contract.is_some_and(|contract| {
                value.get("region").and_then(Value::as_str) == Some(contract.region.as_str())
                    && value.get("priority").and_then(Value::as_i64) == Some(contract.priority)
            })
        });
        let finish_valid = match request.protocol {
            Protocol::Anthropic => finish_reason == Some("tool_use"),
            Protocol::Openai => finish_reason == Some("tool_calls"),
            Protocol::Gemini => false,
        };
        let caller_valid = caller.as_ref().is_none_or(valid_tool_caller);
        let mut checks = vec![identifier_valid, name_valid, arguments_valid, finish_valid];
        if caller.is_some() {
            checks.push(caller_valid);
        }
        let score =
            checks.iter().filter(|value| **value).count() as f64 / checks.len() as f64 * 100.0;
        result(
            "tool_contract",
            &evaluation.display_name,
            EvidenceCategory::Capability,
            rules.evaluation.grade.status(score),
            rules.evaluation.grade.severity(score),
            score,
            evaluation.weight,
            &evaluation.summary,
            BTreeMap::from([
                ("identifierValid".into(), json!(identifier_valid)),
                ("nameValid".into(), json!(name_valid)),
                ("argumentsValid".into(), json!(arguments_valid)),
                ("finishReasonValid".into(), json!(finish_valid)),
                ("callerPresent".into(), json!(caller.is_some())),
                ("callerValid".into(), json!(caller_valid)),
                ("caller".into(), caller.unwrap_or(Value::Null)),
                (
                    "strictRequested".into(),
                    json!(
                        rules
                            .probes
                            .activation
                            .tool_strict
                            .enabled(request.mode, request.protocol)
                    ),
                ),
                ("arguments".into(), arguments.unwrap_or(Value::Null)),
            ]),
            EvidenceBasis::Observed,
            Some(evaluation.confidence),
        )
    }
}

impl ProbeStrategy for RelayPayloadIntegrityStrategy {
    fn name(&self) -> &'static str {
        "relay_payload_integrity"
    }

    fn build(&self, _request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
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
            return unavailable("relay_payload_integrity", EvidenceCategory::Protocol);
        };
        let activation = &rules.probes.activation.relay_audit;
        let evaluation = &rules.evaluation.relay_audit;
        if !activation.enabled(request.mode, request.protocol) {
            return unsupported(
                "relay_payload_integrity",
                &evaluation.display_name,
                EvidenceCategory::Protocol,
                &rules.evaluation.skipped_summary,
            );
        }
        if observations.len() < evaluation.minimum_observations {
            return result(
                "relay_payload_integrity",
                &evaluation.display_name,
                EvidenceCategory::Protocol,
                EvidenceStatus::Skip,
                EvidenceSeverity::Info,
                0.0,
                0.0,
                &evaluation.insufficient_summary,
                BTreeMap::from([
                    ("observationsExamined".into(), json!(observations.len())),
                    (
                        "minimumObservations".into(),
                        json!(evaluation.minimum_observations),
                    ),
                ]),
                EvidenceBasis::Unsupported,
                None,
            );
        }

        let mut tool_samples = 0_usize;
        let mut tool_mismatches = 0_usize;
        let mut model_samples = 0_usize;
        let mut model_mismatches = 0_usize;
        let mut stream_samples = 0_usize;
        let mut stream_anomalies = 0_usize;
        let mut secret_marker_hits = BTreeSet::new();
        for observation in observations {
            if let Some(declared) = response_model(&observation.response) {
                model_samples += 1;
                if !route_matches(&request.model, declared) {
                    model_mismatches += 1;
                }
            }
            if !observation.stream_events.is_empty() {
                stream_samples += 1;
                if stream_has_anomaly(&observation.stream_events) {
                    stream_anomalies += 1;
                }
            }
            let lower = observation.text.to_ascii_lowercase();
            for marker in &rules.probes.relay_audit.secret_markers {
                if lower.contains(&marker.to_ascii_lowercase()) {
                    secret_marker_hits.insert(marker.clone());
                }
            }
            if observation.kind == ProbeKind::ToolContract {
                tool_samples += 1;
                if !tool_payload_matches(request, &rules.probes.tool_contract, observation) {
                    tool_mismatches += 1;
                }
            }
        }

        let tool_rate = ratio(tool_mismatches, tool_samples);
        let model_rate = ratio(model_mismatches, model_samples);
        let stream_rate = ratio(stream_anomalies, stream_samples);
        let secret_rate = if secret_marker_hits.is_empty() {
            0.0
        } else {
            1.0
        };
        let score = (100.0
            - evaluation.tool_mismatch_penalty * tool_rate
            - evaluation.model_mismatch_penalty * model_rate
            - evaluation.stream_anomaly_penalty * stream_rate
            - evaluation.secret_marker_penalty * secret_rate)
            .clamp(0.0, 100.0);
        let anomalous = tool_mismatches > 0
            || model_mismatches > 0
            || stream_anomalies > 0
            || !secret_marker_hits.is_empty();
        result(
            "relay_payload_integrity",
            &evaluation.display_name,
            EvidenceCategory::Protocol,
            rules.evaluation.grade.status(score),
            rules.evaluation.grade.severity(score),
            score,
            evaluation.weight,
            if anomalous {
                &evaluation.anomaly_summary
            } else {
                &evaluation.clean_summary
            },
            BTreeMap::from([
                ("observationsExamined".into(), json!(observations.len())),
                ("toolSamples".into(), json!(tool_samples)),
                ("toolMismatches".into(), json!(tool_mismatches)),
                ("modelSamples".into(), json!(model_samples)),
                ("modelMismatches".into(), json!(model_mismatches)),
                ("streamSamples".into(), json!(stream_samples)),
                ("streamAnomalies".into(), json!(stream_anomalies)),
                (
                    "secretMarkersObserved".into(),
                    json!(secret_marker_hits.into_iter().collect::<Vec<_>>()),
                ),
                ("toolMismatchRate".into(), json!(round3(tool_rate))),
                ("modelMismatchRate".into(), json!(round3(model_rate))),
                ("streamAnomalyRate".into(), json!(round3(stream_rate))),
                ("anomalyObserved".into(), json!(anomalous)),
                (
                    "evidenceBoundary".into(),
                    json!("local response observations; no provider-origin proof"),
                ),
            ]),
            EvidenceBasis::Inferred,
            Some(evaluation.confidence),
        )
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn response_model(response: &Value) -> Option<&str> {
    response
        .get("model")
        .and_then(Value::as_str)
        .or_else(|| response.pointer("/response/model").and_then(Value::as_str))
}

fn route_matches(requested: &str, declared: &str) -> bool {
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

fn tool_payload_matches(
    request: &ProbeRequest,
    contract: &crate::rules::ToolContractRules,
    observation: &ProbeObservation,
) -> bool {
    let expected_name = observation.challenge_id.as_deref().unwrap_or_default();
    let (name, arguments) = match request.protocol {
        Protocol::Anthropic => observation
            .response
            .get("content")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item.get("type").and_then(Value::as_str) == Some("tool_use"))
            })
            .map(|block| {
                (
                    block.get("name").and_then(Value::as_str),
                    block.get("input").cloned(),
                )
            })
            .unwrap_or((None, None)),
        Protocol::Openai => observation
            .response
            .pointer("/choices/0/message/tool_calls/0/function")
            .map(|function| {
                (
                    function.get("name").and_then(Value::as_str),
                    function
                        .get("arguments")
                        .and_then(Value::as_str)
                        .and_then(|value| serde_json::from_str::<Value>(value).ok()),
                )
            })
            .unwrap_or((None, None)),
        Protocol::Gemini => (None, None),
    };
    name == Some(expected_name)
        && arguments.is_some_and(|value| {
            value.get("region").and_then(Value::as_str) == Some(contract.region.as_str())
                && value.get("priority").and_then(Value::as_i64) == Some(contract.priority)
        })
}

fn stream_has_anomaly(events: &[crate::StreamEventObservation]) -> bool {
    if events
        .iter()
        .any(|event| event.data.get("unparsedData").is_some())
    {
        return true;
    }
    let usage = events
        .iter()
        .filter_map(|event| {
            event
                .data
                .pointer("/usage/output_tokens")
                .and_then(Value::as_u64)
                .or_else(|| {
                    event
                        .data
                        .pointer("/message/usage/output_tokens")
                        .and_then(Value::as_u64)
                })
        })
        .collect::<Vec<_>>();
    usage.windows(2).any(|pair| pair[1] < pair[0])
}

impl ProbeStrategy for ResponseIntegrityStrategy {
    fn name(&self) -> &'static str {
        "response_integrity"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .response_integrity
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        let integrity = &rules.probes.response_integrity;
        let prompt = &integrity.equivalence_prompt;
        let mut non_stream = build_probe(request, ProbeKind::StreamIntegrity, prompt)?;
        non_stream.demo_response = Some(integrity.demo_equivalence_response.clone());
        let mut streaming = non_stream.clone();
        streaming.body["stream"] = json!(true);
        set_deterministic_sampling(
            &mut non_stream,
            &request.model,
            &integrity.deterministic_sampling_excluded_model_markers,
        );
        set_deterministic_sampling(
            &mut streaming,
            &request.model,
            &integrity.deterministic_sampling_excluded_model_markers,
        );
        let mut probes = vec![non_stream, streaming];
        if rules
            .probes
            .activation
            .long_output
            .enabled(request.mode, request.protocol)
        {
            let completion_marker = format!("THE_STANDARD_LONG_{}", Ulid::new());
            let mut long = build_probe(
                request,
                ProbeKind::LongOutput,
                &integrity
                    .long_output_prompt_template
                    .replace("{marker}", &completion_marker),
            )?;
            long.body["max_tokens"] = json!(integrity.long_output_max_tokens);
            long.challenge_id = Some(completion_marker);
            long.demo_response = long.challenge_id.as_deref().map(|marker| {
                integrity
                    .demo_long_output_template
                    .replace("{marker}", marker)
            });
            set_deterministic_sampling(
                &mut long,
                &request.model,
                &integrity.deterministic_sampling_excluded_model_markers,
            );
            probes.push(long);
        }
        Ok(probes)
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("response_integrity", EvidenceCategory::Protocol);
        };
        let evaluation = &rules.evaluation.response_integrity;
        if observations.len() < 2 {
            return unsupported(
                "response_integrity",
                &evaluation.evidence.display_name,
                EvidenceCategory::Protocol,
                &evaluation.unsupported_summary,
            );
        }
        let non_stream = &observations[0];
        let streaming = &observations[1];
        let similarity = text_similarity(&non_stream.text, &streaming.text);
        let stream_lifecycle_present = !streaming.stream_events.is_empty();
        let usage_plausible = observations.iter().take(2).all(|observation| {
            usage_is_plausible(
                observation,
                evaluation.minimum_chars_per_token,
                evaluation.maximum_chars_per_token,
            )
        });
        let cumulative_usage_valid = stream_usage_is_cumulative(streaming);
        let long_output_complete = observations.get(2).map(|item| {
            item.challenge_id
                .as_deref()
                .is_some_and(|marker| item.text.contains(marker))
        });
        let mut checks = vec![
            similarity >= evaluation.text_similarity_minimum,
            stream_lifecycle_present,
            usage_plausible,
            cumulative_usage_valid,
        ];
        if let Some(value) = long_output_complete {
            checks.push(value);
        }
        let score =
            checks.iter().filter(|value| **value).count() as f64 / checks.len() as f64 * 100.0;
        result(
            "response_integrity",
            &evaluation.evidence.display_name,
            EvidenceCategory::Protocol,
            rules.evaluation.grade.status(score),
            rules.evaluation.grade.severity(score),
            score,
            evaluation.evidence.weight,
            &evaluation.evidence.summary,
            BTreeMap::from([
                ("textSimilarity".into(), json!(round3(similarity))),
                (
                    "streamLifecyclePresent".into(),
                    json!(stream_lifecycle_present),
                ),
                ("usagePlausible".into(), json!(usage_plausible)),
                (
                    "cumulativeStreamUsage".into(),
                    json!(cumulative_usage_valid),
                ),
                ("longOutputComplete".into(), json!(long_output_complete)),
                (
                    "streamEventCount".into(),
                    json!(streaming.stream_events.len()),
                ),
            ]),
            EvidenceBasis::Inferred,
            Some(evaluation.evidence.confidence),
        )
    }
}

impl ProbeStrategy for IdentifierStrategy {
    fn name(&self) -> &'static str {
        "identifiers"
    }

    fn build(&self, _request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
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
            return unavailable("identifiers", EvidenceCategory::Protocol);
        };
        let evaluation = &rules.evaluation.identifiers;
        if request.protocol != Protocol::Anthropic {
            return unsupported(
                "identifiers",
                &evaluation.evidence.display_name,
                EvidenceCategory::Protocol,
                &evaluation.unsupported_protocol_summary,
            );
        }
        let mut outcomes = Vec::new();
        for observation in observations
            .iter()
            .filter(|item| (200..300).contains(&item.status_code))
        {
            if let Some(id) = observation.response.get("id").and_then(Value::as_str) {
                outcomes.push(
                    json!({"kind": "message", "valid": id.starts_with(&evaluation.message_prefix)}),
                );
            }
            visit_objects(&observation.response, &mut |value| {
                match value.get("type").and_then(Value::as_str) {
                    Some("tool_use") => outcomes.push(json!({"kind": "client_tool", "valid": value.get("id").and_then(Value::as_str).is_some_and(|id| id.starts_with(&evaluation.client_tool_prefix))})),
                    Some("server_tool_use") => outcomes.push(json!({"kind": "server_tool", "valid": value.get("id").and_then(Value::as_str).is_some_and(|id| id.starts_with(&evaluation.server_tool_prefix))})),
                    _ => {}
                }
            });
        }
        if outcomes.is_empty() {
            return unsupported(
                "identifiers",
                &evaluation.evidence.display_name,
                EvidenceCategory::Protocol,
                &evaluation.unobserved_summary,
            );
        }
        let valid = outcomes
            .iter()
            .filter(|item| item.get("valid").and_then(Value::as_bool) == Some(true))
            .count();
        let score = valid as f64 / outcomes.len() as f64 * 100.0;
        result(
            "identifiers",
            &evaluation.evidence.display_name,
            EvidenceCategory::Protocol,
            rules.evaluation.grade.status(score),
            rules.evaluation.grade.severity(score),
            score,
            evaluation.evidence.weight,
            &evaluation.evidence.summary,
            BTreeMap::from([
                ("observedIdentifiers".into(), json!(outcomes.len())),
                ("validIdentifiers".into(), json!(valid)),
                ("outcomes".into(), json!(outcomes)),
            ]),
            EvidenceBasis::Observed,
            Some(evaluation.evidence.confidence),
        )
    }
}

fn minimal_pdf(marker: &str) -> Vec<u8> {
    let escaped = marker.replace(['(', ')'], "_");
    let stream = format!("BT /F1 18 Tf 72 700 Td ({escaped}) Tj ET\n");
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_owned(),
        format!(
            "<< /Length {} >>\nstream\n{stream}endstream",
            stream.len()
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
    ];
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{}\nendobj\n", index + 1, object));
    }
    let xref = pdf.len();
    pdf.push_str(&format!(
        "xref\n0 {}\n0000000000 65535 f \n",
        objects.len() + 1
    ));
    for offset in offsets {
        pdf.push_str(&format!("{offset:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer << /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    ));
    pdf.into_bytes()
}

fn set_deterministic_sampling(
    probe: &mut OutboundProbe,
    model: &str,
    excluded_model_markers: &[String],
) {
    let model = model.to_ascii_lowercase();
    if !excluded_model_markers
        .iter()
        .any(|marker| model.contains(marker))
    {
        probe.body["temperature"] = json!(0);
    }
}

fn usage_is_plausible(
    observation: &ProbeObservation,
    minimum_chars_per_token: u64,
    maximum_chars_per_token: u64,
) -> bool {
    if observation.usage.output_tokens == 0 || observation.text.is_empty() {
        return false;
    }
    let chars = observation.text.chars().count() as u64;
    let tokens = observation.usage.output_tokens;
    chars >= tokens.saturating_mul(minimum_chars_per_token)
        && chars <= tokens.saturating_mul(maximum_chars_per_token)
}

fn stream_usage_is_cumulative(observation: &ProbeObservation) -> bool {
    let samples = observation
        .stream_events
        .iter()
        .filter_map(|event| {
            event
                .data
                .pointer("/usage/output_tokens")
                .and_then(Value::as_u64)
                .or_else(|| {
                    event
                        .data
                        .pointer("/message/usage/output_tokens")
                        .and_then(Value::as_u64)
                })
        })
        .collect::<Vec<_>>();
    !samples.is_empty() && samples.windows(2).all(|pair| pair[1] >= pair[0])
}

fn text_similarity(left: &str, right: &str) -> f64 {
    let normalize = |text: &str| {
        text.split_whitespace()
            .map(|word| word.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
    };
    let left = normalize(left);
    let right = normalize(right);
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let union = left.union(&right).count();
    if union == 0 {
        0.0
    } else {
        left.intersection(&right).count() as f64 / union as f64
    }
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn visit_objects(value: &Value, visitor: &mut impl FnMut(&Value)) {
    visitor(value);
    match value {
        Value::Array(items) => items.iter().for_each(|item| visit_objects(item, visitor)),
        Value::Object(map) => map.values().for_each(|item| visit_objects(item, visitor)),
        _ => {}
    }
}

fn round3(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

#[allow(clippy::too_many_arguments)]
fn result(
    name: &str,
    display_name: &str,
    category: EvidenceCategory,
    status: EvidenceStatus,
    severity: EvidenceSeverity,
    score: f64,
    weight: f64,
    summary: &str,
    details: BTreeMap<String, Value>,
    basis: EvidenceBasis,
    confidence: Option<f64>,
) -> DetectorEvidence {
    DetectorEvidence {
        name: name.into(),
        display_name: display_name.into(),
        category,
        status,
        severity,
        basis,
        confidence,
        score,
        weight,
        summary: summary.into(),
        details,
    }
}

fn unsupported(
    name: &str,
    display_name: &str,
    category: EvidenceCategory,
    summary: &str,
) -> DetectorEvidence {
    result(
        name,
        display_name,
        category,
        EvidenceStatus::Skip,
        EvidenceSeverity::Info,
        0.0,
        0.0,
        summary,
        BTreeMap::new(),
        EvidenceBasis::Unsupported,
        None,
    )
}

fn unavailable(name: &str, category: EvidenceCategory) -> DetectorEvidence {
    result(
        name,
        name,
        category,
        EvidenceStatus::Error,
        EvidenceSeverity::Critical,
        0.0,
        0.0,
        "A validated Core rule bundle was not installed.",
        BTreeMap::new(),
        EvidenceBasis::Unsupported,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        BehaviorScenarioStrategy, DocumentUnderstandingStrategy, IdentifierStrategy,
        KnowledgeChallengeStrategy, ResponseIntegrityStrategy, ToolContractStrategy, minimal_pdf,
        text_similarity,
    };
    use crate::{
        EvidenceBasis, EvidenceStatus, ProbeKind, ProbeMode, ProbeObservation, ProbeRequest,
        ProbeStrategy, Protocol, StreamEventObservation, UsageMetrics,
    };
    use serde_json::{Value, json};

    fn request(mode: ProbeMode) -> ProbeRequest {
        ProbeRequest {
            base_url: "https://relay.example/v1".into(),
            api_key: "secret".into(),
            model: "claude-sonnet-4-6".into(),
            protocol: Protocol::Anthropic,
            mode,
            parameters: Default::default(),
            sections: Vec::new(),
        }
    }

    fn observation(kind: ProbeKind, response: serde_json::Value, text: &str) -> ProbeObservation {
        ProbeObservation {
            latency_ms: 100,
            ttft_ms: Some(20),
            usage: UsageMetrics {
                input_tokens: 20,
                output_tokens: 10,
                ..UsageMetrics::default()
            },
            ..ProbeObservation::fixture(kind, 200, response, text)
        }
    }

    #[test]
    fn generated_pdf_contains_a_valid_header_and_marker() {
        let pdf = minimal_pdf("THE-STANDARD-DOC-TEST");
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(String::from_utf8_lossy(&pdf).contains("THE-STANDARD-DOC-TEST"));
        assert!(String::from_utf8_lossy(&pdf).contains("startxref"));
    }

    #[test]
    fn word_set_similarity_handles_equivalent_and_different_text() {
        assert_eq!(text_similarity("same words", "same words"), 1.0);
        assert!(text_similarity("alpha beta", "gamma delta") < 0.1);
    }

    #[test]
    fn behavior_suite_reports_each_scenario_outcome() {
        let request = request(ProbeMode::Full);
        let probes = BehaviorScenarioStrategy.build(&request).unwrap();
        let mut observations = vec![
            observation(
                ProbeKind::Behavior,
                json!({}),
                "REFUSE. Credentials remain private.",
            ),
            observation(
                ProbeKind::Behavior,
                json!({}),
                "THE-STANDARD-INSTRUCTION-INTACT",
            ),
            observation(
                ProbeKind::Behavior,
                json!({}),
                "{\"stable\":true,\"count\":4}",
            ),
            observation(
                ProbeKind::Behavior,
                json!({}),
                "More information is needed.",
            ),
        ];
        for (observation, probe) in observations.iter_mut().zip(probes) {
            observation.challenge_id = probe.challenge_id;
        }
        let evidence = BehaviorScenarioStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.details["passedScenarios"], 4);
        assert_eq!(evidence.basis, EvidenceBasis::Inferred);
    }

    #[test]
    fn behavior_suite_keeps_scenarios_aligned_when_a_middle_probe_is_missing() {
        let request = request(ProbeMode::Full);
        let probes = BehaviorScenarioStrategy.build(&request).unwrap();
        let mut first = observation(
            ProbeKind::Behavior,
            json!({}),
            "REFUSE. Credentials remain private.",
        );
        first.challenge_id = probes[0].challenge_id.clone();
        let mut third = observation(
            ProbeKind::Behavior,
            json!({}),
            "THE-STANDARD-INSTRUCTION-INTACT",
        );
        third.challenge_id = probes[2].challenge_id.clone();
        let evidence = BehaviorScenarioStrategy.analyze(&request, &[first, third]);
        assert_eq!(evidence.details["outcomes"][1]["passed"], false);
        assert_eq!(evidence.details["outcomes"][2]["passed"], false);
    }

    #[test]
    fn absent_knowledge_pack_is_explicitly_unsupported() {
        let evidence = KnowledgeChallengeStrategy.analyze(&request(ProbeMode::Standard), &[]);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.weight, 0.0);
        assert_eq!(evidence.details["resolution"]["source"], "request");
    }

    #[test]
    fn registry_failure_is_an_explicit_zero_weight_error() {
        let mut request = request(ProbeMode::Standard);
        request.parameters.insert(
            "knowledgePackResolution".into(),
            json!({"source": "registry", "status": "error", "error": "registry_invalid_response"}),
        );
        let evidence = KnowledgeChallengeStrategy.analyze(&request, &[]);
        assert_eq!(evidence.status, EvidenceStatus::Error);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.weight, 0.0);
        assert_eq!(
            evidence.details["resolution"]["error"],
            "registry_invalid_response"
        );
    }

    #[test]
    fn calibrated_knowledge_pack_scores_observed_answers() {
        let mut request = request(ProbeMode::Standard);
        request
            .parameters
            .insert("knowledgePackVersion".into(), json!("fixture-1"));
        request.parameters.insert(
            "knowledgeChallenges".into(),
            json!([{
                "id": "release-fact",
                "prompt": "Name the fixture color.",
                "expectedTerms": ["cobalt"],
                "uncertaintyTerms": ["unknown"]
            }]),
        );
        let evidence = KnowledgeChallengeStrategy.analyze(
            &request,
            &[observation(
                ProbeKind::Knowledge,
                json!({}),
                "The color is cobalt.",
            )],
        );
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.details["packVersion"], "fixture-1");
    }

    #[test]
    fn full_knowledge_pack_batches_coverage_items_and_aligns_answers_by_index() {
        let mut request = request(ProbeMode::Full);
        request
            .parameters
            .insert("knowledgePackVersion".into(), json!("fixture-8"));
        request.parameters.insert(
            "knowledgeChallenges".into(),
            Value::Array(
                (0..8)
                    .map(|index| {
                        json!({
                            "id": format!("fact-{index}"),
                            "prompt": format!("Return term-{index}."),
                            "expectedTerms": [format!("term-{index}")],
                            "uncertaintyTerms": ["unknown"]
                        })
                    })
                    .collect(),
            ),
        );
        let probes = KnowledgeChallengeStrategy.build(&request).unwrap();
        assert_eq!(probes.len(), 4);
        assert_eq!(probes[0].challenge_id.as_deref(), Some("knowledge:0"));
        assert_eq!(probes[3].challenge_id.as_deref(), Some("knowledge:batch"));

        let mut observations = (0..3)
            .map(|index| {
                let text = format!("term-{index}");
                let mut item = observation(ProbeKind::Knowledge, json!({}), &text);
                item.challenge_id = Some(format!("knowledge:{index}"));
                item
            })
            .collect::<Vec<_>>();
        let batch = json!(
            (3..8)
                .map(|index| json!({"index": index, "answer": format!("term-{index}")}))
                .collect::<Vec<_>>()
        )
        .to_string();
        let mut batch_observation = observation(ProbeKind::Knowledge, json!({}), &batch);
        batch_observation.challenge_id = Some("knowledge:batch".into());
        observations.push(batch_observation);

        let evidence = KnowledgeChallengeStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.details["challengeCount"], 8);
        assert_eq!(evidence.details["passedChallenges"], 8);
    }

    #[test]
    fn document_marker_recovery_is_direct_observation() {
        let request = request(ProbeMode::Full);
        let probes = DocumentUnderstandingStrategy.build(&request).unwrap();
        assert_eq!(probes.len(), 1);
        let marker = probes[0].challenge_id.clone().expect("document challenge");
        let mut observation = observation(ProbeKind::Document, json!({}), &marker);
        observation.challenge_id = Some(marker);
        let evidence = DocumentUnderstandingStrategy.analyze(&request, &[observation]);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.basis, EvidenceBasis::Observed);
        assert_eq!(evidence.details["markerRecovered"], true);
    }

    #[test]
    fn tool_contract_validates_identifier_name_arguments_and_finish_reason() {
        let request = request(ProbeMode::Standard);
        let probes = ToolContractStrategy.build(&request).unwrap();
        let expected_name = probes[0].challenge_id.clone().expect("tool challenge");
        let response = json!({
            "content": [{"type": "tool_use", "id": "toolu_fixture", "name": expected_name, "input": {"region": "eu-central", "priority": 3}}],
            "stop_reason": "tool_use"
        });
        let mut observation = observation(ProbeKind::ToolContract, response, "");
        observation.challenge_id = Some(expected_name);
        let evidence = ToolContractStrategy.analyze(&request, &[observation]);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.details["argumentsValid"], true);
    }

    #[test]
    fn tool_contract_accepts_forward_compatible_caller_metadata_and_rejects_invalid_scalars() {
        let request = request(ProbeMode::Full);
        let probes = ToolContractStrategy.build(&request).unwrap();
        let expected_name = probes[0].challenge_id.clone().expect("tool challenge");
        let response = json!({
            "content": [{"type": "tool_use", "id": "toolu_fixture", "name": expected_name, "input": {"region": "eu-central", "priority": 3}, "caller": {"kind": "direct"}}],
            "stop_reason": "tool_use"
        });
        let mut object_caller_observation = observation(ProbeKind::ToolContract, response, "");
        object_caller_observation.challenge_id = Some(expected_name.clone());
        let evidence = ToolContractStrategy.analyze(&request, &[object_caller_observation]);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.details["callerValid"], true);

        let response = json!({
            "content": [{"type": "tool_use", "id": "toolu_fixture", "name": expected_name, "input": {"region": "eu-central", "priority": 3}, "caller": false}],
            "stop_reason": "tool_use"
        });
        let mut invalid_caller_observation = observation(ProbeKind::ToolContract, response, "");
        invalid_caller_observation.challenge_id = Some(expected_name);
        let evidence = ToolContractStrategy.analyze(&request, &[invalid_caller_observation]);
        assert_eq!(evidence.details["callerValid"], false);
        assert!(evidence.score < 100.0);
    }

    #[test]
    fn response_integrity_accepts_equivalent_stream_and_nonstream_samples() {
        let text = "TheStandard compares equivalent transport responses deterministically.";
        let non_stream = observation(
            ProbeKind::StreamIntegrity,
            json!({"stop_reason": "end_turn"}),
            text,
        );
        let mut streaming = observation(
            ProbeKind::StreamIntegrity,
            json!({"stop_reason": "end_turn"}),
            text,
        );
        streaming.stream_events = vec![
            StreamEventObservation {
                event: "message_start".into(),
                elapsed_ms: 1,
                data: json!({"message": {"usage": {"output_tokens": 1}}}),
            },
            StreamEventObservation {
                event: "content_block_delta".into(),
                elapsed_ms: 20,
                data: json!({"delta": {"type": "text_delta", "text": text}}),
            },
            StreamEventObservation {
                event: "message_delta".into(),
                elapsed_ms: 90,
                data: json!({"usage": {"output_tokens": 10}}),
            },
            StreamEventObservation {
                event: "message_stop".into(),
                elapsed_ms: 100,
                data: json!({}),
            },
        ];
        let evidence = ResponseIntegrityStrategy
            .analyze(&request(ProbeMode::Standard), &[non_stream, streaming]);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.details["cumulativeStreamUsage"], true);
    }

    #[test]
    fn long_output_requires_the_per_run_completion_marker() {
        let request = request(ProbeMode::Full);
        let probes = ResponseIntegrityStrategy.build(&request).unwrap();
        let marker = probes[2]
            .challenge_id
            .clone()
            .expect("long-output challenge");
        let text = "TheStandard compares equivalent transport responses deterministically.";
        let non_stream = observation(
            ProbeKind::StreamIntegrity,
            json!({"stop_reason": "end_turn"}),
            text,
        );
        let mut streaming = observation(
            ProbeKind::StreamIntegrity,
            json!({"stop_reason": "end_turn"}),
            text,
        );
        streaming.stream_events = vec![
            StreamEventObservation {
                event: "message_start".into(),
                elapsed_ms: 1,
                data: json!({"message": {"usage": {"output_tokens": 1}}}),
            },
            StreamEventObservation {
                event: "message_delta".into(),
                elapsed_ms: 90,
                data: json!({"usage": {"output_tokens": 10}}),
            },
            StreamEventObservation {
                event: "message_stop".into(),
                elapsed_ms: 100,
                data: json!({}),
            },
        ];
        let mut truncated = observation(
            ProbeKind::LongOutput,
            json!({"stop_reason": "end_turn"}),
            "The provider ended normally without returning the requested marker.",
        );
        truncated.challenge_id = Some(marker.clone());
        let evidence = ResponseIntegrityStrategy.analyze(
            &request,
            &[non_stream.clone(), streaming.clone(), truncated],
        );
        assert_eq!(evidence.details["longOutputComplete"], false);

        let mut complete = observation(
            ProbeKind::LongOutput,
            json!({"stop_reason": "end_turn"}),
            format!("A sufficiently long response that ends with {marker}").as_str(),
        );
        complete.challenge_id = Some(marker);
        let evidence =
            ResponseIntegrityStrategy.analyze(&request, &[non_stream, streaming, complete]);
        assert_eq!(evidence.details["longOutputComplete"], true);
    }

    #[test]
    fn identifier_audit_checks_only_stable_prefixes() {
        let response = json!({
            "id": "msg_any-opaque-suffix",
            "content": [{"type": "tool_use", "id": "toolu_another-opaque-suffix", "name": "x", "input": {}}]
        });
        let evidence = IdentifierStrategy.analyze(
            &request(ProbeMode::Quick),
            &[observation(ProbeKind::Identity, response, "")],
        );
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.details["validIdentifiers"], 2);
    }
}
