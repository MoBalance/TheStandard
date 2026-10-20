//! Reasoning-capability evidence: a rule-scored IQ set and the thinking chain.
//!
//! Both detectors inherit the second-wave rule: the rule document owns the
//! facts (questions, answer formats, thresholds, labels) and this module only
//! holds the algorithms. Missing data downgrades to an unknown result with an
//! `unsupported` basis and never becomes a failure.
//!
//! The reasoning-IQ evidence carries the rule document's `scoringVersion` in
//! its details, so a report produced with an older question set is never
//! rescored against a newer one. Only a final, parsable answer can be wrong: a
//! refusal, a truncated answer or unstructured noise is reported as an
//! unanswered question, not as an incorrect one.

use super::{OutboundProbe, ProbeStrategy, strategies::build_probe};
use crate::{
    CoreError, DetectorEvidence, EvidenceBasis, EvidenceCategory, EvidenceSeverity, EvidenceStatus,
    ProbeKind, ProbeObservation, ProbeRequest,
    rules::{
        ReasoningIqAnswerType, ReasoningIqProbeRules, ReasoningIqQuestion, ThinkingChainProbeRules,
        rules_from_request,
    },
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct ReasoningIqStrategy;
pub struct ThinkingChainStrategy;

const IQ_PREFIX: &str = "iq:";
const THINKING_CHAIN_CHALLENGE: &str = "thinking:chain";

impl ProbeStrategy for ReasoningIqStrategy {
    fn name(&self) -> &'static str {
        "reasoning_iq"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .reasoning_iq
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        let iq = &rules.probes.reasoning_iq;
        // Every question is one independent probe, so a single refusal cannot
        // hide the answers to the rest of the set.
        iq.questions
            .iter()
            .map(|question| iq_probe(request, iq, question))
            .collect()
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("reasoning_iq", EvidenceCategory::Capability);
        };
        let evaluation = &rules.evaluation.reasoning_iq;
        let iq = &rules.probes.reasoning_iq;
        if !rules
            .probes
            .activation
            .reasoning_iq
            .enabled(request.mode, request.protocol)
        {
            return unsupported(
                "reasoning_iq",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &rules.evaluation.skipped_summary,
            );
        }
        if observations.is_empty() {
            return unsupported(
                "reasoning_iq",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &evaluation.unsupported_summary,
            );
        }

        let mut answered = 0_usize;
        let mut correct = 0_usize;
        let mut per_question = Vec::with_capacity(iq.questions.len());
        for question in &iq.questions {
            let challenge = format!("{IQ_PREFIX}{}", question.id);
            let judged = observations
                .iter()
                .find(|item| item.challenge_id.as_deref() == Some(challenge.as_str()))
                .and_then(|observation| judge_answer(iq, question, observation));
            if let Some(hit) = judged {
                answered += 1;
                correct += usize::from(hit);
            }
            per_question.push(json!({
                "id": question.id,
                "correct": judged.unwrap_or(false),
            }));
        }
        let score = if answered > 0 {
            (correct as f64 / answered as f64 * 100.0).round()
        } else {
            0.0
        };
        let details = BTreeMap::from([
            ("scoringVersion".into(), json!(iq.scoring_version)),
            ("answered".into(), json!(answered)),
            ("correct".into(), json!(correct)),
            ("total".into(), json!(iq.questions.len())),
            ("score".into(), json!(score)),
            ("perQuestion".into(), json!(per_question)),
        ]);
        // Too few usable answers means the run never measured reasoning; the
        // partial score stays visible but never enters a weighted total.
        if answered < evaluation.minimum_answered {
            return result(
                "reasoning_iq",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                EvidenceStatus::Skip,
                EvidenceSeverity::Info,
                0.0,
                0.0,
                &evaluation.insufficient_summary,
                details,
                EvidenceBasis::Unsupported,
                None,
            );
        }
        let summary = evaluation
            .summary_template
            .replace("{answered}", &answered.to_string())
            .replace("{correct}", &correct.to_string())
            .replace("{total}", &iq.questions.len().to_string());
        result(
            "reasoning_iq",
            &evaluation.display_name,
            EvidenceCategory::Capability,
            rules.evaluation.grade.status(score),
            rules.evaluation.grade.severity(score),
            score,
            evaluation.weight,
            &summary,
            details,
            EvidenceBasis::Observed,
            Some(evaluation.confidence),
        )
    }
}

fn iq_probe(
    request: &ProbeRequest,
    rules: &ReasoningIqProbeRules,
    question: &ReasoningIqQuestion,
) -> Result<OutboundProbe, CoreError> {
    let prompt = rules
        .prompt_template
        .replace("{question}", &question.prompt)
        .replace(
            "{answerFormat}",
            rules.answer_formats.for_type(question.answer_type),
        );
    let mut probe = build_probe(request, ProbeKind::ReasoningIq, &prompt)?;
    probe.body["max_tokens"] = json!(rules.max_tokens);
    probe.challenge_id = Some(format!("{IQ_PREFIX}{}", question.id));
    Ok(probe)
}

/// Judges one answer.
///
/// `None` means "not an answer": a refused, truncated, ambiguous or missing
/// response. Only `Some` values enter the answered/questioned counters, which
/// is what keeps noise from being scored as a wrong answer.
fn judge_answer(
    rules: &ReasoningIqProbeRules,
    question: &ReasoningIqQuestion,
    observation: &ProbeObservation,
) -> Option<bool> {
    if !(200..300).contains(&observation.status_code) || truncated(rules, observation) {
        return None;
    }
    let text = observation.text.trim();
    if text.is_empty() || refused(rules, text) {
        return None;
    }
    match question.answer_type {
        ReasoningIqAnswerType::Integer => {
            let value = final_integer(text)?;
            let expected = question.expected.parse::<i64>().ok()?;
            Some((value - expected).abs() <= question.tolerance)
        }
        ReasoningIqAnswerType::String => {
            let observed = normalize_term(text);
            let expected = normalize_term(&question.expected);
            if observed.is_empty() || expected.is_empty() {
                return None;
            }
            Some(observed.contains(&expected))
        }
        ReasoningIqAnswerType::Choice => {
            final_choice_letter(text).map(|letter| letter == question.expected)
        }
    }
}

fn truncated(rules: &ReasoningIqProbeRules, observation: &ProbeObservation) -> bool {
    let stop_reason = ["stop_reason", "finishReason", "finish_reason"]
        .iter()
        .find_map(|key| observation.response.get(*key).and_then(Value::as_str));
    stop_reason.is_some_and(|reason| {
        rules
            .truncation_stop_reasons
            .iter()
            .any(|declared| declared == reason)
    })
}

fn refused(rules: &ReasoningIqProbeRules, text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    rules
        .refusal_markers
        .iter()
        .any(|marker| lowered.contains(&marker.to_ascii_lowercase()))
}

/// Extracts the last standalone integer of a response.
///
/// The final number of an answer is the answer: intermediate working is
/// allowed, glued tokens such as `gpt5` or `5th` and fraction digits are not.
fn final_integer(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let mut values = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let negative = byte == b'-'
            && index + 1 < bytes.len()
            && bytes[index + 1].is_ascii_digit()
            && (index == 0 || !bytes[index - 1].is_ascii_alphanumeric());
        if !byte.is_ascii_digit() && !negative {
            index += 1;
            continue;
        }
        if index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'.') {
            index += 1;
            continue;
        }
        let start = index;
        if negative {
            index += 1;
        }
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index < bytes.len() && bytes[index].is_ascii_alphabetic() {
            continue;
        }
        if let Ok(value) = text[start..index].parse::<i64>() {
            values.push(value);
        }
    }
    values.last().copied()
}

fn normalize_term(text: &str) -> String {
    text.to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extracts the single-letter answer of a choice question.
fn final_choice_letter(text: &str) -> Option<String> {
    if let Some(letter) = json_choice_letter(text) {
        return Some(letter);
    }
    let trimmed = text
        .trim()
        .trim_end_matches(['.', '。', ')', '!'])
        .trim()
        .to_string();
    if trimmed.len() == 1
        && trimmed
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        return Some(trimmed.to_ascii_uppercase());
    }
    text.split_whitespace()
        .filter_map(|token| {
            let cleaned = token.trim_matches(|character: char| !character.is_ascii_alphabetic());
            (cleaned.len() == 1
                && cleaned
                    .chars()
                    .all(|character| character.is_ascii_uppercase()))
            .then(|| cleaned.to_string())
        })
        .next_back()
}

fn json_choice_letter(text: &str) -> Option<String> {
    for key in ["\"answer\"", "\"choice\""] {
        let mut search = text;
        while let Some(index) = search.find(key) {
            let after = &search[index + key.len()..];
            if let Some(colon) = after.find(':') {
                let rest = &after[colon + 1..];
                if let Some(start) = rest.find('"')
                    && let Some(end) = rest[start + 1..].find('"')
                {
                    let value = &rest[start + 1..start + 1 + end];
                    if value.len() == 1
                        && value
                            .chars()
                            .all(|character| character.is_ascii_alphabetic())
                    {
                        return Some(value.to_ascii_uppercase());
                    }
                }
            }
            search = &search[index + key.len()..];
        }
    }
    None
}

impl ProbeStrategy for ThinkingChainStrategy {
    fn name(&self) -> &'static str {
        "thinking_chain"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        let chain = &rules.probes.thinking_chain;
        // Thinking output is an Anthropic-messages feature. A non-Claude target
        // is never probed, and the evidence then reports an unsupported skip.
        if !rules
            .probes
            .activation
            .thinking_chain
            .enabled(request.mode, request.protocol)
            || is_non_claude(chain, &request.model)
        {
            return Ok(Vec::new());
        }
        let mut probe = build_probe(request, ProbeKind::ThinkingChain, &chain.prompt)?;
        probe.body["max_tokens"] = json!(chain.max_tokens);
        probe.body["thinking"] = json!({
            "type": chain.thinking_type,
            "budget_tokens": chain.budget_tokens,
        });
        probe.challenge_id = Some(THINKING_CHAIN_CHALLENGE.into());
        Ok(vec![probe])
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("thinking_chain", EvidenceCategory::Capability);
        };
        let evaluation = &rules.evaluation.thinking_chain;
        let chain = &rules.probes.thinking_chain;
        if !rules
            .probes
            .activation
            .thinking_chain
            .enabled(request.mode, request.protocol)
        {
            return unsupported(
                "thinking_chain",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &rules.evaluation.skipped_summary,
            );
        }
        if is_non_claude(chain, &request.model) {
            return skip(
                "thinking_chain",
                &evaluation.display_name,
                &evaluation.non_claude_summary,
                chain_details(chain, ChainWitness::absent()),
                EvidenceBasis::Unsupported,
            );
        }
        let witness = observations
            .first()
            .filter(|observation| (200..300).contains(&observation.status_code))
            .map(|observation| thinking_witness(chain, observation))
            .unwrap_or_else(ChainWitness::absent);
        let details = chain_details(chain, witness.clone());
        if !witness.summary_returned && !witness.redacted {
            return skip(
                "thinking_chain",
                &evaluation.display_name,
                &evaluation.unsupported_summary,
                details,
                EvidenceBasis::Unsupported,
            );
        }
        if !witness.summary_returned {
            // Only an opaque redacted block came back: the chain is there but
            // unreadable, so it is reported as an unknown rather than a pass.
            return skip(
                "thinking_chain",
                &evaluation.display_name,
                &evaluation.redacted_summary,
                details,
                EvidenceBasis::Unsupported,
            );
        }
        let outcome = if witness.signature_present {
            &evaluation.observed
        } else {
            &evaluation.signature_missing
        };
        result(
            "thinking_chain",
            &evaluation.display_name,
            EvidenceCategory::Capability,
            rules.evaluation.grade.status(outcome.score),
            outcome.severity,
            outcome.score,
            evaluation.weight,
            &outcome.summary,
            details,
            EvidenceBasis::Observed,
            Some(outcome.confidence),
        )
    }
}

fn is_non_claude(rules: &ThinkingChainProbeRules, model: &str) -> bool {
    let model = model.trim().to_ascii_lowercase();
    rules
        .non_claude_model_markers
        .iter()
        .any(|marker| model.contains(marker))
}

#[derive(Debug, Clone)]
struct ChainWitness {
    summary_returned: bool,
    full_text_returned: bool,
    signature_present: bool,
    redacted: bool,
    mode: String,
}

impl ChainWitness {
    fn absent() -> Self {
        Self {
            summary_returned: false,
            full_text_returned: false,
            signature_present: false,
            redacted: false,
            mode: String::new(),
        }
    }
}

fn thinking_witness(
    rules: &ThinkingChainProbeRules,
    observation: &ProbeObservation,
) -> ChainWitness {
    let mut text_chars = 0_usize;
    let mut signature_present = false;
    let mut redacted = false;
    if let Some(blocks) = observation
        .response
        .get("content")
        .and_then(Value::as_array)
    {
        for block in blocks {
            let block_type = block
                .get(&rules.content_type_key)
                .and_then(Value::as_str)
                .unwrap_or_default();
            if rules
                .redacted_block_types
                .iter()
                .any(|declared| declared == block_type)
            {
                redacted = true;
            }
            if !rules
                .thinking_block_types
                .iter()
                .any(|declared| declared == block_type)
            {
                continue;
            }
            let text = block
                .get(&rules.text_key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            text_chars = text_chars.max(text.chars().count());
            signature_present |= block
                .get(&rules.signature_key)
                .and_then(Value::as_str)
                .is_some_and(|signature| !signature.trim().is_empty());
        }
    }
    let summary_returned = text_chars > 0;
    let full_text_returned = text_chars >= rules.full_text_minimum_chars;
    let mode = if full_text_returned {
        &rules.modes.full_text
    } else if summary_returned {
        &rules.modes.summary
    } else if redacted {
        &rules.modes.redacted
    } else {
        &rules.modes.absent
    };
    ChainWitness {
        summary_returned,
        full_text_returned,
        signature_present,
        redacted,
        mode: mode.clone(),
    }
}

fn chain_details(
    rules: &ThinkingChainProbeRules,
    witness: ChainWitness,
) -> BTreeMap<String, Value> {
    let mode = if witness.mode.is_empty() {
        rules.modes.absent.clone()
    } else {
        witness.mode
    };
    BTreeMap::from([
        ("summaryReturned".into(), json!(witness.summary_returned)),
        ("fullTextReturned".into(), json!(witness.full_text_returned)),
        ("signaturePresent".into(), json!(witness.signature_present)),
        ("redacted".into(), json!(witness.redacted)),
        ("mode".into(), json!(mode)),
    ])
}

fn skip(
    name: &str,
    display_name: &str,
    summary: &str,
    details: BTreeMap<String, Value>,
    basis: EvidenceBasis,
) -> DetectorEvidence {
    result(
        name,
        display_name,
        EvidenceCategory::Capability,
        EvidenceStatus::Skip,
        EvidenceSeverity::Info,
        0.0,
        0.0,
        summary,
        details,
        basis,
        None,
    )
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
    use super::{ReasoningIqStrategy, ThinkingChainStrategy, final_integer};
    use crate::{
        EvidenceBasis, EvidenceStatus, ProbeKind, ProbeMode, ProbeObservation, ProbeRequest,
        ProbeStrategy, Protocol, UsageMetrics,
        rules::{CoreRules, ReasoningIqAnswerType, rules_from_request},
    };
    use serde_json::{Value, json};

    fn probe_request(mode: ProbeMode, protocol: Protocol, model: &str) -> ProbeRequest {
        ProbeRequest {
            base_url: "https://relay.example/v1".into(),
            api_key: "secret".into(),
            model: model.into(),
            protocol,
            mode,
            parameters: Default::default(),
            sections: Vec::new(),
        }
    }

    fn observation(
        kind: ProbeKind,
        challenge: &str,
        response: Value,
        text: &str,
    ) -> ProbeObservation {
        ProbeObservation {
            challenge_id: Some(challenge.into()),
            usage: UsageMetrics {
                input_tokens: 100,
                output_tokens: 40,
                ..UsageMetrics::default()
            },
            ..ProbeObservation::fixture(kind, 200, response, text)
        }
    }

    /// Answers every declared question correctly except the listed ones.
    fn iq_observations(rules: &CoreRules, wrong: &[&str]) -> Vec<ProbeObservation> {
        let iq = &rules.probes.reasoning_iq;
        iq.questions
            .iter()
            .map(|question| {
                let answer = if wrong.contains(&question.id.as_str()) {
                    match question.answer_type {
                        ReasoningIqAnswerType::Integer => "0".to_string(),
                        ReasoningIqAnswerType::String => "nowhere".to_string(),
                        ReasoningIqAnswerType::Choice => "Z".to_string(),
                    }
                } else {
                    question.expected.clone()
                };
                observation(
                    ProbeKind::ReasoningIq,
                    &format!("iq:{}", question.id),
                    json!({"stop_reason": "end_turn"}),
                    &answer,
                )
            })
            .collect()
    }

    #[test]
    fn reasoning_iq_scores_only_parsable_final_answers() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let rules = rules_from_request(&request).expect("shared rules");
        let total = rules.probes.reasoning_iq.questions.len();
        let observations = iq_observations(&rules, &["iq-1", "iq-4"]);
        let evidence = ReasoningIqStrategy.analyze(&request, &observations);
        let expected_score = ((total - 2) as f64 / total as f64 * 100.0).round();
        // Six of eight is below the rule-declared pass minimum, so the status
        // comes from the shared grade thresholds rather than a literal.
        assert_eq!(
            evidence.status,
            rules.evaluation.grade.status(expected_score)
        );
        assert_eq!(evidence.basis, EvidenceBasis::Observed);
        assert_eq!(
            evidence.details["scoringVersion"],
            json!(rules.probes.reasoning_iq.scoring_version)
        );
        assert_eq!(evidence.details["answered"], json!(total));
        assert_eq!(evidence.details["correct"], json!(total - 2));
        assert_eq!(evidence.details["total"], json!(total));
        assert_eq!(evidence.details["score"], json!(expected_score));
        assert_eq!(
            evidence.details["perQuestion"]
                .as_array()
                .expect("per-question detail")
                .iter()
                .filter(|item| item["correct"] == json!(false))
                .count(),
            2
        );
        assert_eq!(evidence.weight, rules.evaluation.reasoning_iq.weight);
    }

    #[test]
    fn reasoning_iq_never_scores_a_refusal_or_a_truncation_as_wrong() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let rules = rules_from_request(&request).expect("shared rules");
        let total = rules.probes.reasoning_iq.questions.len();
        let mut observations = iq_observations(&rules, &[]);
        // A refusal on the first question.
        observations[0].text = "I cannot help with that request.".into();
        // A truncated answer on the second one.
        observations[1].response = json!({"stop_reason": "max_tokens"});
        observations[1].text = "42".into();
        let evidence = ReasoningIqStrategy.analyze(&request, &observations);
        assert_eq!(evidence.details["answered"], json!(total - 2));
        assert_eq!(evidence.details["correct"], json!(total - 2));
        assert_eq!(evidence.details["score"], json!(100.0));
        assert_eq!(evidence.weight, rules.evaluation.reasoning_iq.weight);
    }

    #[test]
    fn reasoning_iq_downgrades_when_too_few_questions_were_answered() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let rules = rules_from_request(&request).expect("shared rules");
        let mut observations = iq_observations(&rules, &[]);
        for observation in observations.iter_mut().skip(2) {
            observation.text = "As an AI language model I would rather not.".into();
        }
        let evidence = ReasoningIqStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.weight, 0.0);
        assert_eq!(evidence.score, 0.0);
        assert_eq!(evidence.details["answered"], json!(2));
        assert_eq!(
            evidence.summary,
            rules.evaluation.reasoning_iq.insufficient_summary
        );
    }

    #[test]
    fn reasoning_iq_without_observations_is_unsupported() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let evidence = ReasoningIqStrategy.analyze(&request, &[]);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.weight, 0.0);
    }

    #[test]
    fn reasoning_iq_questions_carry_the_declared_answer_format() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let rules = rules_from_request(&request).expect("shared rules");
        let probes = ReasoningIqStrategy.build(&request).expect("iq probes");
        assert_eq!(probes.len(), rules.probes.reasoning_iq.questions.len());
        for (probe, question) in probes.iter().zip(&rules.probes.reasoning_iq.questions) {
            let expected_challenge = format!("iq:{}", question.id);
            assert_eq!(
                probe.challenge_id.as_deref(),
                Some(expected_challenge.as_str())
            );
            let prompt = probe.body["messages"][0]["content"]
                .as_str()
                .expect("anthropic prompt");
            assert!(prompt.contains(&question.prompt));
            assert!(
                prompt.contains(
                    rules
                        .probes
                        .reasoning_iq
                        .answer_formats
                        .for_type(question.answer_type)
                )
            );
        }
        // Quick mode is outside the declared activation window.
        assert!(
            ReasoningIqStrategy
                .build(&request_with_mode(ProbeMode::Quick))
                .expect("quick mode builds nothing")
                .is_empty()
        );
    }

    fn request_with_mode(mode: ProbeMode) -> ProbeRequest {
        probe_request(mode, Protocol::Anthropic, "claude-sonnet-4-6")
    }

    #[test]
    fn final_integer_ignores_working_and_glued_tokens() {
        assert_eq!(final_integer("17 + 25 = 42"), Some(42));
        assert_eq!(final_integer("There are 16 unit squares."), Some(16));
        assert_eq!(final_integer("gpt5 says 5th place"), None);
        assert_eq!(final_integer("about 390000.5 people"), Some(390_000));
        assert_eq!(final_integer("minus eight is -8"), Some(-8));
        assert_eq!(final_integer("no number here"), None);
    }

    #[test]
    fn thinking_chain_passes_only_when_text_and_signature_return() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let rules = rules_from_request(&request).expect("shared rules");
        let text = "x".repeat(rules.probes.thinking_chain.full_text_minimum_chars);
        let observations = vec![observation(
            ProbeKind::ThinkingChain,
            "thinking:chain",
            json!({"content": [
                {"type": "thinking", "thinking": text, "signature": "sig"},
                {"type": "text", "text": "final answer"}
            ]}),
            "final answer",
        )];
        let evidence = ThinkingChainStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.basis, EvidenceBasis::Observed);
        assert_eq!(evidence.details["summaryReturned"], json!(true));
        assert_eq!(evidence.details["fullTextReturned"], json!(true));
        assert_eq!(evidence.details["signaturePresent"], json!(true));
        assert_eq!(evidence.details["redacted"], json!(false));
        assert_eq!(
            evidence.details["mode"],
            json!(rules.probes.thinking_chain.modes.full_text)
        );
        assert_eq!(evidence.weight, rules.evaluation.thinking_chain.weight);
    }

    #[test]
    fn thinking_chain_warns_when_the_signature_is_missing() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let observations = vec![observation(
            ProbeKind::ThinkingChain,
            "thinking:chain",
            json!({"content": [{"type": "thinking", "thinking": "short summary"}]}),
            "answer",
        )];
        let evidence = ThinkingChainStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Warn);
        assert_eq!(evidence.details["signaturePresent"], json!(false));
        assert_eq!(evidence.details["fullTextReturned"], json!(false));
    }

    #[test]
    fn thinking_chain_is_unsupported_for_missing_fields_and_non_claude_targets() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let rules = rules_from_request(&request).expect("shared rules");
        let observations = vec![observation(
            ProbeKind::ThinkingChain,
            "thinking:chain",
            json!({"content": [{"type": "text", "text": "answer"}]}),
            "answer",
        )];
        let evidence = ThinkingChainStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.weight, 0.0);
        assert_eq!(evidence.details["summaryReturned"], json!(false));
        assert_eq!(
            evidence.details["mode"],
            json!(rules.probes.thinking_chain.modes.absent)
        );

        let non_claude = probe_request(ProbeMode::Standard, Protocol::Anthropic, "gpt-5.6-sol");
        assert!(
            ThinkingChainStrategy
                .build(&non_claude)
                .expect("no probe for a non-Claude target")
                .is_empty()
        );
        let evidence = ThinkingChainStrategy.analyze(&non_claude, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(
            evidence.summary,
            rules.evaluation.thinking_chain.non_claude_summary
        );

        // A non-anthropic protocol is outside the declared activation window.
        assert!(
            ThinkingChainStrategy
                .build(&probe_request(
                    ProbeMode::Standard,
                    Protocol::Openai,
                    "claude-sonnet-4-6"
                ))
                .expect("no probe for a non-anthropic protocol")
                .is_empty()
        );
    }

    #[test]
    fn thinking_chain_reports_an_opaque_redacted_block_as_unknown() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let rules = rules_from_request(&request).expect("shared rules");
        let observations = vec![observation(
            ProbeKind::ThinkingChain,
            "thinking:chain",
            json!({"content": [{"type": "redacted_thinking", "data": "opaque"}]}),
            "answer",
        )];
        let evidence = ThinkingChainStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.details["redacted"], json!(true));
        assert_eq!(
            evidence.details["mode"],
            json!(rules.probes.thinking_chain.modes.redacted)
        );
    }

    #[test]
    fn thinking_chain_declares_its_anthropic_only_limitation() {
        let request = probe_request(
            ProbeMode::Standard,
            Protocol::Anthropic,
            "claude-sonnet-4-6",
        );
        let rules = rules_from_request(&request).expect("shared rules");
        let chain = &rules.probes.thinking_chain;
        assert!(
            chain
                .limitations
                .iter()
                .any(|item| item.to_ascii_lowercase().contains("anthropic"))
        );
        // The probe carries the rule-declared thinking block and token budget.
        let probes = ThinkingChainStrategy.build(&request).expect("chain probe");
        assert_eq!(probes.len(), 1);
        assert_eq!(
            probes[0].body["thinking"]["type"],
            json!(chain.thinking_type)
        );
        assert_eq!(
            probes[0].body["thinking"]["budget_tokens"],
            json!(chain.budget_tokens)
        );
        assert_eq!(probes[0].body["max_tokens"], json!(chain.max_tokens));
    }
}
