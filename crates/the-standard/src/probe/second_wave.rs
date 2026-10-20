//! Second-wave evidence strategies.
//!
//! These detectors follow one shared rule: missing data degrades to an unknown
//! result with an `unsupported` basis and never becomes a failure. The rule
//! document owns the facts (prompts, anchors, pointers, thresholds); this
//! module only holds the algorithms.

use super::{OutboundProbe, ProbeStrategy, strategies::build_probe};
use crate::{
    CoreError, DetectorEvidence, EvidenceBasis, EvidenceCategory, EvidenceSeverity, EvidenceStatus,
    ProbeKind, ProbeObservation, ProbeRequest,
    rules::{
        KnowledgeCutoffAnchor, KnowledgeCutoffChoiceKind, KnowledgeCutoffProbeRules,
        rules_from_request,
    },
};
use chrono::NaiveDate;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub struct CacheReuseStrategy;
pub struct InjectionOverheadStrategy;
pub struct KnowledgeCutoffStrategy;
pub struct WebSearchStrategy;

const CACHE_PREFIX: &str = "cache:";
const INJECTION_BASELINE: &str = "injection:baseline";
const INJECTION_WRAPPED: &str = "injection:wrapped";
const CUTOFF_PREFIX: &str = "cutoff:";
const WEB_SEARCH_CHALLENGE: &str = "web:search";

impl ProbeStrategy for CacheReuseStrategy {
    fn name(&self) -> &'static str {
        "cache_reuse"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .cache
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        Ok(vec![cache_probe(request, &rules, 0)?])
    }

    fn follow_up(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        // A round only follows an answered round, and only inside an enabled
        // activation: a skipped strategy must not start probing through its
        // follow-up path.
        if observations.is_empty()
            || !rules
                .probes
                .activation
                .cache
                .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        let round = observations.len();
        if round >= rules.probes.cache.rounds {
            return Ok(Vec::new());
        }

        Ok(vec![cache_probe(request, &rules, round)?])
    }

    fn serial_follow_up(&self) -> bool {
        true
    }

    fn serial_follow_up_budget(&self, request: &ProbeRequest) -> usize {
        rules_from_request(request)
            .map(|rules| rules.probes.cache.rounds.saturating_sub(1))
            .unwrap_or(0)
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("cache_reuse", EvidenceCategory::Protocol);
        };
        let evaluation = &rules.evaluation.cache_reuse;
        let cache = &rules.probes.cache;
        if !rules
            .probes
            .activation
            .cache
            .enabled(request.mode, request.protocol)
            || observations.is_empty()
        {
            return unsupported(
                "cache_reuse",
                &evaluation.display_name,
                EvidenceCategory::Protocol,
                &rules.evaluation.skipped_summary,
            );
        }

        let mut read_tokens = Vec::new();
        let mut write_tokens = Vec::new();
        let mut input_tokens = Vec::new();
        let mut fields_reported = false;
        for observation in observations {
            let read = pointer_sum(&observation.response, &cache.read_pointers);
            let write = pointer_sum(&observation.response, &cache.write_pointers);
            fields_reported |= read.is_some() || write.is_some();
            read_tokens.push(read.unwrap_or(0));
            write_tokens.push(write.unwrap_or(0));
            input_tokens.push(observation.usage.input_tokens);
        }
        let rounds = observations.len();
        let total_read: u64 = read_tokens.iter().sum();
        let total_write: u64 = write_tokens.iter().sum();
        let total_input: u64 = input_tokens.iter().sum();
        let hit_rate = ratio(total_read, total_read + total_write + total_input);
        let last_round_cache_ratio = ratio(
            *read_tokens.last().unwrap_or(&0),
            read_tokens.last().unwrap_or(&0) + write_tokens.last().unwrap_or(&0),
        );
        let details = BTreeMap::from([
            ("rounds".into(), json!(rounds)),
            ("cacheReadTokens".into(), json!(read_tokens)),
            ("cacheWriteTokens".into(), json!(write_tokens)),
            ("hitRate".into(), json!(hit_rate)),
            ("lastRoundCacheRatio".into(), json!(last_round_cache_ratio)),
            ("fieldsMissing".into(), json!(!fields_reported)),
        ]);
        if !fields_reported {
            return result(
                "cache_reuse",
                &evaluation.display_name,
                EvidenceCategory::Protocol,
                EvidenceStatus::Skip,
                EvidenceSeverity::Info,
                0.0,
                0.0,
                &evaluation.unsupported_summary,
                details,
                EvidenceBasis::Unsupported,
                None,
            );
        }

        let reused = read_tokens.iter().skip(1).any(|value| *value > 0);
        let outcome = if reused {
            &evaluation.observed
        } else {
            &evaluation.absent
        };
        result(
            "cache_reuse",
            &evaluation.display_name,
            EvidenceCategory::Protocol,
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

fn cache_probe(
    request: &ProbeRequest,
    rules: &crate::rules::CoreRules,
    round: usize,
) -> Result<OutboundProbe, CoreError> {
    let cache = &rules.probes.cache;
    let prompt = format!(
        "{}\n{}",
        cache.prefix(),
        cache
            .round_instruction_template
            .replace("{round}", &(round + 1).to_string())
    );
    let mut probe = build_probe(request, ProbeKind::CacheReuse, &prompt)?;
    probe.body["max_tokens"] = json!(cache.max_tokens);
    probe.challenge_id = Some(format!("{CACHE_PREFIX}{round}"));
    Ok(probe)
}

impl ProbeStrategy for InjectionOverheadStrategy {
    fn name(&self) -> &'static str {
        "injection_overhead"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .injection
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        let injection = &rules.probes.injection;
        let baseline = injection_probe(
            request,
            &injection.baseline_prompt,
            INJECTION_BASELINE,
            injection.max_tokens,
        )?;
        let wrapped = injection_probe(
            request,
            &injection.wrapped_prompt,
            INJECTION_WRAPPED,
            injection.max_tokens,
        )?;
        Ok(vec![baseline, wrapped])
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("injection_overhead", EvidenceCategory::Protocol);
        };
        let evaluation = &rules.evaluation.injection_overhead;
        if !rules
            .probes
            .activation
            .injection
            .enabled(request.mode, request.protocol)
        {
            return unsupported(
                "injection_overhead",
                &evaluation.display_name,
                EvidenceCategory::Protocol,
                &rules.evaluation.skipped_summary,
            );
        }
        let baseline = observations
            .iter()
            .find(|item| item.challenge_id.as_deref() == Some(INJECTION_BASELINE));
        let wrapped = observations
            .iter()
            .find(|item| item.challenge_id.as_deref() == Some(INJECTION_WRAPPED));
        let (Some(baseline), Some(wrapped)) = (baseline, wrapped) else {
            return unsupported(
                "injection_overhead",
                &evaluation.display_name,
                EvidenceCategory::Protocol,
                &evaluation.unsupported_summary,
            );
        };
        if !usage_available(baseline) || !usage_available(wrapped) {
            return unsupported(
                "injection_overhead",
                &evaluation.display_name,
                EvidenceCategory::Protocol,
                &evaluation.unsupported_summary,
            );
        }
        let estimated = wrapped.usage.input_tokens as i64
            - baseline.usage.input_tokens as i64
            - rules.probes.injection.expected_extra_tokens;
        let outcome = if estimated <= evaluation.expected_overhead_maximum {
            &evaluation.expected
        } else if estimated <= evaluation.elevated_overhead_maximum {
            &evaluation.elevated
        } else {
            &evaluation.high
        };
        result(
            "injection_overhead",
            &evaluation.display_name,
            EvidenceCategory::Protocol,
            rules.evaluation.grade.status(outcome.score),
            outcome.severity,
            outcome.score,
            evaluation.weight,
            &outcome.summary,
            BTreeMap::from([
                (
                    "baselineInputTokens".into(),
                    json!(baseline.usage.input_tokens),
                ),
                (
                    "wrappedInputTokens".into(),
                    json!(wrapped.usage.input_tokens),
                ),
                ("estimatedOverheadTokens".into(), json!(estimated)),
                ("samples".into(), json!(2)),
            ]),
            EvidenceBasis::Inferred,
            Some(outcome.confidence),
        )
    }
}

fn injection_probe(
    request: &ProbeRequest,
    prompt: &str,
    challenge: &str,
    max_tokens: u32,
) -> Result<OutboundProbe, CoreError> {
    let mut probe = build_probe(request, ProbeKind::InjectionOverhead, prompt)?;
    probe.body["max_tokens"] = json!(max_tokens);
    probe.challenge_id = Some(challenge.into());
    Ok(probe)
}

fn usage_available(observation: &ProbeObservation) -> bool {
    (200..300).contains(&observation.status_code) && observation.usage.input_tokens > 0
}

impl ProbeStrategy for KnowledgeCutoffStrategy {
    fn name(&self) -> &'static str {
        "knowledge_cutoff"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .knowledge_cutoff
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        match next_cutoff_anchor(&rules.probes.knowledge_cutoff, &[]) {
            Some(anchor) => Ok(vec![cutoff_probe(request, &rules, anchor)?]),
            None => Ok(Vec::new()),
        }
    }

    fn follow_up(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if observations.is_empty()
            || !rules
                .probes
                .activation
                .knowledge_cutoff
                .enabled(request.mode, request.protocol)
            || observations.len() >= rules.probes.knowledge_cutoff.max_questions
        {
            return Ok(Vec::new());
        }
        match next_cutoff_anchor(&rules.probes.knowledge_cutoff, observations) {
            Some(anchor) => Ok(vec![cutoff_probe(request, &rules, anchor)?]),
            None => Ok(Vec::new()),
        }
    }

    fn serial_follow_up(&self) -> bool {
        true
    }

    fn serial_follow_up_budget(&self, request: &ProbeRequest) -> usize {
        rules_from_request(request)
            .map(|rules| {
                rules
                    .probes
                    .knowledge_cutoff
                    .max_questions
                    .saturating_sub(1)
            })
            .unwrap_or(0)
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("knowledge_cutoff", EvidenceCategory::Capability);
        };
        let evaluation = &rules.evaluation.knowledge_cutoff;
        let cutoff = &rules.probes.knowledge_cutoff;
        if !rules
            .probes
            .activation
            .knowledge_cutoff
            .enabled(request.mode, request.protocol)
        {
            return unsupported(
                "knowledge_cutoff",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &rules.evaluation.skipped_summary,
            );
        }
        if observations.is_empty() {
            return unsupported(
                "knowledge_cutoff",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &evaluation.unsupported_summary,
            );
        }

        let state = cutoff_state(cutoff, observations);
        let resolved = state.lower > state.from || state.upper < state.to;
        let reason = if state.invalidated {
            &evaluation.invalidated_summary
        } else if resolved {
            &evaluation.resolved_summary
        } else if state.questions >= cutoff.max_questions {
            &evaluation.exhausted_summary
        } else {
            &evaluation.unresolved_summary
        };
        let status = if state.invalidated || !resolved {
            EvidenceStatus::Skip
        } else {
            EvidenceStatus::Pass
        };
        let basis = if state.invalidated {
            EvidenceBasis::Unsupported
        } else if resolved {
            EvidenceBasis::Observed
        } else {
            EvidenceBasis::Inferred
        };
        result(
            "knowledge_cutoff",
            &evaluation.display_name,
            EvidenceCategory::Capability,
            status,
            EvidenceSeverity::Info,
            0.0,
            evaluation.weight,
            reason,
            BTreeMap::from([
                (
                    "lowerBound".into(),
                    json!((state.lower > state.from).then(|| state.lower.to_string())),
                ),
                (
                    "upperBound".into(),
                    json!((state.upper < state.to).then(|| state.upper.to_string())),
                ),
                ("questionCount".into(), json!(state.questions)),
                ("resolved".into(), json!(resolved && !state.invalidated)),
                ("invalidated".into(), json!(state.invalidated)),
                ("reason".into(), json!(reason)),
            ]),
            basis,
            Some(evaluation.confidence),
        )
    }
}

struct CutoffState {
    from: NaiveDate,
    to: NaiveDate,
    lower: NaiveDate,
    upper: NaiveDate,
    asked: BTreeSet<String>,
    questions: usize,
    invalidated: bool,
}

fn cutoff_state(
    rules: &KnowledgeCutoffProbeRules,
    observations: &[ProbeObservation],
) -> CutoffState {
    let from = NaiveDate::parse_from_str(&rules.window.from, "%Y-%m-%d")
        .expect("validated cutoff window start");
    let to = NaiveDate::parse_from_str(&rules.window.to, "%Y-%m-%d")
        .expect("validated cutoff window end");
    let mut state = CutoffState {
        from,
        to,
        lower: from,
        upper: to,
        asked: BTreeSet::new(),
        questions: 0,
        invalidated: false,
    };
    for observation in observations {
        let Some(id) = observation
            .challenge_id
            .as_deref()
            .and_then(|value| value.strip_prefix(CUTOFF_PREFIX))
        else {
            continue;
        };
        let Some(anchor) = rules.anchors.iter().find(|anchor| anchor.id == id) else {
            continue;
        };
        state.questions += 1;
        state.asked.insert(anchor.id.clone());
        if cutoff_invalidated(rules, observation) {
            state.invalidated = true;
            continue;
        }
        let Some(letter) = parse_cutoff_letter(&observation.text) else {
            continue;
        };
        let Some(choice) = anchor.choices.iter().find(|choice| choice.letter == letter) else {
            continue;
        };
        let Some(date) = anchor.parsed_date() else {
            continue;
        };
        match choice.kind {
            KnowledgeCutoffChoiceKind::Known => {
                if date > state.lower {
                    state.lower = date;
                }
            }
            KnowledgeCutoffChoiceKind::Unknown => {
                if date < state.upper {
                    state.upper = date;
                }
            }
            KnowledgeCutoffChoiceKind::Wrong => {}
        }
    }
    state
}

/// Picks the median anchor strictly inside the current window: a serial binary
/// search over rule-declared dated events.
fn next_cutoff_anchor(
    rules: &KnowledgeCutoffProbeRules,
    observations: &[ProbeObservation],
) -> Option<KnowledgeCutoffAnchor> {
    let state = cutoff_state(rules, observations);
    if state.invalidated || state.questions >= rules.max_questions {
        return None;
    }
    let mut candidates: Vec<&KnowledgeCutoffAnchor> = rules
        .anchors
        .iter()
        .filter(|anchor| !state.asked.contains(&anchor.id))
        .filter(|anchor| {
            anchor
                .parsed_date()
                .is_some_and(|date| date > state.lower && date < state.upper)
        })
        .collect();
    candidates.sort_by_key(|anchor| (anchor.parsed_date(), anchor.id.clone()));
    if candidates.is_empty() {
        return None;
    }
    Some(candidates[candidates.len() / 2].clone())
}

fn cutoff_probe(
    request: &ProbeRequest,
    rules: &crate::rules::CoreRules,
    anchor: KnowledgeCutoffAnchor,
) -> Result<OutboundProbe, CoreError> {
    let cutoff = &rules.probes.knowledge_cutoff;
    let choices = anchor
        .choices
        .iter()
        .map(|choice| {
            cutoff
                .choice_line_template
                .replace("{letter}", &choice.letter)
                .replace("{text}", &choice.text)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let prompt = cutoff
        .prompt_template
        .replace("{question}", &anchor.question)
        .replace("{choices}", &choices);
    let mut probe = build_probe(request, ProbeKind::KnowledgeCutoff, &prompt)?;
    probe.body["max_tokens"] = json!(cutoff.max_tokens);
    probe.challenge_id = Some(format!("{CUTOFF_PREFIX}{}", anchor.id));
    Ok(probe)
}

fn cutoff_invalidated(rules: &KnowledgeCutoffProbeRules, observation: &ProbeObservation) -> bool {
    let text = observation.text.to_ascii_lowercase();
    rules
        .invalidated_markers
        .iter()
        .any(|marker| text.contains(&marker.to_ascii_lowercase()))
}

/// Extracts the single-letter answer from `{"choice":"A"}`-style output.
fn parse_cutoff_letter(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.len() == 1
        && trimmed
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        return Some(trimmed.to_ascii_uppercase());
    }
    let mut search = text;
    while let Some(index) = search.find("\"choice\"") {
        let after = &search[index + "\"choice\"".len()..];
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
        search = &search[index + "\"choice\"".len()..];
    }
    None
}

impl ProbeStrategy for WebSearchStrategy {
    fn name(&self) -> &'static str {
        "web_search"
    }

    fn build(&self, request: &ProbeRequest) -> Result<Vec<OutboundProbe>, CoreError> {
        let Some(rules) = rules_from_request(request) else {
            return Ok(Vec::new());
        };
        if !rules
            .probes
            .activation
            .web_search
            .enabled(request.mode, request.protocol)
        {
            return Ok(Vec::new());
        }
        let Some(protocol_rule) = rules.probes.web_search.protocol_rule(request.protocol) else {
            return Ok(Vec::new());
        };
        let mut probe = build_probe(
            request,
            ProbeKind::WebSearch,
            &rules.probes.web_search.prompt,
        )?;
        probe.body["max_tokens"] = json!(rules.probes.web_search.max_tokens);
        for (key, value) in &protocol_rule.body_patch {
            probe.body[key.clone()] = value.clone();
        }
        probe.challenge_id = Some(WEB_SEARCH_CHALLENGE.into());
        Ok(vec![probe])
    }

    fn analyze(
        &self,
        request: &ProbeRequest,
        observations: &[ProbeObservation],
    ) -> DetectorEvidence {
        let Some(rules) = rules_from_request(request) else {
            return unavailable("web_search", EvidenceCategory::Capability);
        };
        let evaluation = &rules.evaluation.web_search;
        if !rules
            .probes
            .activation
            .web_search
            .enabled(request.mode, request.protocol)
        {
            return unsupported(
                "web_search",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                &rules.evaluation.skipped_summary,
            );
        }
        let mode = rules
            .probes
            .web_search
            .protocol_rule(request.protocol)
            .map(|entry| entry.mode.clone())
            .unwrap_or_default();
        let mut sources = BTreeSet::new();
        let mut executed = false;
        for observation in observations {
            collect_source_urls(
                &observation.response,
                &rules.probes.web_search.source_url_keys,
                &mut sources,
            );
            let serialized = observation.response.to_string().to_ascii_lowercase();
            executed |= rules
                .probes
                .web_search
                .execution_markers
                .iter()
                .any(|marker| serialized.contains(&marker.to_ascii_lowercase()));
        }
        let executed = executed || !sources.is_empty();
        let sources = sources.into_iter().collect::<Vec<_>>();
        let details = BTreeMap::from([
            ("executed".into(), json!(executed)),
            ("sourceCount".into(), json!(sources.len())),
            ("sources".into(), json!(sources)),
            ("mode".into(), json!(mode)),
        ]);
        if !executed || sources.is_empty() {
            return result(
                "web_search",
                &evaluation.display_name,
                EvidenceCategory::Capability,
                EvidenceStatus::Skip,
                EvidenceSeverity::Info,
                0.0,
                0.0,
                &evaluation.unsupported_summary,
                details,
                EvidenceBasis::Unsupported,
                None,
            );
        }
        result(
            "web_search",
            &evaluation.display_name,
            EvidenceCategory::Capability,
            rules.evaluation.grade.status(evaluation.observed.score),
            evaluation.observed.severity,
            evaluation.observed.score,
            evaluation.weight,
            &evaluation.observed.summary,
            details,
            EvidenceBasis::Observed,
            Some(evaluation.observed.confidence),
        )
    }
}

fn collect_source_urls(value: &Value, keys: &[String], out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(url) = map.get(key).and_then(Value::as_str)
                    && !url.trim().is_empty()
                {
                    out.insert(url.to_string());
                }
            }
            for item in map.values() {
                collect_source_urls(item, keys, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_source_urls(item, keys, out);
            }
        }
        _ => {}
    }
}

fn pointer_sum(value: &Value, pointers: &[String]) -> Option<u64> {
    let mut total = 0_u64;
    let mut found = false;
    for pointer in pointers {
        if let Some(number) = value.pointer(pointer).and_then(Value::as_u64) {
            found = true;
            total += number;
        }
    }
    found.then_some(total)
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    round4(numerator as f64 / denominator as f64)
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
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
        CacheReuseStrategy, InjectionOverheadStrategy, KnowledgeCutoffStrategy, WebSearchStrategy,
    };
    use crate::{
        EvidenceBasis, EvidenceStatus, ProbeKind, ProbeMode, ProbeObservation, ProbeRequest,
        ProbeStrategy, Protocol, UsageMetrics,
        rules::{
            CoreRules, KnowledgeCutoffAnchor, KnowledgeCutoffChoice, KnowledgeCutoffChoiceKind,
            KnowledgeCutoffWindow, rules_from_request,
        },
    };
    use serde_json::{Value, json};

    fn request(mode: ProbeMode, protocol: Protocol) -> ProbeRequest {
        ProbeRequest {
            base_url: "https://relay.example/v1".into(),
            api_key: "secret".into(),
            model: "claude-sonnet-4-6".into(),
            protocol,
            mode,
            parameters: Default::default(),
            sections: Vec::new(),
        }
    }

    fn observation(challenge: &str, response: Value, text: &str) -> ProbeObservation {
        ProbeObservation {
            challenge_id: Some(challenge.into()),
            usage: UsageMetrics {
                input_tokens: 100,
                output_tokens: 5,
                ..UsageMetrics::default()
            },
            ..ProbeObservation::fixture(ProbeKind::CacheReuse, 200, response, text)
        }
    }

    #[test]
    fn cache_reuse_without_usage_fields_degrades_to_an_unsupported_skip() {
        let request = request(ProbeMode::Standard, Protocol::Anthropic);
        let observations = vec![
            observation("cache:0", json!({"usage": {}}), "OK"),
            observation("cache:1", json!({"usage": {}}), "OK"),
        ];
        let evidence = CacheReuseStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.weight, 0.0);
        assert_eq!(evidence.details["fieldsMissing"], json!(true));
        assert_eq!(evidence.details["rounds"], json!(2));
    }

    #[test]
    fn cache_reuse_recognizes_a_rewritten_prefix_only_when_usage_is_reported() {
        let request = request(ProbeMode::Standard, Protocol::Anthropic);
        let observations = vec![
            observation(
                "cache:0",
                json!({"usage": {"cache_creation_input_tokens": 512}}),
                "OK",
            ),
            observation(
                "cache:1",
                json!({"usage": {"cache_read_input_tokens": 512, "cache_creation_input_tokens": 0}}),
                "OK",
            ),
        ];
        let evidence = CacheReuseStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.basis, EvidenceBasis::Observed);
        assert_eq!(evidence.details["fieldsMissing"], json!(false));
        assert_eq!(evidence.details["cacheReadTokens"], json!([0, 512]));
        assert_eq!(evidence.details["cacheWriteTokens"], json!([512, 0]));
        assert_eq!(evidence.details["lastRoundCacheRatio"], json!(1.0));
        assert_eq!(evidence.details["hitRate"], json!(0.4183));
    }

    #[test]
    fn injection_overhead_without_usage_is_skipped() {
        let request = request(ProbeMode::Standard, Protocol::Openai);
        let observations = vec![
            ProbeObservation {
                usage: UsageMetrics::default(),
                ..observation("injection:baseline", json!({}), "OK")
            },
            observation("injection:wrapped", json!({}), "OK"),
        ];
        let evidence = InjectionOverheadStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.weight, 0.0);
    }

    #[test]
    fn injection_overhead_uses_the_two_reported_samples() {
        let request = request(ProbeMode::Standard, Protocol::Openai);
        let expected_extra = rules_from_request(&request)
            .expect("shared rules")
            .probes
            .injection
            .expected_extra_tokens;
        let observations = vec![
            observation("injection:baseline", json!({}), "OK"),
            ProbeObservation {
                usage: UsageMetrics {
                    input_tokens: 100 + expected_extra as u64,
                    ..UsageMetrics::default()
                },
                ..observation("injection:wrapped", json!({}), "OK")
            },
        ];
        let evidence = InjectionOverheadStrategy.analyze(&request, &observations);
        assert_eq!(evidence.basis, EvidenceBasis::Inferred);
        assert_eq!(evidence.details["samples"], json!(2));
        assert_eq!(evidence.details["estimatedOverheadTokens"], json!(0));
        assert_eq!(evidence.status, EvidenceStatus::Pass);
    }

    #[test]
    fn knowledge_cutoff_without_a_parsable_answer_stays_unresolved() {
        let request = request(ProbeMode::Full, Protocol::Anthropic);
        let observations = vec![observation(
            "cutoff:trump-inauguration",
            json!({}),
            "I cannot answer that.",
        )];
        let evidence = KnowledgeCutoffStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.details["resolved"], json!(false));
        assert_eq!(evidence.details["invalidated"], json!(false));
        assert_eq!(evidence.details["questionCount"], json!(1));
        assert_eq!(evidence.weight, 0.0);
    }

    #[test]
    fn knowledge_cutoff_is_invalidated_by_web_or_tool_use() {
        let request = request(ProbeMode::Full, Protocol::Anthropic);
        let observations = vec![observation(
            "cutoff:trump-inauguration",
            json!({}),
            "I used a tool, so {\"choice\":\"A\"}.",
        )];
        let evidence = KnowledgeCutoffStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.details["invalidated"], json!(true));
        assert_eq!(evidence.details["resolved"], json!(false));
        assert_eq!(evidence.weight, 0.0);
    }

    fn fixture_anchor(index: usize) -> KnowledgeCutoffAnchor {
        let choices = [
            (
                "A",
                "Yes, it already happened.",
                KnowledgeCutoffChoiceKind::Known,
            ),
            (
                "B",
                "Only scheduled or unsure.",
                KnowledgeCutoffChoiceKind::Unknown,
            ),
            (
                "C",
                "No, it did not happen.",
                KnowledgeCutoffChoiceKind::Wrong,
            ),
            (
                "D",
                "It happened before 2025.",
                KnowledgeCutoffChoiceKind::Wrong,
            ),
        ]
        .into_iter()
        .map(|(letter, text, kind)| KnowledgeCutoffChoice {
            letter: letter.into(),
            text: text.into(),
            kind,
        })
        .collect();
        KnowledgeCutoffAnchor {
            id: format!("anchor-{index}"),
            date: format!("2025-{index:02}-10"),
            event: format!("Fixture event {index}"),
            question: format!("Has fixture event {index} already happened?"),
            choices,
        }
    }

    fn fixture_request() -> ProbeRequest {
        let mut request = request(ProbeMode::Full, Protocol::Anthropic);
        let mut rules: CoreRules = rules_from_request(&request).expect("shared rules");
        rules.probes.knowledge_cutoff.window = KnowledgeCutoffWindow {
            from: "2025-01-01".into(),
            to: "2025-12-31".into(),
        };
        rules.probes.knowledge_cutoff.anchors = (1..=8).map(fixture_anchor).collect();
        request.parameters.insert(
            "_theStandardRuleBundle".into(),
            serde_json::to_value(&rules).expect("rules serialize"),
        );
        request
    }

    #[test]
    fn knowledge_cutoff_binary_search_narrows_a_fixture_window() {
        let request = fixture_request();
        let strategy = KnowledgeCutoffStrategy;
        let mut probes = strategy.build(&request).expect("first question");
        let mut observations = Vec::new();
        let mut asked = Vec::new();
        while let Some(probe) = probes.first() {
            let challenge = probe.challenge_id.clone().expect("cutoff challenge");
            asked.push(
                challenge
                    .strip_prefix("cutoff:")
                    .expect("cutoff prefix")
                    .to_string(),
            );
            observations.push(observation(&challenge, json!({}), "{\"choice\":\"A\"}"));
            assert!(asked.len() <= 10, "binary search must stay bounded");
            probes = strategy
                .follow_up(&request, &observations)
                .expect("next question");
        }
        // Median of eight anchors, then the median of the upper half, then the
        // last remaining anchor: a fixed answer sequence gives a fixed interval.
        assert_eq!(asked, vec!["anchor-5", "anchor-7", "anchor-8"]);
        let evidence = strategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.details["lowerBound"], json!("2025-08-10"));
        assert_eq!(evidence.details["upperBound"], Value::Null);
        assert_eq!(evidence.details["questionCount"], json!(3));
        assert_eq!(evidence.details["resolved"], json!(true));
        assert_eq!(evidence.weight, 0.0);
    }

    #[test]
    fn web_search_without_execution_is_unsupported() {
        let request = request(ProbeMode::Standard, Protocol::Anthropic);
        let observations = vec![observation(
            "web:search",
            json!({"content": []}),
            "no search",
        )];
        let evidence = WebSearchStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Skip);
        assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
        assert_eq!(evidence.weight, 0.0);
        assert_eq!(evidence.details["executed"], json!(false));
        assert_eq!(evidence.details["sourceCount"], json!(0));
    }

    #[test]
    fn web_search_requires_source_urls_and_reports_the_declared_mode() {
        let request = request(ProbeMode::Standard, Protocol::Anthropic);
        let probes = WebSearchStrategy.build(&request).expect("web search probe");
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].body["tools"][0]["name"], json!("web_search"));
        let observations = vec![observation(
            "web:search",
            json!({"content": [{"type": "web_search_tool_result", "citations": [
                {"url": "https://example.com/population"}
            ]}]}),
            "Iceland has about 390000 people.",
        )];
        let evidence = WebSearchStrategy.analyze(&request, &observations);
        assert_eq!(evidence.status, EvidenceStatus::Pass);
        assert_eq!(evidence.basis, EvidenceBasis::Observed);
        assert_eq!(evidence.details["executed"], json!(true));
        assert_eq!(evidence.details["sourceCount"], json!(1));
        assert_eq!(
            evidence.details["sources"],
            json!(["https://example.com/population"])
        );
        assert_eq!(evidence.details["mode"], json!("native_tool"));
    }

    #[test]
    fn web_search_builds_the_protocol_shape_declared_by_the_rules() {
        let openai = request(ProbeMode::Standard, Protocol::Openai);
        let probes = WebSearchStrategy.build(&openai).expect("web search probe");
        assert_eq!(probes.len(), 1);
        assert_eq!(
            probes[0].body["tools"][0]["function"]["name"],
            json!("web_search")
        );
        // A protocol with no declared shape never guesses one.
        let rules = WebSearchStrategy
            .build(&request(ProbeMode::Quick, Protocol::Anthropic))
            .expect("quick mode builds nothing");
        assert!(rules.is_empty());
    }
}
