use serde::Serialize;
use serde_json::{Value, json};
use wire_contracts::{
    CoreUiManifest, DetectionReport, PRESENTATION_SCHEMA_VERSION, PresentationContract,
    PresentationField, PresentationRow, PresentationSection, PresentationView, ProbeInputField,
    ProbeInputOption, ProbeRequestManifest, ReportPresentation, UI_MANIFEST_SCHEMA_VERSION,
};

use crate::rules::SectionRules;

const LAYOUTS: &[&str] = &["hero", "metric_grid", "key_value", "table"];
const FORMATS: &[&str] = &[
    "text",
    "number",
    "score",
    "status",
    "duration_ms",
    "rate",
    "token_count",
    "percentage",
    "code",
    "timestamp",
    "json",
];

pub fn core_ui_manifest(
    default_base_url: Option<&str>,
    sections: Option<&SectionRules>,
) -> CoreUiManifest {
    CoreUiManifest {
        schema_version: UI_MANIFEST_SCHEMA_VERSION,
        language: "en".into(),
        request: ProbeRequestManifest {
            submit_label: "Start detection".into(),
            fields: {
                let mut fields = vec![
                input_field(
                    "base-url",
                    "/baseUrl",
                    "Model API endpoint",
                    "url",
                    true,
                    false,
                    json!(default_base_url.unwrap_or_default()),
                    Some("https://relay.example/v1"),
                    Some("Enter the base URL for the model API you want to test."),
                    Vec::new(),
                ),
                input_field(
                    "api-key",
                    "/apiKey",
                    "API key",
                    "secret",
                    true,
                    true,
                    json!(""),
                    Some("sk-..."),
                    Some("Enter the API key required by this model API."),
                    Vec::new(),
                ),
                input_field(
                    "model",
                    "/model",
                    "Target model",
                    "text",
                    true,
                    false,
                    json!("claude-sonnet-4-6"),
                    Some("claude-sonnet-4-6"),
                    Some("Enter the model identifier accepted by the target API."),
                    Vec::new(),
                ),
                input_field(
                    "protocol",
                    "/protocol",
                    "API protocol",
                    "segmented",
                    true,
                    false,
                    json!("anthropic"),
                    None,
                    Some("Choose the protocol supported by the model API."),
                    vec![
                        option("anthropic", "Anthropic", None),
                        option("openai", "OpenAI", None),
                        option("gemini", "Gemini", None),
                    ],
                ),
                input_field(
                    "mode",
                    "/mode",
                    "Detection depth",
                    "segmented",
                    true,
                    false,
                    json!("standard"),
                    None,
                    Some("Choose the level of context, consistency, and capability analysis."),
                    vec![
                        option("quick", "Quick", Some("Essential checks with 2 context levels")),
                        option(
                            "standard",
                            "Standard",
                            Some("Balanced analysis with 3 context levels"),
                        ),
                        option(
                            "full",
                            "Full",
                            Some("Most comprehensive available analysis"),
                        ),
                    ],
                ),
                input_field(
                    "strict-attestation",
                    "/parameters/strictAttestation",
                    "Validate reasoning attestation",
                    "boolean",
                    false,
                    false,
                    json!(false),
                    None,
                    Some("Run an additional validation step for supported reasoning metadata."),
                    Vec::new(),
                ),
                input_field(
                    "juice-fingerprint-enabled",
                    "/parameters/juiceFingerprintEnabled",
                    "Reasoning budget fingerprint",
                    "boolean",
                    false,
                    false,
                    json!(true),
                    None,
                    Some("Run the GPT reasoning-budget fingerprint or the non-GPT XML Juice guard for Standard and Full detections. A positive non-GPT value is matched to calibrated GPT families; zero and text are normal. It is unavailable in Quick mode and cannot cryptographically prove model identity."),
                    Vec::new(),
                ),
                input_field(
                    "expected-provider",
                    "/parameters/expectedProvider",
                    "Expected model provider",
                    "text",
                    false,
                    false,
                    Value::Null,
                    Some("Anthropic"),
                    Some("Optionally name the provider you expect this model to represent."),
                    Vec::new(),
                ),
                input_field(
                    "knowledge-repository-enabled",
                    "/parameters/knowledgeRepositoryEnabled",
                    "Choose a knowledge pack automatically",
                    "boolean",
                    false,
                    false,
                    json!(true),
                    None,
                    Some("Use a compatible knowledge question set when one is available."),
                    Vec::new(),
                ),
                input_field(
                    "knowledge-pack-id",
                    "/parameters/knowledgePackId",
                    "Knowledge pack ID",
                    "text",
                    false,
                    false,
                    Value::Null,
                    Some("provider-model-knowledge"),
                    Some("Select a specific knowledge pack, or leave empty for the best available match."),
                    Vec::new(),
                ),
                input_field(
                    "knowledge-pack-channel",
                    "/parameters/knowledgePackChannel",
                    "Knowledge pack channel",
                    "text",
                    false,
                    false,
                    Value::Null,
                    Some("stable"),
                    Some("Choose a release channel, or leave empty to use the recommended channel."),
                    Vec::new(),
                ),
                input_field(
                    "knowledge-pack-version",
                    "/parameters/knowledgePackVersion",
                    "Knowledge pack version",
                    "text",
                    false,
                    false,
                    Value::Null,
                    Some("provider-model-YYYYMMDD"),
                    Some("Select a specific version, or leave empty to use the latest compatible release."),
                    Vec::new(),
                ),
                input_field(
                    "knowledge-challenges",
                    "/parameters/knowledgeChallenges",
                    "Knowledge challenges",
                    "json",
                    false,
                    false,
                    json!([]),
                    None,
                    Some("Optionally provide your own knowledge questions as a JSON array."),
                    Vec::new(),
                ),
            ];
            if let Some(sections) = sections {
                fields.push(section_selection_field(sections));
            }
                fields
            },
        },
        presentation: PresentationContract {
            schema_version: PRESENTATION_SCHEMA_VERSION,
            supported_layouts: LAYOUTS.iter().map(|value| (*value).into()).collect(),
            supported_formats: FORMATS.iter().map(|value| (*value).into()).collect(),
            unknown_hint_fallback: "Render unknown layouts as adaptive stacked sections and infer every field value from its JSON shape; reserve serialized JSON for an explicit raw developer view.".into(),
        },
    }
}

pub fn report_presentation(report: &DetectionReport) -> ReportPresentation {
    let mut overview = overview_view(report);
    if let Some(selection) = &report.section_selection {
        overview.sections.push(section(
            "section-selection",
            "Detection sections",
            Some(
                "This detection ran an explicit subset of the available detection sections, so its score is not directly comparable with a default detection."
                    .into(),
            ),
            "key_value",
            vec![
                field(
                    "selected-sections",
                    "Selected sections",
                    json!(selection.requested),
                    "json",
                    None,
                    None,
                    None,
                ),
                field(
                    "not-selected-sections",
                    "Not selected sections",
                    json!(selection.not_selected),
                    "json",
                    None,
                    None,
                    None,
                ),
            ],
            Vec::new(),
        ));
    }
    let mut views = vec![overview, evidence_view(report)];
    if report.context_audit.is_some() {
        views.push(context_view(report));
    }
    ReportPresentation {
        schema_version: PRESENTATION_SCHEMA_VERSION,
        language: "en".into(),
        views,
    }
}

fn overview_view(report: &DetectionReport) -> PresentationView {
    PresentationView {
        id: "overview".into(),
        label: "Overview".into(),
        description: Some("Core verdict, provenance, and performance for this detection.".into()),
        sections: vec![
            section(
                "verdict",
                "Detection result",
                Some(report.tier_message.clone()),
                "hero",
                vec![
                    field(
                        "score",
                        "Authenticity score",
                        json!(report.total_score),
                        "score",
                        None,
                        None,
                        Some(enum_string(report.verdict)),
                    ),
                    field(
                        "verdict",
                        "Verdict",
                        enum_value(report.verdict),
                        "status",
                        None,
                        None,
                        Some(enum_string(report.verdict)),
                    ),
                    field(
                        "tier",
                        "Evidence tier",
                        enum_value(report.tier),
                        "status",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "model",
                        "Target model",
                        json!(report.target.model),
                        "code",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "protocol",
                        "Protocol",
                        enum_value(report.target.protocol),
                        "code",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "mode",
                        "Detection mode",
                        enum_value(report.mode),
                        "code",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "created-at",
                        "Created at",
                        json!(report.created_at),
                        "timestamp",
                        None,
                        None,
                        None,
                    ),
                ],
                Vec::new(),
            ),
            section(
                "provenance",
                "Core provenance",
                Some(
                    "Exact Core release and contract revisions used to generate this report."
                        .into(),
                ),
                "key_value",
                vec![
                    field(
                        "engine",
                        "Engine",
                        json!(format!("{} v{}", report.core.name, report.core.version)),
                        "code",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "report-schema",
                        "Report schema",
                        json!(report.core.report_schema_version),
                        "number",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "capability-profile",
                        "Capability profile",
                        json!(report.core.capability_profile),
                        "code",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "rule-bundle",
                        "Rule bundle",
                        json!(format!("{} v{}", report.rules.id, report.rules.version)),
                        "code",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "rule-bundle-digest",
                        "Rule bundle digest",
                        json!(report.rules.digest),
                        "code",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "rule-source-revision",
                        "Rule source revision",
                        json!(report.rules.source_revision),
                        "code",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "rule-repository-release",
                        "Rule repository release",
                        json!(
                            report
                                .rules
                                .repository
                                .as_ref()
                                .map(|repository| &repository.release)
                        ),
                        "code",
                        None,
                        Some("The SanBiao Manifest release that selected this rule document."),
                        None,
                    ),
                    field(
                        "rule-manifest-source",
                        "Rule Manifest source",
                        json!(
                            report
                                .rules
                                .repository
                                .as_ref()
                                .map(|repository| repository.manifest_source)
                        ),
                        "status",
                        None,
                        Some(
                            "Remote repository or validated local fallback; no URL or path is exposed.",
                        ),
                        None,
                    ),
                    field(
                        "rule-document-source",
                        "Rule document source",
                        json!(
                            report
                                .rules
                                .repository
                                .as_ref()
                                .map(|repository| repository.document_source)
                        ),
                        "status",
                        None,
                        Some("The source used for the digest-verified Core rule document."),
                        None,
                    ),
                    field(
                        "capabilities",
                        "Declared capabilities",
                        json!(report.core.capabilities),
                        "json",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "report-id",
                        "Report ULID",
                        json!(report.id),
                        "code",
                        None,
                        None,
                        None,
                    ),
                ],
                Vec::new(),
            ),
            section(
                "performance",
                "Detection performance",
                None,
                "metric_grid",
                vec![
                    field(
                        "mean-latency",
                        "Mean latency",
                        json!(report.performance.average_latency_ms),
                        "duration_ms",
                        Some("ms"),
                        None,
                        None,
                    ),
                    field(
                        "ttft",
                        "Time to first token",
                        json!(report.performance.ttft_ms),
                        "duration_ms",
                        Some("ms"),
                        None,
                        None,
                    ),
                    field(
                        "generation-speed",
                        "Generation speed",
                        json!(report.performance.tokens_per_second),
                        "rate",
                        Some("tokens/s"),
                        None,
                        None,
                    ),
                    field(
                        "requests",
                        "Evidence requests",
                        json!(report.performance.request_count),
                        "number",
                        Some("runs"),
                        None,
                        None,
                    ),
                    field(
                        "input-tokens",
                        "Input tokens",
                        json!(report.performance.usage.input_tokens),
                        "token_count",
                        Some("tokens"),
                        None,
                        None,
                    ),
                    field(
                        "output-tokens",
                        "Output tokens",
                        json!(report.performance.usage.output_tokens),
                        "token_count",
                        Some("tokens"),
                        None,
                        None,
                    ),
                    field(
                        "cache-read-input",
                        "Cache-read input tokens",
                        json!(report.performance.usage.cache_read_input_tokens),
                        "token_count",
                        Some("tokens"),
                        None,
                        None,
                    ),
                    field(
                        "cache-created-input",
                        "Cache-created input tokens",
                        json!(report.performance.usage.cache_creation_input_tokens),
                        "token_count",
                        Some("tokens"),
                        None,
                        None,
                    ),
                    field(
                        "retries",
                        "Request retries",
                        json!(report.performance.retry_count),
                        "number",
                        Some("retries"),
                        None,
                        None,
                    ),
                    field(
                        "backoff-events",
                        "Backoff events",
                        json!(report.performance.backoff_count),
                        "number",
                        Some("events"),
                        None,
                        None,
                    ),
                ],
                Vec::new(),
            ),
            section(
                "coverage",
                "Evidence coverage",
                Some(
                    "Detectors that could not verify anything only lower coverage; they never fail a detection."
                        .into(),
                ),
                "key_value",
                vec![
                    field(
                        "coverage-ratio",
                        "Verified evidence coverage",
                        json!(report.coverage.ratio),
                        "percentage",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "verified-weight",
                        "Verified detector weight",
                        json!(report.coverage.verified_weight),
                        "number",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "applicable-weight",
                        "Applicable detector weight",
                        json!(report.coverage.applicable_weight),
                        "number",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "unverified-detectors",
                        "Unverified detectors",
                        json!(report.coverage.unverified_count),
                        "number",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "coverage-note",
                        "Coverage note",
                        json!(
                            "Unknown or errored detectors are excluded from the score and only reduce coverage."
                        ),
                        "text",
                        None,
                        None,
                        None,
                    ),
                ],
                Vec::new(),
            ),
        ],
    }
}

fn evidence_view(report: &DetectionReport) -> PresentationView {
    PresentationView {
        id: "evidence".into(),
        label: "Evidence".into(),
        description: Some("Detector output supplied by this Core release.".into()),
        sections: vec![section(
            "detectors",
            "Detector evidence",
            Some("Names and explanations are canonical English owned by TheStandard.".into()),
            "table",
            Vec::new(),
            report
                .evidence
                .iter()
                .map(|item| PresentationRow {
                    id: item.name.clone(),
                    status: Some(enum_string(item.status)),
                    fields: vec![
                        field(
                            "detector",
                            "Detector",
                            json!(item.display_name),
                            "text",
                            None,
                            None,
                            None,
                        ),
                        field(
                            "detector-id",
                            "Detector ID",
                            json!(item.name),
                            "code",
                            None,
                            None,
                            None,
                        ),
                        field(
                            "summary",
                            "Explanation",
                            json!(item.summary),
                            "text",
                            None,
                            None,
                            None,
                        ),
                        field(
                            "category",
                            "Category",
                            enum_value(item.category),
                            "status",
                            None,
                            None,
                            None,
                        ),
                        field(
                            "severity",
                            "Severity",
                            enum_value(item.severity),
                            "status",
                            None,
                            None,
                            Some(enum_string(item.severity)),
                        ),
                        field(
                            "basis",
                            "Evidence basis",
                            enum_value(item.basis),
                            "status",
                            None,
                            Some("Observed values come directly from transport data; inferred values are derived assessments; unsupported values were not measurable."),
                            Some(enum_string(item.basis)),
                        ),
                        field(
                            "confidence",
                            "Assessment confidence",
                            json!(item.confidence.map(|value| value * 100.0)),
                            "percentage",
                            Some("%"),
                            None,
                            None,
                        ),
                        field(
                            "weight",
                            "Weight",
                            json!(item.weight * 100.0),
                            "percentage",
                            Some("%"),
                            None,
                            None,
                        ),
                        field(
                            "score",
                            "Score",
                            json!(item.score),
                            "score",
                            None,
                            None,
                            Some(enum_string(item.status)),
                        ),
                        field(
                            "status",
                            "Status",
                            enum_value(item.status),
                            "status",
                            None,
                            None,
                            Some(enum_string(item.status)),
                        ),
                        field(
                            "details",
                            "Details",
                            json!(item.details),
                            "json",
                            None,
                            None,
                            None,
                        ),
                    ],
                })
                .collect(),
        )],
    }
}

fn context_view(report: &DetectionReport) -> PresentationView {
    let audit = report
        .context_audit
        .as_ref()
        .expect("context view requires audit data");
    PresentationView {
        id: "context".into(),
        label: "Context".into(),
        description: Some("Controlled context growth and upstream input-token evidence.".into()),
        sections: vec![
            section(
                "context-summary",
                "Context input audit",
                Some(if audit.controlled_context_confirmed {
                    "The final controlled context was returned exactly.".into()
                } else {
                    "The final controlled context requires review.".into()
                }),
                "metric_grid",
                vec![
                    field(
                        "sample-count",
                        "Samples",
                        json!(audit.sample_count),
                        "number",
                        None,
                        None,
                        None,
                    ),
                    field(
                        "fixed-overhead",
                        "Estimated fixed input overhead",
                        json!(audit.estimated_fixed_overhead_tokens),
                        "token_count",
                        Some("tokens"),
                        None,
                        None,
                    ),
                    field(
                        "fit-confidence",
                        "Growth fit confidence",
                        json!(audit.fit_confidence.map(|value| value * 100.0)),
                        "percentage",
                        Some("%"),
                        None,
                        None,
                    ),
                    field(
                        "overhead-assessment",
                        "Overhead assessment",
                        enum_value(audit.overhead_assessment),
                        "status",
                        None,
                        None,
                        Some(enum_string(audit.overhead_assessment)),
                    ),
                    field(
                        "final-echo",
                        "Final echo",
                        enum_value(audit.final_echo_status),
                        "status",
                        None,
                        None,
                        Some(enum_string(audit.final_echo_status)),
                    ),
                    field(
                        "controlled-context",
                        "Controlled context confirmed",
                        json!(audit.controlled_context_confirmed),
                        "status",
                        None,
                        None,
                        Some(if audit.controlled_context_confirmed {
                            "pass".into()
                        } else {
                            "warn".into()
                        }),
                    ),
                    field(
                        "independent-requests",
                        "Independent requests",
                        json!(audit.independent_requests),
                        "status",
                        None,
                        Some("Each gradient level was submitted as a fresh request with no prior assistant response or earlier level payload.".into()),
                        Some(if audit.independent_requests { "pass".into() } else { "fail".into() }),
                    ),
                    field(
                        "unique-request-fingerprints",
                        "Unique request fingerprints",
                        json!(audit.unique_request_fingerprints),
                        "status",
                        None,
                        None,
                        Some(if audit.unique_request_fingerprints { "pass".into() } else { "warn".into() }),
                    ),
                    field(
                        "cumulative-history-suspected",
                        "Cumulative history suspected",
                        json!(audit.cumulative_history_suspected),
                        "status",
                        None,
                        Some("This diagnostic compares successive upstream token-growth deltas with the independently measured visible payload growth.".into()),
                        Some(if audit.cumulative_history_suspected == Some(true) { "warn".into() } else { "pass".into() }),
                    ),
                    field(
                        "cache-hit-observed",
                        "Provider cache usage observed",
                        json!(audit.cache_hit_observed),
                        "status",
                        None,
                        None,
                        Some(if audit.cache_hit_observed { "info".into() } else { "pass".into() }),
                    ),
                    field(
                        "accounting-interpretation",
                        "Token accounting interpretation",
                        json!(audit.accounting_interpretation),
                        "code",
                        None,
                        None,
                        None,
                    ),
                ],
                Vec::new(),
            ),
            section(
                "context-samples",
                "Context token gradient",
                None,
                "table",
                Vec::new(),
                audit
                    .samples
                    .iter()
                    .map(|sample| PresentationRow {
                        id: format!("context-level-{}", sample.level),
                        status: None,
                        fields: vec![
                            field(
                                "level",
                                "Level",
                                json!(sample.level),
                                "number",
                                None,
                                None,
                                None,
                            ),
                            field(
                                "controlled-units",
                                "Controlled units",
                                json!(sample.controlled_units),
                                "number",
                                Some("units"),
                                None,
                                None,
                            ),
                            field(
                                "controlled-bytes",
                                "Controlled bytes",
                                json!(sample.controlled_bytes),
                                "number",
                                Some("bytes"),
                                None,
                                None,
                            ),
                            field(
                                "visible-input",
                                "Visible input estimate",
                                json!(sample.visible_input_token_estimate),
                                "token_count",
                                Some("tokens"),
                                None,
                                None,
                            ),
                            field(
                                "reported-input",
                                "Upstream reported input",
                                json!(sample.reported_input_tokens),
                                "token_count",
                                Some("tokens"),
                                None,
                                None,
                            ),
                            field(
                                "input-overhead",
                                "Estimated input overhead",
                                json!(sample.estimated_input_overhead_tokens),
                                "token_count",
                                Some("tokens"),
                                None,
                                None,
                            ),
                            field(
                                "exact-echo",
                                "Exact echo requested",
                                json!(sample.exact_echo_requested),
                                "status",
                                None,
                                None,
                                None,
                            ),
                            field(
                                "request-body-bytes",
                                "Request body bytes",
                                json!(sample.request_body_bytes),
                                "number",
                                Some("bytes"),
                                None,
                                None,
                            ),
                            field(
                                "message-count",
                                "Conversation messages",
                                json!(sample.message_count),
                                "number",
                                Some("messages"),
                                Some("A value of one proves the Core did not submit earlier gradient levels as chat history.".into()),
                                None,
                            ),
                            field(
                                "request-fingerprint",
                                "Request fingerprint",
                                json!(sample.request_fingerprint),
                                "code",
                                None,
                                None,
                                None,
                            ),
                            field(
                                "independent-request",
                                "Independent request",
                                json!(sample.independent_request),
                                "status",
                                None,
                                None,
                                Some(if sample.independent_request { "pass".into() } else { "fail".into() }),
                            ),
                            field(
                                "cache-read-input",
                                "Cache-read input",
                                json!(sample.cache_read_input_tokens),
                                "token_count",
                                Some("tokens"),
                                None,
                                None,
                            ),
                            field(
                                "cache-created-input",
                                "Cache-created input",
                                json!(sample.cache_creation_input_tokens),
                                "token_count",
                                Some("tokens"),
                                None,
                                None,
                            ),
                        ],
                    })
                    .collect(),
            ),
        ],
    }
}

fn section_selection_field(sections: &SectionRules) -> ProbeInputField {
    input_field(
        "sections",
        "/sections",
        "Detection sections",
        "sections",
        false,
        false,
        json!([]),
        None,
        Some(
            "Optionally run only the selected detection sections. Every section is enabled by default; reports from different selections are not directly comparable.",
        ),
        sections
            .items
            .iter()
            .map(|item| option(&item.id, &item.label, Some(item.description.as_str())))
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn input_field(
    id: &str,
    pointer: &str,
    label: &str,
    control: &str,
    required: bool,
    sensitive: bool,
    default_value: Value,
    placeholder: Option<&str>,
    description: Option<&str>,
    options: Vec<ProbeInputOption>,
) -> ProbeInputField {
    ProbeInputField {
        id: id.into(),
        json_pointer: pointer.into(),
        label: label.into(),
        description: description.map(Into::into),
        control: control.into(),
        required,
        sensitive,
        placeholder: placeholder.map(Into::into),
        default_value,
        options,
    }
}

fn option(value: &str, label: &str, description: Option<&str>) -> ProbeInputOption {
    ProbeInputOption {
        value: json!(value),
        label: label.into(),
        description: description.map(Into::into),
    }
}

fn section(
    id: &str,
    title: &str,
    description: Option<String>,
    layout: &str,
    fields: Vec<PresentationField>,
    rows: Vec<PresentationRow>,
) -> PresentationSection {
    PresentationSection {
        id: id.into(),
        title: title.into(),
        description,
        layout: layout.into(),
        fields,
        rows,
    }
}

#[allow(clippy::too_many_arguments)]
fn field(
    key: &str,
    label: &str,
    value: Value,
    format: &str,
    unit: Option<&str>,
    description: Option<&str>,
    status: Option<String>,
) -> PresentationField {
    PresentationField {
        key: key.into(),
        label: label.into(),
        value,
        format: format.into(),
        unit: unit.map(Into::into),
        description: description.map(Into::into),
        status,
    }
}

fn enum_value<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("presentation enums are serializable")
}

fn enum_string<T: Serialize>(value: T) -> String {
    enum_value(value).as_str().unwrap_or("unknown").into()
}

#[cfg(test)]
mod tests {
    use super::core_ui_manifest;
    use serde_json::json;

    #[test]
    fn manifest_is_english_extensible_and_secret_aware() {
        let manifest = core_ui_manifest(Some("https://demo.example.com"), None);
        assert_eq!(manifest.language, "en");
        assert_eq!(manifest.schema_version, 1);
        assert!(
            manifest
                .request
                .fields
                .iter()
                .all(|field| field.json_pointer.starts_with('/'))
        );
        let secret = manifest
            .request
            .fields
            .iter()
            .find(|field| field.json_pointer == "/apiKey")
            .expect("API key field");
        assert!(secret.sensitive);
        assert_eq!(secret.control, "secret");
        let juice = manifest
            .request
            .fields
            .iter()
            .find(|field| field.json_pointer == "/parameters/juiceFingerprintEnabled")
            .expect("juice option");
        assert_eq!(juice.default_value, serde_json::json!(true));
        assert!(!juice.sensitive);
        assert!(
            manifest
                .presentation
                .unknown_hint_fallback
                .contains("JSON shape")
        );
        assert!(
            manifest
                .presentation
                .unknown_hint_fallback
                .contains("raw developer view")
        );
    }

    #[test]
    fn manifest_declares_sections_from_the_shared_rule_document() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../SanBiao/rules/the-standard/stable.json");
        let bundle =
            crate::rules::CoreRuleBundle::from_document(&std::fs::read(path).unwrap(), None)
                .expect("shared rule document");
        let sections = bundle.rules.sections.as_ref().expect("declared sections");
        let manifest = core_ui_manifest(None, Some(sections));
        let field = manifest
            .request
            .fields
            .iter()
            .find(|field| field.json_pointer == "/sections")
            .expect("section selection field");
        assert_eq!(field.control, "sections");
        assert_eq!(field.default_value, json!([]));
        assert_eq!(field.options.len(), sections.items.len());
        assert!(!field.sensitive);
        assert!(!field.required);
        assert!(
            core_ui_manifest(None, None)
                .request
                .fields
                .iter()
                .all(|field| field.json_pointer != "/sections")
        );
    }
}
