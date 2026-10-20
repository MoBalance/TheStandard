# 法仪（TheStandard）

法仪是独立的模型探测与证据衡量引擎，英文代号为 `TheStandard`。它拥有探针算法以及每个
引擎输入和结果的规范英文说明。客户端在运行时发现当前交互契约，
submits a JSON request assembled from that contract, and renders the semantic presentation
included in the report.

## 名称出处

“法仪”取自墨子的标准观：凡事必须有可以共同遵循的“法”作为衡量依据，否则无法判断是非、
检验成败。墨子以规矩衡量方圆，以法仪衡量言行；TheStandard 将这一思想落实为可复核的请求、
观察、规则、摘要和证据边界，而不是依赖模型或供应方的单方面声明。

This document is the normative contract guide for services, CLIs, product frontends, and
independently deployed clients that integrate TheStandard.

## Project repositories

- TheStandard source: <https://github.com/MoBalance/TheStandard>
- SanBiao rule and knowledge repository: <https://github.com/MoBalance/SanBiao>
- GhostReveal standalone detection console: <https://github.com/MoBalance/GhostReveal>

TheStandard loads its immutable rule snapshot from SanBiao and exposes the same contract to
GhostReveal and other independent clients. These repositories are versioned and deployable
separately; the links above are the canonical project locations.

## Contract boundary

Core returns semantic data, never HTML, CSS, framework components, templates, scripts, or other
executable UI. A frontend continues to own branding, accessibility, responsive behavior, local
business navigation, and the implementation of semantic layouts. It must not own detector-specific
labels, verdict explanations, evidence descriptions, or fixed report sections.

Wire types live in the shared contract crate. The typed `DetectionReport` remains the source for storage,
ranking, exports, and machine processing. `DetectionReport.presentation` is Core's human-readable
projection of that same report; clients must not recompute detector meaning from presentation data.

## Current version matrix

| Core release | Manifest schema | Report schema | Presentation schema | Capability profile |
| --- | ---: | ---: | ---: | --- |
| `0.1.1015` | `1` | `7` | `1` | `adaptive-evidence-v17` |

TheStandard begins at `0.1.1000`. Every released iteration increments the SemVer patch component by
at least one: `0.1.1000` → `0.1.1001` → `0.1.1002` → `0.1.1003` → `0.1.1004` → `0.1.1005` → `0.1.1006` → `0.1.1007` → `0.1.1008` → `0.1.1009` → `0.1.1010` → `0.1.1011` → `0.1.1012` → `0.1.1013` → `0.1.1014` → `0.1.1015`. A release must never reuse or move backward to an
earlier number, including documentation-only and rule-adapter changes that alter the published
artifact.

These identifiers have different purposes:

- `core.version` identifies the exact algorithm implementation release.
- `core.reportSchemaVersion` identifies the typed report envelope.
- `core.capabilityProfile` identifies probe/scoring behavior. Scores from different profiles are
  not automatically comparable.
- `rules.id`, `rules.version`, and `rules.digest` identify the exact external rule snapshot used by
  the algorithms. Reports without a validated rule snapshot are not produced.
- `manifest.schemaVersion` versions request discovery.
- `presentation.schemaVersion` versions semantic report presentation.

## Project layout and service configuration

```text
TheStandard/
├── Cargo.toml
├── README.md
├── the-standard.toml
├── crates/
│   ├── the-standard-contracts/
│   ├── the-standard/
│   └── the-standard-service/
└── deployments/
    ├── docker/
    └── kubernetes/
```

The library is deterministic with respect to caller-supplied configuration and never reads files or
environment variables. `the-standard-service` is the network adapter. It reads `the-standard.toml`
by default; `THE_STANDARD_CONFIG_FILE` selects another file. The TOML file owns non-sensitive
service settings and the SanBiao source:

```toml
[service]
host = "0.0.0.0"
port = 8081
require_auth = false
allow_private_targets = false
allowed_origins = ["http://localhost:5174"]
demo_targets = ["https://demo.example.com"]
max_inflight_detections = 8
max_request_body_bytes = 2097152
shutdown_grace_seconds = 30
target_dns_timeout_seconds = 5

[engine]
request_timeout_seconds = 30
max_retries = 3
retry_backoff_milliseconds = 1000
max_concurrent = 3
quick_timeout_seconds = 60
standard_timeout_seconds = 120
full_timeout_seconds = 180

[transport]
max_response_bytes = 4194304
max_stream_bytes = 4194304
max_stream_events = 10000

[rules]
manifest_url = "https://raw.githubusercontent.com/MoBalance/SanBiao/main/manifest.json"
fallback_directory = "../SanBiao"
allow_insecure_http = false
refresh_seconds = 300
request_timeout_seconds = 5
max_manifest_bytes = 262144
max_document_bytes = 1048576
```

`demo_targets` contains exact HTTP(S) origins that use the deterministic `DemoTransport`. No domain
is compiled into the service or library. The service passes the first configured origin into the
runtime UI Manifest as `/baseUrl`'s default; an empty list produces an empty default. Production
deployments must keep this list empty unless they intentionally operate a public deterministic demo.

Every non-secret TOML setting can be overridden by its uppercase `THE_STANDARD_*` environment
variable. Engine overrides use `THE_STANDARD_ENGINE_...`, transport overrides use
`THE_STANDARD_TRANSPORT_...`, and repository overrides use `THE_STANDARD_RULE_...`; the optional
`fallback_directory` (or `THE_STANDARD_RULE_FALLBACK_DIRECTORY`) is used only when the remote Manifest
is unavailable and is still checked against its local digest. `.env.example` is the complete deployment
reference. The bearer token is deliberately environment-only through
`THE_STANDARD_AUTH_TOKEN`; it must not be placed in TOML.

Service admission and lifecycle settings use `THE_STANDARD_SERVICE_MAX_INFLIGHT_DETECTIONS`,
`THE_STANDARD_SERVICE_MAX_REQUEST_BODY_BYTES`, and
`THE_STANDARD_SERVICE_SHUTDOWN_GRACE_SECONDS`. Target hostname resolution uses
`THE_STANDARD_SERVICE_TARGET_DNS_TIMEOUT_SECONDS` (1–30 seconds, default 5). Detection requests beyond the configured in-flight
limit fail immediately with HTTP 429 and `Retry-After: 1`; they are not queued indefinitely.
Every HTTP response includes a server-generated ULID in `x-request-id`. Logs contain only that ID,
method, route, status, and latency; credentials and request/response bodies are never logged.

Outbound target safety is enabled by default. Before a live detection, the service resolves the
target hostname with the bounded DNS timeout and rejects the target when any answer is loopback,
private, link-local, unspecified, multicast, documentation-only, benchmarking, carrier-grade NAT,
or another non-public address. The validated address set is pinned to the detection HTTP client,
which prevents a DNS rebinding between validation and the request. HTTP redirects are disabled and
returned as ordinary upstream status observations, so a redirect cannot move a request into a
restricted network. Set `allow_private_targets = true` or
`THE_STANDARD_ALLOW_PRIVATE_TARGETS=true` only for a deliberately trusted local deployment; this
explicit mode bypasses the DNS restriction and is unsuitable for a public service.

Transport response memory is bounded independently for ordinary and streaming responses. The
default `max_response_bytes = 4194304` caps transport-delivered non-streaming body bytes at 4 MiB; the service reads
chunks incrementally and stops before buffering a byte beyond that ceiling. Configure it through
`THE_STANDARD_TRANSPORT_MAX_RESPONSE_BYTES` within the validated 64 KiB–64 MiB range. The existing
`max_stream_bytes` and `max_stream_events` limits continue to govern SSE responses. Limit errors are
reported generically and never include response bodies or request credentials.

The service rejects invalid settings during startup and `--check-config`. Timeouts and concurrency
must be positive, except `max_retries = 0` explicitly disables retries and permits a zero backoff.
Probe timeouts must satisfy `request <= quick <= standard <= full`. Rule refresh must be between 30
seconds and 24 hours. Ordinary response, stream, and repository byte/event limits have finite safety ceilings; invalid
values are never silently clamped. These checks prevent a typo from creating unbounded memory use or
turning an upstream timeout into a permanently occupied worker.

Run locally with `cargo run -p the-standard-service`, or use `docker compose up -d --build`.

## Detection sections

The SanBiao rule document declares a `sections` block: every engine strategy belongs to exactly one
stable section identifier, with an English label, a description, and a default-enabled set. The service
publishes those declarations through `GET /v1/manifest` as a `/sections` field, so a client renders the
control from the rules instead of hard-coding detector names.

`POST /v1/detect`, `POST /v1/detect/jobs`, and the JSON-RPC `core.detect` method accept an optional
`sections` array. Omitting it, or sending an empty array, runs every default-enabled section, which is
identical to the behavior of `0.1.1012`. An unknown identifier is rejected with `400 invalid_request`.
When a caller selects a subset, the report adds `sectionSelection` (`requested` and `notSelected`) and the
presentation adds a `section-selection` block. The weighted `totalScore` keeps its existing formula but is
no longer directly comparable with a default detection, because it averages over fewer detectors. Mode and
protocol gating still come from `payload.probes.activation`, not from `sections`.

## Capability model

Release `0.1.1015` raises the profile to `adaptive-evidence-v17` because a default detection now also runs
the rule-declared reasoning-IQ and thinking-chain sections, so v15, v16 and v17 scores are not
comparable. `reasoning_iq` evidence answers the eight rule-scored questions, counts only a parsable final
answer, and reports `{scoringVersion, answered, correct, total, score, perQuestion}`; a refusal, a
truncation or unstructured noise is downgraded to an unanswered question instead of being scored as a
wrong answer, and too few answered questions turn the evidence into an `unsupported` skip. The report
keeps the rule document's `scoringVersion` (currently `2026.10.19.1`), so an older report is never
rescored against a newer question set; `CORE_CAPABILITIES` adds `reasoning_iq_evidence_v1` and
`reasoning_iq_scoring_version_v1`. `thinking_chain` evidence is Anthropic-only and reports
`{summaryReturned, fullTextReturned, signaturePresent, redacted, mode}`: a non-Claude target, another
protocol, or a response without thinking fields is always `skip` with an `unsupported` basis and never a
failure, and `CORE_CAPABILITIES` adds `thinking_chain_evidence_v1`. Release `0.1.1014` had raised the
profile to `adaptive-evidence-v16` because a default detection also ran the rule-declared cache-reuse,
injection-overhead and knowledge-cutoff sections. Every report additionally carries an always-present
`coverage` object
(`verifiedWeight`, `applicableWeight`, `ratio` rounded to four decimals, `unverifiedCount`) that is derived
from the same evidence set and the same verified-weight denominator as `totalScore`; a skipped or errored
detector lowers coverage and never fails a detection, and `ratio` never enters the score or the verdict.
The overview view publishes a `coverage` section for clients, and `CORE_CAPABILITIES` adds
`evidence_coverage_ratio_v1`. `knowledge_cutoff` evidence is informational only: it runs a serial binary
search over rule-declared dated events with at most ten questions, carries weight `0.0` and never enters
any score. The profile retains rule-declared detection sections: a request may select a subset of the
declared sections, and the report then records `sectionSelection` so consumers can see that its score is
not directly comparable with a default detection. It consumes the 2026.10.19.2 SanBiao
calibration: the endpoint owner confirmed gpt-5.6-sol high fingerprints are 40805/40855, so those
values now classify as gpt-5.6-sol while template-dependent 40/48 outputs are no longer identity
evidence. The profile retains per-response route aliasing, effort rejection or downgrade
classification, HTTP outcome distributions, latency and retry/backoff telemetry, and detailed usage
accounting (cached, reasoning and prediction tokens) with cache-read normalization. Non-GPT guard
evidence carries a stricter reverse lookup against the versioned calibration table. Stable
classification can use only families whose rule entry has `classificationEnabled: true`; historical
and unstable observations remain available for rule audit without becoming identity candidates. The
profile retains repository provenance, the v11 rule-driven relay payload integrity evidence, and
redacted runtime progress jobs and request-isolation evidence for the context gradient. Each context
level records its own request-body byte count, single-message count, SHA-256 request fingerprint,
provider cache-token accounting and cumulative-history assessment. The profile is organized by
observable evidence rather than provider claims:

| Evidence family | What Core observes | Availability |
| --- | --- | --- |
| Identity declaration | Response model metadata and an independent concise self-declaration | All modes |
| Behavioral scenarios | Safety boundaries, untrusted instructions, exact structured formatting, and calibrated uncertainty | Full |
| Reasoning attestation | Visible or protected reasoning blocks and their opaque provider-issued attestation | Anthropic, all modes |
| Reasoning budget fingerprint | Strictly parsed visible values returned by bounded effort probes; an empirical auxiliary model-family signal | OpenAI Responses-compatible Standard/Full |
| Non-GPT Juice guard | Strict positive numeric exposure from the active rule document plus reverse lookup against its versioned GPT calibration data | Anthropic/OpenAI-compatible/Gemini-compatible Standard/Full for non-GPT model identifiers |
| Model route consistency | Requested/declared model identity, repeated text similarity, and output-token dispersion | Route check in Quick; repeated samples in Standard/Full |
| Knowledge challenge pack | Automatically resolved or manually supplied, release-calibrated factual challenges | Standard/Full when a valid pack is available |
| Embedded document | Recovery of a per-run ULID marker from an in-memory PDF | Anthropic Full |
| Tool contract | Forced client-tool identifier, selected name, schema-conforming arguments, and finish semantics | Anthropic/OpenAI Standard/Full |
| Context input audit | Controlled context gradient, exact final echo, usage growth, and fixed input overhead | All modes |
| Response integrity | Stream/non-stream similarity, usage plausibility, cumulative stream usage, and long-output termination | Standard/Full |
| Relay payload integrity | Locally observable tool payload mismatches, model-route drift, stream anomalies and secret-like response markers | Passive in Standard/Full; inferred, never cryptographic |
| Protocol conformance | Field types, content variants, usage, finish semantics, and SSE lifecycle across all collected observations | Passive in all modes |
| Identifier conventions | Stable message/client-tool/server-tool prefixes without assuming opaque suffix format | Passive for Anthropic |
| Performance telemetry | Full latency, real stream TTFT, post-TTFT generation rate, tokens, cache tokens, retries, and backoff | All collected observations |

Model self-declaration checks infer common providers from recognizable model families. Callers can
set `/parameters/expectedProvider` when a private alias or an otherwise ambiguous model identifier
needs an explicit provider expectation.

`quick`, `standard`, and `full` always return the same report shape. An evidence family that is not
applicable is emitted with `status: "skip"`, `basis: "unsupported"`, and zero effective weight. A
network failure confined to one family is recorded as `status: "error"` or a degraded warning; it
does not erase observations produced by other families.

### Reasoning budget fingerprint

The `reasoning_budget_fingerprint` detector is an optional, bounded auxiliary signal for OpenAI
Responses-compatible endpoints. Sampling plans, prompt templates, effort labels, family mappings,
scores, confidence values, summaries, and limitations come from the validated `the-standard` rule
document published by the SanBiao JSON repository. A per-sample ULID prevents reports from depending on a
fixed request identifier. Core enforces bounded plans and safe value formats before accepting a
bundle; the repository cannot supply executable code.

The classifier keeps only the effort label, normalized decimal, calibration family matches, template
identifier, HTTP status, and aggregate counts. It never persists the visible answer, prompt, request
body, headers, or authorization value. High-effort agreement is required before a family is named;
one independent effort level is required for the higher confidence grade. Overlapping values are
reported as ambiguous, and conflicting high-effort values are reported as mixed. This evidence is
always `basis: inferred`, has a deliberately small weight, and cannot promote a report to the
cryptographic tier. Relay rewriting, provider changes, and model updates can invalidate the signal.

Every Juice evidence item also exposes the secret-safe calibration revision, completion time, method,
independent-run count, accepted observations and unresolved routes. The current SanBiao calibration was
built from two complete matrices, three identity-preserving templates per effort and fresh requests with
no conversation-history reuse. `calibrationState` distinguishes `confirmed`, `partial`, `historical` and
`unstable` families. `classificationEnabled: false` means an observation is retained for audit only.

For a model identifier that does not match the GPT markers in the active rule bundle, the same
feature flag selects the `non_gpt_juice_guard_v4` capability. Its prompt and per-mode sample counts
are rule data and are intentionally not duplicated in this Core repository.

A strictly parsed and normalized decimal greater than zero sets `gptImpersonationDetected: true`,
produces `status: fail`, and is reported as a major authenticity risk. Normalized zero, including
inputs such as `0.0` or `000.000`, and successful non-numeric text set the flag to `false` and pass
the guard. If every guard request fails, the result is `warn` and remains inconclusive.

Every positive value is compared with all effort levels in the active rule bundle.
`familyMatchStatus` describes the reverse lookup:

- `unique`: every positive sample has one consistent family; `identifiedModelFamily` names it.
- `ambiguous`: the observed value is shared by multiple GPT families;
  `candidateModelFamilies` preserves every compatible family.
- `mixed`: multiple positive samples have incompatible calibrated matches, which can indicate
  mixed relay routing; no unique family is claimed.
- `unmatched`: Juice exposure is positive but absent from this calibration release; impersonation
  still fails the guard, while model identity remains unknown.
- `none`: no positive Juice value was exposed.

The secret-safe schema-v2 `details` object includes `positiveNumericSamples`, `zeroSamples`,
`familyMatchStatus`, `identifiedModelFamily`, `candidateModelFamilies`, `calibrationMatches`, the
rule status, normalized `observedValues`, aggregate counts, and limitations. It excludes
the XML, raw replies, request bodies, headers, authorization data, and API keys.

This guard is an inferred exposure test, not a private-model oracle. A relay can recognize the XML,
return a fabricated number, suppress a real value, or rewrite the response. Consequently, a positive
result signals possible GPT substitution or signal impersonation. A unique calibration match is the
best available model-family identification for that rule bundle, but it is not cryptographic proof
of the physical backend. Zero or non-numeric text is normal and only means no positive Juice value
was exposed in that run.

### Relay payload integrity

The `relay_payload_integrity` detector is a passive, rule-driven review signal inspired by the
application-layer relay trust boundary. It consumes observations already collected by other probes and
compares tool names and arguments with the per-run contract, checks declared model routes, inspects SSE
usage monotonicity and counts configured secret-like response markers. It stores aggregate counts and
rates only; raw response bodies, headers, request payloads and credentials are never copied into the
report. A mismatch indicates that the local response path deserves review, not that a provider or router
has been cryptographically proven malicious. Missing samples are `unsupported`/`skip`, and an anomaly is
never collapsed into a clean verdict.

The detector's marker list, penalties, activation matrix and English explanations are loaded from the
validated SanBiao rule document. This keeps future relay protocols and model-family calibrations outside
the binary and lets a newer rule snapshot add fields without changing the service boundary.

## Evidence basis and claims

Every detector result carries an evidence `basis`:

- `observed` means the value came directly from HTTP status, response fields, response bytes,
  headers, stream events, timing, or a challenge response.
- `inferred` means Core derived an assessment from observed values, such as model-route agreement,
  text similarity, behavior outcomes, a knowledge score, or token-growth regression.
- `unsupported` means the selected protocol, mode, model, or request configuration could not expose
  the measurement. Unsupported evidence is never silently converted to a failure or a passing score.

`confidence` expresses assessment confidence from `0` to `1`; it is not an authenticity score and
must not be used as a replacement for `score` or `verdict`.

An opaque reasoning attestation is not described as cryptographic proof merely because it exists or
looks encoded. Set `/parameters/strictAttestation` to `true` to submit a continuation containing the
returned reasoning block. Only a successful upstream continuation upgrades the report to the
`cryptographic` tier. Without that acceptance, the attestation remains inferred evidence and the
report remains at the protocol tier.

Knowledge challenges and mutable Core rules deliberately remain outside the Core binary because
facts, prompts, thresholds, mappings, and model cutoffs age independently from detection code.
SanBiao is a static JSON-only GitHub repository: it has no binary, API, database, port, or
deployment process. Core itself never reads an environment variable and never accepts a per-request
repository URL. The service adapter constructs the caller-supplied `RuleRepositoryConfig`
from a trusted manifest URL such as:

```text
https://raw.githubusercontent.com/MoBalance/SanBiao/main/manifest.json
```

Core Service fetches `manifest.json`, resolves its same-origin relative Core rule path, verifies the
SHA-256 digest of canonical UTF-8 JSON (recursive byte-sorted object keys, preserved array order and
normalized standard scalar encoding), validates every typed field and resource bound, and injects the resulting immutable
snapshot into Engine. It refreshes on a bounded TTL and keeps the last valid snapshot if a later
refresh fails. If no valid snapshot has ever loaded, detection fails explicitly with
`rules_unavailable`; Core does not contain or select an embedded production fallback.

An embedding application may ship an external, read-only SanBiao snapshot beside the service and set
`THE_STANDARD_RULE_FALLBACK_DIRECTORY` to its absolute directory. This is still repository data, not
compiled Core logic: the same Manifest, relative-path checks, size limits, typed parsing, and digest
verification apply. GhostReveal desktop packages use this mechanism so a downloaded application can
start without network access while remaining upgradeable through a newer SanBiao snapshot.

Repository-backed reports and `/health` include the following secret-safe provenance object inside
`rules`:

```json
{
  "repository": {
    "release": "2026.08.15.1",
    "manifestSource": "remote",
    "documentSource": "local_fallback"
  }
}
```

`manifestSource` and `documentSource` are recorded independently because a valid remote Manifest may
select a rule document that is temporarily read from the matching local snapshot. The only valid
values are `remote` and `local_fallback`; URLs, local paths and request credentials never enter the
health document, report, presentation, logs or share link. Direct in-memory rule injection leaves the
optional `repository` object absent rather than fabricating a source.

The current rule payload contract is `payloadSchemaVersion: 2`. It is intentionally breaking and
strict: missing or unknown fields are rejected. Activation by mode/protocol, context gradients,
consistency samples, behavior expectations, evidence weights, grade thresholds, confidence,
severity, summaries, and all Juice calibration are repository data. Rust retains finite evaluators,
protocol parsers, statistical algorithms, resource ceilings, and secret-handling invariants. The
rule payload cannot provide scripts, templates that execute code, or arbitrary expressions.

Core Service `/health` returns a compatibility health document with `status: ok` only when a validated
bundle is active. `/health/live` reports process and build liveness without loading rules, while
`/health/ready` returns the full health document with HTTP 200 only when a validated bundle is active
and HTTP 503 otherwise. Container and Kubernetes readiness probes must use `/health/ready`; liveness
probes must use `/health/live`. The nested
`rules.status` is `active` with full bundle provenance, or `unavailable` while the top-level status is
`degraded`. The `runtime` object publishes resolved engine deadlines, retry/concurrency settings,
ordinary response/stream limits, and rule refresh/document limits for operational verification. It never includes the
service bearer token, submitted API keys, configured targets, local paths, or the repository URL.
This endpoint is the readiness signal for direct Core deployments.

## Observing long-running detections

The synchronous `POST /v1/detect` endpoint and JSON-RPC `core.detect` method remain available. A UI
that needs truthful progress should use the asynchronous job API:

```text
POST /v1/detect/jobs       Create a detection job and receive its ULID snapshot
GET  /v1/detect/jobs/{id}  Poll status, redacted runtime events, final report, or public error
```

Job status moves through `queued`, `running`, and either `completed` or `failed`. Runtime events are
ordered by `sequence` and include elapsed milliseconds, stage, event name, status, an English message,
and extensible scalar details. Probe events may expose strategy, probe kind, attempt number, HTTP
status, latency, Token counts, retry delay, context level, request-body bytes, message count, and the
request-body SHA-256 fingerprint. They never expose the target URL, API key, authorization header,
full request body, or upstream response body. The in-memory service store retains at most 256 jobs;
clients must persist completed reports elsewhere when durable history is required.

Loopback HTTP is accepted for local development. Other cleartext HTTP sources require the
an explicit adapter-level insecure-HTTP override. TheStandard limits the
response size, validates Repository Schema v1, rejects redirects and cross-origin paths, and verifies the pack's canonical SHA-256 digest before
using any challenge.

When `knowledgeChallenges` is absent or empty, Standard and Full modes resolve by protocol, model,
optional `expectedProvider`, channel, optional pack id, and optional pinned version:

```json
{
  "parameters": {
    "knowledgeRepositoryEnabled": true,
    "knowledgePackId": "provider-model-knowledge",
    "knowledgePackChannel": "stable",
    "knowledgePackVersion": "2026.08.05",
    "knowledgeChallenges": []
  }
}
```

Leave id and version empty to select the newest matching pack in the configured channel. A non-empty
manual array takes precedence and is useful for offline runs or one-time calibration:

```json
{
  "parameters": {
    "knowledgePackVersion": "provider-model-20260805",
    "knowledgeChallenges": [
      {
        "id": "release-fact-01",
        "prompt": "A fact question validated against the target release.",
        "expectedTerms": ["required phrase"],
        "uncertaintyTerms": ["unknown", "cannot confirm"]
      }
    ]
  }
}
```

Repository maintainers own calibration and versioning of those facts. Reports include resolution source,
status, pack id, version, channel, and digest in the knowledge evidence details. The challenge prompt
and expected terms are not copied into the report. A missing match is `skip`; an unavailable or
invalid repository document is a zero-weight `error`, so the other evidence families still complete.

## Discovering the manifest

All supported transports return the same `CoreUiManifest`:

```text
REST       GET /v1/manifest
JSON-RPC   POST /rpc, method core.manifest, params {}
Product    GET /api/core/manifest (transport-neutral proxy)
```

When a service bearer token is configured, REST and JSON-RPC discovery require the same token
as detection. A product proxy uses its configured REST or JSON-RPC transport and never exposes that service
token to the browser.

Schema v1 example, shortened only by omitting additional fields and options:

```json
{
  "schemaVersion": 1,
  "language": "en",
  "request": {
    "submitLabel": "Start detection",
    "fields": [
      {
        "id": "base-url",
        "jsonPointer": "/baseUrl",
        "label": "Model API endpoint",
        "description": "Enter the base URL for the model API you want to test.",
        "control": "url",
        "required": true,
        "sensitive": false,
        "placeholder": "https://relay.example/v1",
        "defaultValue": "https://demo.example.com"
      },
      {
        "id": "api-key",
        "jsonPointer": "/apiKey",
        "label": "API key",
        "control": "secret",
        "required": true,
        "sensitive": true,
        "defaultValue": ""
      },
      {
        "id": "mode",
        "jsonPointer": "/mode",
        "label": "Detection depth",
        "control": "segmented",
        "required": true,
        "sensitive": false,
        "defaultValue": "standard",
        "options": [
          { "value": "quick", "label": "Quick", "description": "2 context levels" },
          { "value": "standard", "label": "Standard", "description": "3 levels plus consistency" },
          { "value": "full", "label": "Full", "description": "4-level evidence suite" }
        ]
      }
    ]
  },
  "presentation": {
    "schemaVersion": 1,
    "supportedLayouts": ["hero", "metric_grid", "key_value", "table"],
    "supportedFormats": [
      "text", "number", "score", "status", "duration_ms", "rate",
      "token_count", "percentage", "code", "timestamp", "json"
    ],
    "unknownHintFallback": "Render unknown layouts as adaptive stacked sections and infer every field value from its JSON shape; reserve serialized JSON for an explicit raw developer view."
  }
}
```

## Building requests

Every manifest field writes its JSON `defaultValue` or user value to `jsonPointer`. Pointers follow
RFC 6901, including `~0` for `~` and `~1` for `/`. Clients must preserve the JSON value type supplied
by an option or default instead of coercing every value to a string.

Stable envelope fields currently use `/baseUrl`, `/apiKey`, `/model`, `/protocol`, and `/mode`.
New optional inputs are added below `/parameters/*`:

```json
{
  "baseUrl": "https://relay.example/v1",
  "apiKey": "write-only-secret",
  "model": "model-id",
  "protocol": "openai",
  "mode": "standard",
  "parameters": {
    "expectedProvider": "Anthropic",
    "strictAttestation": true,
    "knowledgeRepositoryEnabled": true,
    "knowledgePackId": "provider-model-knowledge",
    "knowledgePackChannel": "stable",
    "knowledgePackVersion": "2026.08.05",
    "knowledgeChallenges": [],
    "repetitionTolerance": 0.15,
    "strictContext": true,
    "futureConfig": { "sampleBudget": 4 }
  }
}
```

`ProbeRequest.parameters` is an extension map. Unknown keys must survive transport serialization.
Old clients may omit it. Core may add optional fields without changing the stable envelope or
requiring a client release.

The default execution guard allows at most three concurrent requests. A retryable transport failure
or HTTP 429/503 response activates shared backoff across all evidence families, using a bounded
1/2/4-second retry sequence unless the upstream supplies `Retry-After`. Per-request timeout is 30
seconds; overall timeouts are 60/120/180 seconds for Quick/Standard/Full.

Schema-v1 clients should implement `text`, `url`, `secret`, `number`, `select`, `segmented`, and
`boolean`. An unknown control containing an object or array should use a JSON editor; an unknown
scalar should use a labeled text fallback. If a required field truly cannot be represented, disable
submission and show an explicit English contract error. Optional unknown fields must not make the
whole manifest unusable.

Do not copy non-sensitive field names into a hardcoded local form. Query-string prefill, when a
product offers it, must also be derived from manifest pointers. Sensitive fields must never be read
from URLs.

## Rendering reports

Schema-v4 reports include an English `presentation` document:

```json
{
  "schemaVersion": 1,
  "language": "en",
  "views": [
    {
      "id": "overview",
      "label": "Overview",
      "description": "Core verdict, provenance, and performance for this detection.",
      "sections": [
        {
          "id": "verdict",
          "title": "Detection result",
          "layout": "hero",
          "fields": [
            {
              "key": "score",
              "label": "Authenticity score",
              "value": 92.4,
              "format": "score",
              "status": "verified"
            }
          ]
        },
        {
          "id": "provenance",
          "title": "Core provenance",
          "layout": "key_value",
          "fields": [
            { "key": "core-version", "label": "Core version", "value": "0.1.1015", "format": "code" },
            { "key": "report-schema", "label": "Report schema", "value": 7, "format": "number" },
            { "key": "profile", "label": "Capability profile", "value": "adaptive-evidence-v17", "format": "code" }
          ]
        }
      ]
    }
  ]
}
```

Clients render `views` as selectable report views and preserve manifest order. Within each view they
render `sections`, then `fields` or `rows`. The schema-v1 layout hints are:

| Layout | Meaning |
| --- | --- |
| `hero` | Dominant verdict or primary result fields |
| `metric_grid` | Comparable measurements |
| `key_value` | Metadata and provenance |
| `table` | Repeated rows with fields matched by `key` |

The schema-v1 formats are `text`, `number`, `score`, `status`, `duration_ms`, `rate`, `token_count`,
`percentage`, `code`, `timestamp`, and `json`. `format`, `layout`, and `status` are semantic hints,
not closed enums. A client encountering a new layout must render every field and row through an
adaptive stacked or grid layout. A new or unknown format must fall back to the runtime JSON shape;
`format: json` does not require or permit an inline serialized JSON block in an ordinary report view.

Every compliant presentation renderer recursively applies these minimum shape rules:

| Runtime value shape | Required generic presentation |
| --- | --- |
| `null` | Quiet empty-value marker |
| Boolean | Distinct true/false semantic indicator |
| Number | Locale-safe numeric value, preserving `unit` and recognized format hints |
| String | Escaped text, with safe URL, timestamp, code, or status treatment when hinted or unambiguous |
| Array of primitives | Wrapping value list or tags that preserve order |
| Array of flat objects | Responsive table with columns derived from the object keys |
| Mixed or nested array | Indexed repeated groups, recursively rendering each item |
| Object | Labeled key-value grid, recursively rendering every property |

Clients must not assume a maximum number, order, or fixed set of presentation fields. Large field,
row, property, and array collections must use bounded pagination, windowing, or progressive expansion
that keeps every item reachable without mounting an unbounded DOM tree. Automatic recursion may stop
at a documented safe depth only when the UI provides an explicit control to continue inspecting the
nested value. It must not serialize, truncate, or silently discard the remainder.

Full serialized JSON belongs only in an explicit Raw JSON developer view. Unknown hints and values
must never hide data, inject markup, execute content, expose secrets, or reject an otherwise valid
report. React and similar clients rely on their normal escaped text rendering and must never treat a
Core string as HTML.

Reports created before presentation schema v1 may have no `presentation`. Clients must keep a generic
legacy adapter that projects typed top-level report properties into the same recursive renderer. They
must not reintroduce detector-ID switches or inline JSON panels to make old reports look specialized.

## Language ownership

All Core-owned labels, detector names, option text, explanations, verdict content, view titles,
section titles, field labels, and descriptions are canonical English. Clients render them verbatim.
A host product may localize its own navigation, authentication, monitoring, ranking, and
administration UI. A standalone demo may localize its application chrome, but not engine content.

Dynamic provider, model, and customer strings are data and remain unchanged.

## Sensitive-field policy

`ProbeInputField.sensitive` is authoritative. A compliant client and transport must ensure that a
sensitive value:

- remains only in live request/component memory for the current operation;
- is never initialized from or written to a URL;
- is never written to localStorage, sessionStorage, persisted history, logs, analytics, or exports;
- is never copied into report presentation or raw report JSON;
- is removed defensively if a non-compliant upstream accidentally echoes it.

Core reports expose only `target.apiKeyMasked`. Adding a new secret requires `sensitive: true` in the
manifest before release. A secret value is not a valid presentation field under any format.

## Extension procedure

To add a request parameter, add an optional manifest field under `/parameters/*`, select the closest
existing control, provide an English label/description/default, and mark sensitivity accurately.
Keep the typed stable envelope unchanged.

To add a detector or metric, extend the typed report and generate presentation fields or rows in the
appropriate view. Add a view or section when it communicates a distinct concept. Prefer existing
layouts and formats, but new semantic hints are allowed because compliant clients have fallbacks.

Every extension must add contract tests proving:

- REST and JSON-RPC return equivalent manifests;
- the new value crosses the request boundary with its original JSON type;
- the report carries Core version, report schema, capability profile, and presentation schema;
- a generic client recursively displays every new field and nested value even when it does not
  recognize a hint, without an inline serialized JSON fallback;
- no manifest-declared secret occurs in the report or persisted browser state.

## Versioning and breaking changes

Adding an optional field below `/parameters/*`, a detector, metric, view, section, or unknown-tolerant
layout/format hint is forward-compatible. It does not by itself require a manifest or presentation
schema increment.

Increment the relevant schema before changing required property meaning, removing/renaming a stable
property, changing JSON Pointer semantics, changing row/field structure, or making a formerly
optional input required. A breaking release may remove prior names, fields, and transport behavior
when its release notes explicitly declare that compatibility is not provided. TheStandard does not
publish implicit aliases.

Change `capabilityProfile` whenever scoring semantics or probe capabilities change enough that report
scores should not be compared on the same scale. Change the Core crate version for every released
implementation change. Never infer one identifier from another.

## Acknowledgements

TheStandard's independent reasoning-budget fingerprint design was informed by the public research notes,
calibration observations, and limitations discussion in
[`chen-006/gpt56_api_detector`](https://github.com/chen-006/gpt56_api_detector). We wrote the
TheStandard implementation, prompts, contracts, and presentation independently; no source code, prompt
text, or report schema is copied from that project.

We also thank the [linux.do](https://linux.do) forum community for public discussions about model
API observability, relay transparency, and practical verification methods.

The broader relay-integrity and behavioral-fingerprinting design was also informed by:

- [Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain](https://arxiv.org/pdf/2604.08407)
- [LLMmap](https://github.com/pasquini-dario/LLMmap)
- [api-relay-audit](https://github.com/toby-bridges/api-relay-audit)

The paper is acknowledged as an academic publication; LLMmap is published under GPL-3.0 and
api-relay-audit under AGPL-3.0-only. These sources are acknowledged for research inspiration and
capability boundaries only. TheStandard's
implementation, rule contract, prompts, scoring and UI presentation are independently written; no
third-party source code, model weights, prompts, rules or report templates are copied. Each referenced
project remains governed by its own license. The open-source matrix is connected through
[SanBiao](https://github.com/MoBalance/SanBiao) and
[GhostReveal](https://github.com/MoBalance/GhostReveal).
