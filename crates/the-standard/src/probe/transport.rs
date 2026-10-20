use crate::{
    ContextProbeMetadata, CoreError, HttpTransportConfig, ProbeKind, ProbeObservation,
    StreamEventObservation, UsageMetrics,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, time::Duration};
use tokio::time::Instant;

#[derive(Debug, Clone)]
pub struct OutboundProbe {
    pub kind: ProbeKind,
    pub challenge_id: Option<String>,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
    pub context: Option<ContextProbeMetadata>,
    pub(crate) demo_response: Option<String>,
    pub(crate) demo_tool_arguments: Option<Value>,
}

#[async_trait]
pub trait ProbeTransport: Send + Sync {
    async fn execute(
        &self,
        probe: &OutboundProbe,
        timeout: Duration,
    ) -> Result<ProbeObservation, CoreError>;
}

#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    config: HttpTransportConfig,
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpTransport {
    pub fn new() -> Self {
        Self::with_config(HttpTransportConfig::default())
            .expect("default HTTP transport configuration is valid")
    }

    pub fn with_config(config: HttpTransportConfig) -> Result<Self, String> {
        config.validate()?;
        Self::from_builder(reqwest::Client::builder(), config)
    }

    pub fn with_resolved_target(
        config: HttpTransportConfig,
        host: &str,
        addresses: &[SocketAddr],
    ) -> Result<Self, String> {
        config.validate()?;
        if host.trim().is_empty() || addresses.is_empty() {
            return Err("resolved target host and addresses must not be empty".into());
        }
        Self::from_builder(
            reqwest::Client::builder().resolve_to_addrs(host, addresses),
            config,
        )
    }

    fn from_builder(
        builder: reqwest::ClientBuilder,
        config: HttpTransportConfig,
    ) -> Result<Self, String> {
        Ok(Self {
            client: builder
                .user_agent(concat!("the-standard/", env!("CARGO_PKG_VERSION")))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| format!("invalid HTTP client configuration: {error}"))?,
            config,
        })
    }

    pub fn config(&self) -> HttpTransportConfig {
        self.config
    }
}

#[async_trait]
impl ProbeTransport for HttpTransport {
    async fn execute(
        &self,
        probe: &OutboundProbe,
        timeout: Duration,
    ) -> Result<ProbeObservation, CoreError> {
        let mut headers = HeaderMap::new();
        for (name, value) in &probe.headers {
            let name = HeaderName::from_str(name)
                .map_err(|error| CoreError::InvalidEndpoint(error.to_string()))?;
            let value = HeaderValue::from_str(value)
                .map_err(|error| CoreError::InvalidEndpoint(error.to_string()))?;
            headers.insert(name, value);
        }
        if probe
            .body
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            headers.insert(
                reqwest::header::ACCEPT,
                HeaderValue::from_static("text/event-stream"),
            );
        }

        let started = Instant::now();
        let response = self
            .client
            .post(&probe.url)
            .headers(headers)
            .json(&probe.body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|error| CoreError::Transport(error.to_string()))?;
        let status_code = response.status().as_u16();
        let response_headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        let is_stream = probe
            .body
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("text/event-stream"));

        let (response, text, usage, ttft_ms, stream_events) = if is_stream {
            read_event_stream(response, started, self.config).await?
        } else {
            let raw = read_bounded_response(response, self.config.max_response_bytes).await?;
            let response: Value =
                serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({ "raw": raw }));
            let text = extract_response_text(&response);
            let usage = extract_usage(&response);
            (response, text, usage, None, Vec::new())
        };
        let latency_ms = started.elapsed().as_millis() as u64;

        Ok(ProbeObservation {
            kind: probe.kind,
            challenge_id: probe.challenge_id.clone(),
            status_code,
            latency_ms,
            ttft_ms,
            response,
            text,
            response_headers,
            stream_events,
            usage,
            retry_count: 0,
            backoff_count: 0,
            context: probe.context.clone(),
        })
    }
}

async fn read_bounded_response(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<String, CoreError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(CoreError::Parse(format!(
            "response exceeded the {max_response_bytes}-byte safety limit"
        )));
    }
    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default()
        .min(max_response_bytes);
    let mut chunks = response.bytes_stream();
    let mut raw = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|error| CoreError::Transport(error.to_string()))?;
        if chunk.len() > max_response_bytes.saturating_sub(raw.len()) {
            return Err(CoreError::Parse(format!(
                "response exceeded the {max_response_bytes}-byte safety limit"
            )));
        }
        raw.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

async fn read_event_stream(
    response: reqwest::Response,
    started: Instant,
    config: HttpTransportConfig,
) -> Result<
    (
        Value,
        String,
        UsageMetrics,
        Option<u64>,
        Vec<StreamEventObservation>,
    ),
    CoreError,
> {
    let mut bytes = response.bytes_stream();
    let mut pending = String::new();
    let mut events = Vec::new();
    let mut ttft_ms = None;
    let mut received_bytes = 0_usize;
    let mut terminal = false;

    while !terminal {
        let Some(chunk) = bytes.next().await else {
            break;
        };
        let chunk = chunk.map_err(|error| CoreError::Transport(error.to_string()))?;
        received_bytes = received_bytes.saturating_add(chunk.len());
        if received_bytes > config.max_stream_bytes {
            return Err(CoreError::Parse(format!(
                "event stream exceeded the {}-byte safety limit",
                config.max_stream_bytes
            )));
        }
        pending.push_str(&String::from_utf8_lossy(&chunk));
        pending = pending.replace("\r\n", "\n");
        while let Some(boundary) = pending.find("\n\n") {
            let frame = pending[..boundary].to_owned();
            pending.drain(..boundary + 2);
            match parse_event_frame(&frame, started.elapsed().as_millis() as u64) {
                ParsedEventFrame::Event(event) => {
                    push_stream_event(&mut events, &mut ttft_ms, event, config.max_stream_events)?;
                }
                ParsedEventFrame::Terminal(event) => {
                    if let Some(event) = event {
                        push_stream_event(
                            &mut events,
                            &mut ttft_ms,
                            event,
                            config.max_stream_events,
                        )?;
                    }
                    terminal = true;
                    break;
                }
                ParsedEventFrame::Ignore => {}
            }
        }
    }
    if !terminal {
        match parse_event_frame(pending.trim(), started.elapsed().as_millis() as u64) {
            ParsedEventFrame::Event(event) | ParsedEventFrame::Terminal(Some(event)) => {
                push_stream_event(&mut events, &mut ttft_ms, event, config.max_stream_events)?;
            }
            ParsedEventFrame::Terminal(None) | ParsedEventFrame::Ignore => {}
        }
    }

    let assembled = assemble_event_response(&events);
    let text = extract_response_text(&assembled);
    let usage = extract_usage(&assembled);
    Ok((assembled, text, usage, ttft_ms, events))
}

enum ParsedEventFrame {
    Event(StreamEventObservation),
    Terminal(Option<StreamEventObservation>),
    Ignore,
}

fn push_stream_event(
    events: &mut Vec<StreamEventObservation>,
    ttft_ms: &mut Option<u64>,
    event: StreamEventObservation,
    max_stream_events: usize,
) -> Result<(), CoreError> {
    if events.len() >= max_stream_events {
        return Err(CoreError::Parse(format!(
            "event stream exceeded the {max_stream_events}-event safety limit"
        )));
    }
    if ttft_ms.is_none() && event_contains_output(&event) {
        *ttft_ms = Some(event.elapsed_ms);
    }
    events.push(event);
    Ok(())
}

fn parse_event_frame(frame: &str, elapsed_ms: u64) -> ParsedEventFrame {
    if frame.is_empty() {
        return ParsedEventFrame::Ignore;
    }
    let mut event_name = None;
    let mut data_lines = Vec::new();
    for line in frame.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            event_name = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_lines.push(value.trim_start());
        }
    }
    let data_text = data_lines.join("\n");
    if data_text.is_empty() {
        return ParsedEventFrame::Ignore;
    }
    if data_text == "[DONE]" {
        return ParsedEventFrame::Terminal(None);
    }
    let data = serde_json::from_str::<Value>(&data_text)
        .unwrap_or_else(|_| serde_json::json!({ "unparsedData": data_text }));
    let event = event_name
        .or_else(|| data.get("type").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| "message".into());
    let event = StreamEventObservation {
        event,
        elapsed_ms,
        data,
    };
    if matches!(
        event.event.as_str(),
        "message_stop" | "response.completed" | "response.failed" | "response.incomplete"
    ) {
        ParsedEventFrame::Terminal(Some(event))
    } else {
        ParsedEventFrame::Event(event)
    }
}

fn event_contains_output(event: &StreamEventObservation) -> bool {
    matches!(
        event.data.pointer("/delta/type").and_then(Value::as_str),
        Some("text_delta" | "thinking_delta" | "input_json_delta")
    ) || event.data.pointer("/choices/0/delta/content").is_some()
}

fn assemble_event_response(events: &[StreamEventObservation]) -> Value {
    if events
        .iter()
        .any(|event| event.data.pointer("/choices/0/delta").is_some())
    {
        return assemble_openai_event_response(events);
    }
    let mut root = events
        .iter()
        .find_map(|event| {
            event
                .data
                .get("message")
                .or_else(|| event.data.get("response"))
                .cloned()
        })
        .unwrap_or_else(|| serde_json::json!({}));
    let mut blocks = BTreeMap::<usize, Value>::new();

    for event in events {
        let data = &event.data;
        match event.event.as_str() {
            "content_block_start" => {
                if let (Some(index), Some(block)) = (
                    data.get("index").and_then(Value::as_u64),
                    data.get("content_block").cloned(),
                ) {
                    blocks.insert(index as usize, block);
                }
            }
            "content_block_delta" => {
                let Some(index) = data.get("index").and_then(Value::as_u64) else {
                    continue;
                };
                let delta = data.get("delta").cloned().unwrap_or(Value::Null);
                let block = blocks
                    .entry(index as usize)
                    .or_insert_with(|| serde_json::json!({}));
                merge_block_delta(block, &delta);
            }
            "message_delta" => {
                if let Some(delta) = data.get("delta") {
                    merge_object(&mut root, delta);
                }
                if let Some(usage) = data.get("usage") {
                    root["usage"] = usage.clone();
                }
            }
            _ => {
                if let Some(content) = data
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                {
                    let block = blocks
                        .entry(0)
                        .or_insert_with(|| serde_json::json!({ "type": "text", "text": "" }));
                    append_string(block, "text", content);
                }
                if data.get("usage").is_some() {
                    root["usage"] = data["usage"].clone();
                }
            }
        }
    }

    if !blocks.is_empty() {
        root["content"] = Value::Array(blocks.into_values().collect());
    }
    if root.get("choices").is_none() && root.get("content").is_none() {
        root["streamEvents"] = serde_json::to_value(events).unwrap_or_default();
    }
    root
}

fn assemble_openai_event_response(events: &[StreamEventObservation]) -> Value {
    let first = events
        .iter()
        .find(|event| event.data.pointer("/choices/0/delta").is_some())
        .map(|event| &event.data);
    let mut text = String::new();
    let mut finish_reason = Value::Null;
    let mut usage = Value::Null;
    for event in events {
        if let Some(content) = event
            .data
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
        {
            text.push_str(content);
        }
        if let Some(reason) = event.data.pointer("/choices/0/finish_reason")
            && !reason.is_null()
        {
            finish_reason = reason.clone();
        }
        if event
            .data
            .get("usage")
            .is_some_and(|value| !value.is_null())
        {
            usage = event.data["usage"].clone();
        }
    }
    json!({
        "id": first.and_then(|value| value.get("id")).cloned().unwrap_or(Value::Null),
        "object": first.and_then(|value| value.get("object")).cloned().unwrap_or(json!("chat.completion")),
        "model": first.and_then(|value| value.get("model")).cloned().unwrap_or(Value::Null),
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": finish_reason
        }],
        "usage": usage
    })
}

fn merge_block_delta(block: &mut Value, delta: &Value) {
    match delta.get("type").and_then(Value::as_str) {
        Some("text_delta") => append_string(
            block,
            "text",
            delta
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        Some("thinking_delta") => append_string(
            block,
            "thinking",
            delta
                .get("thinking")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        Some("signature_delta") => {
            block["signature"] = delta.get("signature").cloned().unwrap_or(Value::Null);
        }
        Some("input_json_delta") => append_string(
            block,
            "partial_json",
            delta
                .get("partial_json")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        _ => merge_object(block, delta),
    }
}

fn append_string(value: &mut Value, key: &str, suffix: &str) {
    let current = value.get(key).and_then(Value::as_str).unwrap_or_default();
    value[key] = Value::String(format!("{current}{suffix}"));
}

fn merge_object(target: &mut Value, source: &Value) {
    let Some(source) = source.as_object() else {
        return;
    };
    if !target.is_object() {
        *target = serde_json::json!({});
    }
    let target = target.as_object_mut().expect("target was initialized");
    for (key, value) in source {
        target.insert(key.clone(), value.clone());
    }
}

fn extract_response_text(value: &Value) -> String {
    let content_text = value
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    if !content_text.is_empty() {
        return content_text;
    }
    let responses_text = value
        .get("output")
        .and_then(Value::as_array)
        .map(|outputs| {
            outputs
                .iter()
                .filter_map(|output| output.get("content").and_then(Value::as_array))
                .flatten()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("output_text"))
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    if !responses_text.is_empty() {
        return responses_text;
    }
    value
        .pointer("/content/0/text")
        .or_else(|| value.pointer("/choices/0/message/content"))
        .or_else(|| value.pointer("/candidates/0/content/parts/0/text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn extract_usage(value: &Value) -> UsageMetrics {
    let input = value
        .pointer("/usage/input_tokens")
        .or_else(|| value.pointer("/usage/prompt_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let output = value
        .pointer("/usage/output_tokens")
        .or_else(|| value.pointer("/usage/completion_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let openai_input_details = value.pointer("/usage/input_tokens_details").cloned();
    let openai_output_details = value.pointer("/usage/output_tokens_details").cloned();
    let server_tool_use = value.pointer("/usage/server_tool_use").cloned();
    let provider_extensions = if openai_input_details.is_some()
        || openai_output_details.is_some()
        || server_tool_use.is_some()
    {
        Some(json!({
            "openai": {
                "inputTokensDetails": openai_input_details,
                "outputTokensDetails": openai_output_details,
            },
            "serverToolUse": server_tool_use,
        }))
    } else {
        None
    };
    UsageMetrics {
        input_tokens: input,
        output_tokens: output,
        cache_read_input_tokens: value
            .pointer("/usage/cache_read_input_tokens")
            .or_else(|| value.pointer("/usage/input_tokens_details/cached_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        cache_creation_input_tokens: value
            .pointer("/usage/cache_creation_input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        provider_extensions,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ParsedEventFrame, assemble_event_response, event_contains_output, extract_response_text,
        extract_usage, parse_event_frame,
    };
    use crate::probe::transport::ProbeTransport;
    use crate::{HttpTransportConfig, StreamEventObservation};
    use axum::{
        Json, Router,
        body::Body,
        http::{StatusCode, header},
        routing::post,
    };
    use futures_util::{StreamExt, stream};
    use serde_json::json;
    use std::{
        convert::Infallible,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::time::{Duration, timeout};

    #[test]
    fn event_frames_preserve_multiline_json_and_elapsed_time() {
        let ParsedEventFrame::Event(event) = parse_event_frame(
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\ndata: \"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}",
            37,
        ) else {
            panic!("event frame")
        };
        assert_eq!(event.event, "content_block_delta");
        assert_eq!(event.elapsed_ms, 37);
        assert_eq!(event.data["delta"]["text"], "hello");
        assert!(event_contains_output(&event));
    }

    #[test]
    fn anthropic_stream_is_assembled_into_a_normal_response() {
        let events = vec![
            StreamEventObservation {
                event: "message_start".into(),
                elapsed_ms: 2,
                data: json!({"message": {"id": "msg_fixture", "type": "message", "role": "assistant", "model": "claude-sonnet-4-6", "content": [], "usage": {"input_tokens": 5, "output_tokens": 1}}}),
            },
            StreamEventObservation {
                event: "content_block_start".into(),
                elapsed_ms: 4,
                data: json!({"index": 0, "content_block": {"type": "text", "text": ""}}),
            },
            StreamEventObservation {
                event: "content_block_delta".into(),
                elapsed_ms: 8,
                data: json!({"index": 0, "delta": {"type": "text_delta", "text": "hello "}}),
            },
            StreamEventObservation {
                event: "content_block_delta".into(),
                elapsed_ms: 9,
                data: json!({"index": 0, "delta": {"type": "text_delta", "text": "world"}}),
            },
            StreamEventObservation {
                event: "content_block_stop".into(),
                elapsed_ms: 10,
                data: json!({"index": 0}),
            },
            StreamEventObservation {
                event: "message_delta".into(),
                elapsed_ms: 12,
                data: json!({"delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"input_tokens": 5, "output_tokens": 3}}),
            },
            StreamEventObservation {
                event: "message_stop".into(),
                elapsed_ms: 13,
                data: json!({}),
            },
        ];
        let response = assemble_event_response(&events);
        assert_eq!(response["content"][0]["text"], "hello world");
        assert_eq!(response["stop_reason"], "end_turn");
        assert_eq!(response["usage"]["output_tokens"], 3);
    }

    #[test]
    fn signature_deltas_are_attached_to_the_reasoning_block() {
        let response = assemble_event_response(&[
            StreamEventObservation {
                event: "message_start".into(),
                elapsed_ms: 1,
                data: json!({"message": {"content": []}}),
            },
            StreamEventObservation {
                event: "content_block_start".into(),
                elapsed_ms: 2,
                data: json!({"index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}}),
            },
            StreamEventObservation {
                event: "content_block_delta".into(),
                elapsed_ms: 3,
                data: json!({"index": 0, "delta": {"type": "thinking_delta", "thinking": "reasoning"}}),
            },
            StreamEventObservation {
                event: "content_block_delta".into(),
                elapsed_ms: 4,
                data: json!({"index": 0, "delta": {"type": "signature_delta", "signature": "opaque-attestation"}}),
            },
        ]);
        assert_eq!(response["content"][0]["thinking"], "reasoning");
        assert_eq!(response["content"][0]["signature"], "opaque-attestation");
    }

    #[test]
    fn openai_stream_is_assembled_into_chat_completion_shape() {
        let response = assemble_event_response(&[
            StreamEventObservation {
                event: "message".into(),
                elapsed_ms: 2,
                data: json!({"id": "chatcmpl_fixture", "object": "chat.completion.chunk", "model": "gpt-fixture", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "hello "}, "finish_reason": null}]}),
            },
            StreamEventObservation {
                event: "message".into(),
                elapsed_ms: 4,
                data: json!({"id": "chatcmpl_fixture", "model": "gpt-fixture", "choices": [{"index": 0, "delta": {"content": "world"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 5, "completion_tokens": 2}}),
            },
        ]);
        assert_eq!(response["id"], "chatcmpl_fixture");
        assert_eq!(response["model"], "gpt-fixture");
        assert_eq!(response["choices"][0]["message"]["content"], "hello world");
        assert_eq!(response["choices"][0]["finish_reason"], "stop");
        assert_eq!(response["usage"]["completion_tokens"], 2);
    }

    #[test]
    fn openai_responses_output_text_is_extracted() {
        let response = json!({
            "output": [
                {"type": "reasoning", "content": []},
                {"type": "message", "content": [
                    {"type": "output_text", "text": "4"},
                    {"type": "refusal", "text": "ignored"},
                    {"type": "output_text", "text": "0"}
                ]}
            ]
        });
        assert_eq!(extract_response_text(&response), "40");
    }

    #[test]
    fn openai_usage_details_are_normalized_without_losing_extensions() {
        let usage = extract_usage(&json!({
            "usage": {
                "input_tokens": 120,
                "output_tokens": 32,
                "total_tokens": 152,
                "input_tokens_details": {"cached_tokens": 80},
                "output_tokens_details": {
                    "reasoning_tokens": 24,
                    "accepted_prediction_tokens": 3,
                    "rejected_prediction_tokens": 1
                }
            }
        }));
        assert_eq!(usage.input_tokens, 120);
        assert_eq!(usage.output_tokens, 32);
        assert_eq!(usage.cache_read_input_tokens, 80);
        let extensions = usage.provider_extensions.expect("OpenAI usage extensions");
        assert_eq!(
            extensions.pointer("/openai/outputTokensDetails/reasoning_tokens"),
            Some(&json!(24))
        );
        assert_eq!(
            extensions.pointer("/openai/inputTokensDetails/cached_tokens"),
            Some(&json!(80))
        );
    }

    #[test]
    fn terminal_done_frame_is_distinguished_from_an_ignored_frame() {
        assert!(matches!(
            parse_event_frame("data: [DONE]", 4),
            ParsedEventFrame::Terminal(None)
        ));
        assert!(matches!(
            parse_event_frame(": heartbeat", 4),
            ParsedEventFrame::Ignore
        ));
        assert!(matches!(
            parse_event_frame(
                "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\"}}",
                4
            ),
            ParsedEventFrame::Terminal(Some(_))
        ));
    }

    #[tokio::test]
    async fn http_transport_stops_after_done_without_waiting_for_eof() {
        let app = Router::new().route(
            "/stream",
            post(|| async {
                let body = stream::once(async {
                    Ok::<_, Infallible>(
                        "data: {\"id\":\"chatcmpl_fixture\",\"model\":\"fixture\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n"
                            .to_owned(),
                    )
                })
                .chain(stream::pending());
                Body::from_stream(body)
            }),
        );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });

        let probe = super::OutboundProbe {
            kind: crate::ProbeKind::StreamIntegrity,
            challenge_id: None,
            url: format!("http://{address}/stream"),
            headers: Default::default(),
            body: json!({"model":"fixture","stream":true}),
            context: None,
            demo_response: None,
            demo_tool_arguments: None,
        };
        let observation = timeout(
            Duration::from_secs(1),
            super::HttpTransport::new().execute(&probe, Duration::from_secs(5)),
        )
        .await
        .expect("terminal event should stop the reader")
        .expect("stream should be valid");
        assert_eq!(observation.text, "ok");
        assert_eq!(observation.stream_events.len(), 1);
    }

    #[tokio::test]
    async fn http_transport_enforces_its_configured_event_limit() {
        let app = Router::new().route(
            "/stream",
            post(|| async {
                Body::from(
                    "data: {\"choices\":[{\"delta\":{\"content\":\"one\"}}]}\n\n\
                     data: {\"choices\":[{\"delta\":{\"content\":\"two\"}}]}\n\n\
                     data: [DONE]\n\n",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("test server address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server runs");
        });
        let probe = super::OutboundProbe {
            kind: crate::ProbeKind::StreamIntegrity,
            challenge_id: None,
            url: format!("http://{address}/stream"),
            headers: Default::default(),
            body: json!({"model":"fixture","stream":true}),
            context: None,
            demo_response: None,
            demo_tool_arguments: None,
        };
        let transport = super::HttpTransport::with_config(HttpTransportConfig {
            max_response_bytes: 64 * 1024,
            max_stream_bytes: 64 * 1024,
            max_stream_events: 1,
        })
        .unwrap();
        let error = transport
            .execute(&probe, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("1-event safety limit"));
    }

    #[tokio::test]
    async fn http_transport_bounds_ordinary_response_bodies() {
        const LIMIT: usize = 64 * 1024;
        let exact = "x".repeat(LIMIT);
        let oversized = "y".repeat(LIMIT + 1);
        let app = Router::new()
            .route(
                "/exact",
                post(move || {
                    let exact = exact.clone();
                    async move { exact }
                }),
            )
            .route(
                "/oversized",
                post(move || {
                    let oversized = oversized.clone();
                    async move { oversized }
                }),
            )
            .route(
                "/chunked-oversized",
                post(|| async {
                    Body::from_stream(stream::iter([
                        Ok::<_, Infallible>("z".repeat(LIMIT / 2)),
                        Ok::<_, Infallible>("z".repeat(LIMIT / 2)),
                        Ok::<_, Infallible>("z".to_owned()),
                    ]))
                }),
            );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind response-limit server");
        let address = listener.local_addr().expect("response-limit address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("response-limit server runs");
        });
        let transport = super::HttpTransport::with_config(HttpTransportConfig {
            max_response_bytes: LIMIT,
            ..HttpTransportConfig::default()
        })
        .unwrap();
        let probe = |path: &str| super::OutboundProbe {
            kind: crate::ProbeKind::Identity,
            challenge_id: None,
            url: format!("http://{address}/{path}"),
            headers: Default::default(),
            body: json!({"model":"fixture"}),
            context: None,
            demo_response: None,
            demo_tool_arguments: None,
        };

        let exact = transport
            .execute(&probe("exact"), Duration::from_secs(2))
            .await
            .expect("body exactly at the configured ceiling is accepted");
        assert_eq!(exact.response["raw"].as_str().unwrap().len(), LIMIT);

        let error = transport
            .execute(&probe("oversized"), Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(error, crate::CoreError::Parse(_)));
        assert!(error.to_string().contains("65536-byte safety limit"));
        assert!(!error.to_string().contains(&"y".repeat(64)));

        let error = transport
            .execute(&probe("chunked-oversized"), Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(error, crate::CoreError::Parse(_)));
        assert!(error.to_string().contains("65536-byte safety limit"));
        assert!(!error.to_string().contains(&"z".repeat(64)));
    }

    #[test]
    fn resolved_transport_requires_a_complete_resolution() {
        let address = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
        assert!(
            super::HttpTransport::with_resolved_target(
                HttpTransportConfig::default(),
                "",
                &[address],
            )
            .is_err()
        );
        assert!(
            super::HttpTransport::with_resolved_target(
                HttpTransportConfig::default(),
                "probe.fixture.test",
                &[],
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn resolved_transport_pins_the_validated_host_for_the_request() {
        let app = Router::new().route(
            "/probe",
            post(|| async { Json(json!({"choices":[{"message":{"content":"pinned"}}]})) }),
        );
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind pinned target");
        let address = listener.local_addr().expect("pinned target address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("pinned target runs");
        });
        let transport = super::HttpTransport::with_resolved_target(
            HttpTransportConfig::default(),
            "probe.fixture.test",
            &[address],
        )
        .unwrap();
        let probe = super::OutboundProbe {
            kind: crate::ProbeKind::Identity,
            challenge_id: None,
            url: format!("http://probe.fixture.test:{}/probe", address.port()),
            headers: Default::default(),
            body: json!({"model":"fixture"}),
            context: None,
            demo_response: None,
            demo_tool_arguments: None,
        };
        let observation = transport
            .execute(&probe, Duration::from_secs(2))
            .await
            .expect("pinned host connects without a second DNS lookup");
        assert_eq!(observation.status_code, 200);
        assert_eq!(observation.text, "pinned");
    }

    #[tokio::test]
    async fn http_transport_never_follows_an_upstream_redirect() {
        let redirected_requests = Arc::new(AtomicUsize::new(0));
        let target_requests = Arc::clone(&redirected_requests);
        let target = Router::new().route(
            "/private",
            post(move || {
                let requests = Arc::clone(&target_requests);
                async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"choices":[{"message":{"content":"unexpected"}}]}))
                }
            }),
        );
        let target_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind redirect target");
        let target_address = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(target_listener, target)
                .await
                .expect("redirect target runs");
        });

        let redirect_location = format!("http://{target_address}/private");
        let source = Router::new().route(
            "/probe",
            post(move || {
                let redirect_location = redirect_location.clone();
                async move { (StatusCode::FOUND, [(header::LOCATION, redirect_location)]) }
            }),
        );
        let source_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind redirect source");
        let source_address = source_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(source_listener, source)
                .await
                .expect("redirect source runs");
        });

        let probe = super::OutboundProbe {
            kind: crate::ProbeKind::Identity,
            challenge_id: None,
            url: format!("http://{source_address}/probe"),
            headers: Default::default(),
            body: json!({"model":"fixture"}),
            context: None,
            demo_response: None,
            demo_tool_arguments: None,
        };
        let observation = super::HttpTransport::new()
            .execute(&probe, Duration::from_secs(2))
            .await
            .expect("redirect remains an observable upstream response");
        assert_eq!(observation.status_code, StatusCode::FOUND.as_u16());
        assert_eq!(redirected_requests.load(Ordering::SeqCst), 0);
    }
}
