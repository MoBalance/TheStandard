use super::{OutboundProbe, ProbeTransport};
use crate::{CoreError, ProbeKind, ProbeObservation, StreamEventObservation, UsageMetrics};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

/// Deterministic in-process target used by the product demo and transport contract tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct DemoTransport;

#[async_trait]
impl ProbeTransport for DemoTransport {
    async fn execute(
        &self,
        probe: &OutboundProbe,
        _timeout: Duration,
    ) -> Result<ProbeObservation, CoreError> {
        let model = probe
            .body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("claude-sonnet-4-6");
        let anthropic = probe.headers.contains_key("x-api-key");
        let text = demo_text(probe, model);
        let input_tokens = probe
            .context
            .as_ref()
            .map_or(42, |metadata| metadata.visible_input_token_estimate + 26);
        let output_tokens = (text.chars().count() as u64).div_ceil(4).max(1);
        let response = if anthropic {
            anthropic_response(probe, model, &text, input_tokens, output_tokens)
        } else {
            openai_response(probe, model, &text, input_tokens, output_tokens)
        };
        let streaming = probe.body.get("stream").and_then(Value::as_bool) == Some(true);

        Ok(ProbeObservation {
            kind: probe.kind,
            challenge_id: probe.challenge_id.clone(),
            status_code: 200,
            latency_ms: match probe.kind {
                ProbeKind::ReasoningAttestation => 512,
                ProbeKind::ReasoningBudget => 366,
                ProbeKind::Context => 404,
                ProbeKind::Consistency => 338,
                ProbeKind::StreamIntegrity => 184,
                _ => 286,
            },
            ttft_ms: streaming.then_some(94),
            response,
            text: text.clone(),
            response_headers: BTreeMap::new(),
            stream_events: if streaming {
                demo_stream_events(model, &text, input_tokens, output_tokens)
            } else {
                Vec::new()
            },
            usage: UsageMetrics {
                input_tokens,
                output_tokens,
                ..UsageMetrics::default()
            },
            retry_count: 0,
            backoff_count: 0,
            context: probe.context.clone(),
        })
    }
}

fn demo_text(probe: &OutboundProbe, _model: &str) -> String {
    match probe.kind {
        ProbeKind::Identity => probe.demo_response.clone().unwrap_or_default(),
        ProbeKind::Behavior => probe.demo_response.clone().unwrap_or_default(),
        ProbeKind::ReasoningAttestation => probe.demo_response.clone().unwrap_or_default(),
        ProbeKind::ReasoningBudget => probe.demo_response.clone().unwrap_or_default(),
        ProbeKind::Knowledge => probe.demo_response.clone().unwrap_or_default(),
        ProbeKind::Document => {
            document_marker(&probe.body).unwrap_or_else(|| "document-marker-unavailable".into())
        }
        ProbeKind::ToolContract => String::new(),
        ProbeKind::Protocol => "{\"status\":\"ok\",\"checks\":3}".into(),
        ProbeKind::Context => probe.context.as_ref().map_or_else(String::new, |metadata| {
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
        }),
        ProbeKind::Consistency
        | ProbeKind::StreamIntegrity
        | ProbeKind::LongOutput
        | ProbeKind::CacheReuse
        | ProbeKind::InjectionOverhead
        | ProbeKind::KnowledgeCutoff
        | ProbeKind::WebSearch
        | ProbeKind::ReasoningIq
        | ProbeKind::ThinkingChain => probe.demo_response.clone().unwrap_or_default(),
    }
}

fn anthropic_response(
    probe: &OutboundProbe,
    model: &str,
    text: &str,
    input_tokens: u64,
    output_tokens: u64,
) -> Value {
    if probe.kind == ProbeKind::ToolContract {
        let arguments = probe
            .demo_tool_arguments
            .clone()
            .unwrap_or_else(|| json!({}));
        let tool_name = probe
            .body
            .pointer("/tool_choice/name")
            .and_then(Value::as_str)
            .unwrap_or("the_standard_record_demo");
        return json!({
            "id": "msg_the_standard_demo",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{
                "type": "tool_use",
                "id": "toolu_the_standard_demo",
                "name": tool_name,
                "input": arguments,
                "caller": {"kind": "direct"}
            }],
            "stop_reason": "tool_use",
            "stop_sequence": null,
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens}
        });
    }
    let content = if probe.kind == ProbeKind::ReasoningAttestation
        && message_count(&probe.body) == 1
    {
        json!([
            {"type": "thinking", "thinking": "Demo reasoning summary.", "signature": "R".repeat(128)},
            {"type": "text", "text": text}
        ])
    } else {
        json!([{"type": "text", "text": text}])
    };
    json!({
        "id": "msg_the_standard_demo",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens}
    })
}

fn openai_response(
    probe: &OutboundProbe,
    model: &str,
    text: &str,
    input_tokens: u64,
    output_tokens: u64,
) -> Value {
    if probe.kind == ProbeKind::ReasoningBudget {
        return json!({
            "id": "resp_the_standard_demo",
            "object": "response",
            "model": model,
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}]
            }],
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens}
        });
    }
    if probe.kind == ProbeKind::ToolContract {
        let arguments = serde_json::to_string(
            &probe
                .demo_tool_arguments
                .clone()
                .unwrap_or_else(|| json!({})),
        )
        .expect("demo tool arguments are serializable");
        let name = probe
            .body
            .pointer("/tool_choice/function/name")
            .and_then(Value::as_str)
            .unwrap_or("the_standard_record_demo");
        return json!({
            "id": "chatcmpl_the_standard_demo",
            "object": "chat.completion",
            "model": model,
            "choices": [{"message": {"role": "assistant", "content": null, "tool_calls": [{
                "id": "call_the_standard_demo",
                "type": "function",
                "function": {"name": name, "arguments": arguments}
            }]}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens}
        });
    }
    json!({
        "id": "chatcmpl_the_standard_demo",
        "object": "chat.completion",
        "model": model,
        "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": input_tokens, "completion_tokens": output_tokens}
    })
}

fn demo_stream_events(
    model: &str,
    text: &str,
    input_tokens: u64,
    output_tokens: u64,
) -> Vec<StreamEventObservation> {
    vec![
        StreamEventObservation {
            event: "message_start".into(),
            elapsed_ms: 20,
            data: json!({"type": "message_start", "message": {
                "id": "msg_the_standard_demo", "type": "message", "role": "assistant",
                "model": model, "content": [],
                "usage": {"input_tokens": input_tokens, "output_tokens": 1}
            }}),
        },
        StreamEventObservation {
            event: "content_block_start".into(),
            elapsed_ms: 30,
            data: json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        },
        StreamEventObservation {
            event: "content_block_delta".into(),
            elapsed_ms: 94,
            data: json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
        },
        StreamEventObservation {
            event: "content_block_stop".into(),
            elapsed_ms: 160,
            data: json!({"type": "content_block_stop", "index": 0}),
        },
        StreamEventObservation {
            event: "message_delta".into(),
            elapsed_ms: 180,
            data: json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": output_tokens}}),
        },
        StreamEventObservation {
            event: "message_stop".into(),
            elapsed_ms: 184,
            data: json!({"type": "message_stop"}),
        },
    ]
}

fn message_count(body: &Value) -> usize {
    body.get("messages")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn document_marker(body: &Value) -> Option<String> {
    let encoded = body
        .pointer("/messages/0/content")
        .and_then(Value::as_array)?
        .iter()
        .find(|item| item.get("type").and_then(Value::as_str) == Some("document"))?
        .pointer("/source/data")?
        .as_str()?;
    let bytes = BASE64.decode(encoded).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let start = text.find("THE-STANDARD-DOC-")?;
    let marker = text[start..]
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect::<String>();
    (!marker.is_empty()).then_some(marker)
}

#[cfg(test)]
mod tests {
    use super::{DemoTransport, document_marker};
    use crate::{ProbeKind, ProbeTransport};
    use serde_json::json;
    use std::{collections::BTreeMap, time::Duration};

    #[test]
    fn extracts_the_real_marker_from_an_embedded_document() {
        let body = json!({"messages": [{"content": [{"type": "document", "source": {
            "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"prefix THE-STANDARD-DOC-ABC123 suffix")
        }}]}]});
        assert_eq!(
            document_marker(&body).as_deref(),
            Some("THE-STANDARD-DOC-ABC123")
        );
    }

    #[tokio::test]
    async fn demo_transport_returns_protocol_complete_identity_response() {
        let probe = crate::OutboundProbe {
            kind: ProbeKind::Identity,
            challenge_id: None,
            url: "https://demo.example.com/v1/messages".into(),
            headers: BTreeMap::from([("x-api-key".into(), "demo".into())]),
            body: json!({"model": "claude-sonnet-4-6", "messages": [{"role": "user", "content": "identify"}]}),
            context: None,
            demo_response: Some(
                "I am claude-sonnet-4-6, a claude-family model served by anthropic.".into(),
            ),
            demo_tool_arguments: None,
        };
        let observation = DemoTransport
            .execute(&probe, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(observation.response["role"], "assistant");
        assert_eq!(observation.response["stop_reason"], "end_turn");
        assert!(observation.text.contains("claude-sonnet-4-6"));
    }
}
