//! End-to-end `web_search` evidence against a local mock HTTP upstream.
//!
//! These tests drive the real engine and the real HTTP transport against a
//! loopback responder that speaks the Anthropic messages shape. They assert the
//! three contract points that a fixture-only test cannot cover:
//!
//! 1. the outbound body carries the protocol shape declared by the rules,
//! 2. a response with a real search-execution marker and source URLs passes,
//! 3. a response without source URLs is an unsupported skip, never a failure.

use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use the_standard::{
    CoreRuleBundle, Engine, EngineConfig, EvidenceBasis, EvidenceStatus, HttpTransport, ProbeMode,
    ProbeRequest, Protocol,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const WEB_SECTION: &str = "web";

fn rule_bundle() -> Arc<CoreRuleBundle> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../SanBiao/rules/the-standard/stable.json");
    let bytes = std::fs::read(path).expect("the shared rule document is readable");
    Arc::new(
        CoreRuleBundle::from_document(&bytes, None).expect("the shared rule document is valid"),
    )
}

fn engine() -> Engine {
    Engine::new(EngineConfig {
        rule_bundle: Some(rule_bundle()),
        // A local mock never throttles, so retries would only hide mistakes.
        max_retries: 0,
        retry_backoff: Duration::ZERO,
        request_timeout: Duration::from_secs(5),
        quick_timeout: Duration::from_secs(5),
        standard_timeout: Duration::from_secs(10),
        full_timeout: Duration::from_secs(10),
        ..EngineConfig::default()
    })
}

fn detection_request(address: SocketAddr) -> ProbeRequest {
    ProbeRequest {
        base_url: format!("http://{address}"),
        api_key: "test-key".into(),
        model: "claude-sonnet-4-6".into(),
        protocol: Protocol::Anthropic,
        mode: ProbeMode::Standard,
        parameters: Default::default(),
        sections: vec![WEB_SECTION.into()],
    }
}

/// A loopback HTTP responder that records every request body it receives.
struct MockUpstream {
    address: SocketAddr,
    bodies: Arc<Mutex<Vec<Value>>>,
}

impl MockUpstream {
    async fn start(response: Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the mock upstream binds a loopback port");
        let address = listener
            .local_addr()
            .expect("the mock upstream has an address");
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&bodies);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                let response = response.clone();
                tokio::spawn(async move {
                    if let Some(body) = read_request(&mut socket).await {
                        recorded
                            .lock()
                            .expect("the recording lock is healthy")
                            .push(body);
                    }
                    let payload = response.to_string();
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        Self { address, bodies }
    }

    fn bodies(&self) -> Vec<Value> {
        self.bodies
            .lock()
            .expect("the recording lock is healthy")
            .clone()
    }
}

async fn read_request(socket: &mut TcpStream) -> Option<Value> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4_096];
    let body_start = loop {
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
        if buffer.len() > 1 << 20 {
            return None;
        }
    };
    let headers = String::from_utf8_lossy(&buffer[..body_start]).to_ascii_lowercase();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or_default();
    while buffer.len() < body_start + content_length {
        let read = socket.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    serde_json::from_slice(&buffer[body_start..body_start + content_length]).ok()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

async fn detect(upstream: &MockUpstream) -> the_standard::DetectionReport {
    engine()
        .detect(detection_request(upstream.address), &HttpTransport::new())
        .await
        .expect("the mock upstream answers every probe")
}

fn web_search_evidence(report: &the_standard::DetectionReport) -> the_standard::DetectorEvidence {
    report
        .evidence
        .iter()
        .find(|item| item.name == "web_search")
        .expect("the web section produced web_search evidence")
        .clone()
}

#[tokio::test]
async fn web_search_request_carries_the_rule_declared_body_patch() {
    let rules = rule_bundle();
    let anthropic = rules
        .rules
        .probes
        .web_search
        .protocols
        .iter()
        .find(|entry| entry.protocol == Protocol::Anthropic)
        .expect("the rules declare an anthropic web-search shape");
    let upstream = MockUpstream::start(json!({
        "id": "msg_mock",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-6",
        "content": [{"type": "text", "text": "Iceland has about 390000 residents."}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 120, "output_tokens": 24}
    }))
    .await;
    let report = detect(&upstream).await;

    let bodies = upstream.bodies();
    assert_eq!(bodies.len(), 1, "the web section sends exactly one probe");
    let body = &bodies[0];
    // (a) Every key declared by the rule document reached the wire unmodified.
    for (key, value) in &anthropic.body_patch {
        assert_eq!(&body[key], value, "the outbound body must carry `{key}`");
    }
    assert_eq!(
        body["max_tokens"],
        json!(rules.rules.probes.web_search.max_tokens)
    );
    assert_eq!(
        body["messages"][0]["content"],
        json!(rules.rules.probes.web_search.prompt)
    );
    assert_eq!(report.mode, ProbeMode::Standard);
}

#[tokio::test]
async fn web_search_passes_with_an_execution_marker_and_source_urls() {
    let upstream = MockUpstream::start(json!({
        "id": "msg_mock",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-6",
        "content": [
            {
                "type": "web_search_tool_result",
                "tool_use_id": "srvtoolu_mock",
                "citations": [{"url": "https://example.com/iceland-population"}]
            },
            {"type": "text", "text": "Iceland has about 390000 residents."}
        ],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 140, "output_tokens": 32}
    }))
    .await;
    let report = detect(&upstream).await;
    let evidence = web_search_evidence(&report);

    assert_eq!(evidence.status, EvidenceStatus::Pass);
    assert_eq!(evidence.basis, EvidenceBasis::Observed);
    assert_eq!(evidence.details["executed"], json!(true));
    assert_eq!(evidence.details["sourceCount"], json!(1));
    assert_eq!(
        evidence.details["sources"],
        json!(["https://example.com/iceland-population"])
    );
    assert_eq!(evidence.details["mode"], json!("native_tool"));
    assert!(evidence.weight > 0.0);
    // The evidence is comparable only through the rules that produced it.
    assert_eq!(report.rules.version, rule_bundle().provenance.version);
}

#[tokio::test]
async fn web_search_without_source_urls_is_an_unsupported_skip() {
    let upstream = MockUpstream::start(json!({
        "id": "msg_mock",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-6",
        "content": [
            // The execution marker alone is not enough: no URL was returned.
            {"type": "web_search_tool_result", "tool_use_id": "srvtoolu_mock", "citations": []},
            {"type": "text", "text": "Iceland has about 390000 residents."}
        ],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 140, "output_tokens": 32}
    }))
    .await;
    let report = detect(&upstream).await;
    let evidence = web_search_evidence(&report);

    assert_eq!(evidence.status, EvidenceStatus::Skip);
    assert_eq!(evidence.basis, EvidenceBasis::Unsupported);
    assert_eq!(evidence.weight, 0.0);
    assert_eq!(evidence.score, 0.0);
    assert_eq!(evidence.details["executed"], json!(true));
    assert_eq!(evidence.details["sourceCount"], json!(0));
    assert_eq!(evidence.details["sources"], json!([]));
    // A skipped detector only lowers coverage; it never fails the detection.
    assert_eq!(report.coverage.unverified_count, 1);
    assert_eq!(report.coverage.verified_weight, 0.0);
}
