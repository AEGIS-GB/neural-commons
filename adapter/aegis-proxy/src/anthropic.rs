//! Anthropic wire format parsing and provider detection.
//!
//! Isolates all Anthropic-specific knowledge to one module. When OpenAI
//! support is added in Phase 2, a parallel `openai.rs` module is added
//! without touching the core proxy logic.

use std::collections::HashMap;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

// ---------------------------------------------------------------------------
// Anthropic request types
// ---------------------------------------------------------------------------

/// Parsed Anthropic `/v1/messages` request body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnthropicRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(default)]
    pub system: Option<String>,
    pub max_tokens: u32,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub tools: Option<Vec<serde_json::Value>>,
}

/// A single message in the Anthropic conversation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Message {
    pub role: String,
    /// Content can be a string or an array of content blocks.
    pub content: MessageContent,
}

/// Anthropic message content — either a plain string or structured blocks.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// A single content block within a message.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub input: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

// ---------------------------------------------------------------------------
// Screen payload — what the SLM actually needs to analyze
// ---------------------------------------------------------------------------

/// Extracted content for SLM screening.
///
/// The SLM needs the actual conversation content, not the raw API payload
/// (which includes model name, max_tokens, etc. that waste SLM tokens).
#[derive(Debug, Clone)]
pub struct AnthropicScreenPayload {
    pub system: Option<String>,
    pub messages: Vec<ScreenMessage>,
    pub model: String,
}

/// A message extracted for screening.
#[derive(Debug, Clone)]
pub struct ScreenMessage {
    pub role: String,
    pub content: String,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse an Anthropic request body from raw bytes.
pub fn parse_request(body: &[u8]) -> Result<AnthropicRequest, serde_json::Error> {
    serde_json::from_slice(body)
}

/// Extract the screenable content from a parsed Anthropic request.
///
/// Concatenates all text content from messages and the system prompt
/// into a format the SLM can analyze without wasting tokens on API metadata.
pub fn extract_screen_payload(req: &AnthropicRequest) -> AnthropicScreenPayload {
    let messages = req
        .messages
        .iter()
        .map(|msg| {
            let content = match &msg.content {
                MessageContent::Text(s) => s.clone(),
                MessageContent::Blocks(blocks) => blocks
                    .iter()
                    .filter_map(|b| match b.block_type.as_str() {
                        "text" => b.text.clone(),
                        "tool_result" => b.content.clone(),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            ScreenMessage {
                role: msg.role.clone(),
                content,
            }
        })
        .collect();

    AnthropicScreenPayload {
        system: req.system.clone(),
        messages,
        model: req.model.clone(),
    }
}

/// Concatenate the screen payload into a single string for the SLM hook.
///
/// Extract last user message + trailing tool results for screening.
///
/// Same logic as `extract_user_content_from_json`: only the last user message
/// (actual human input) and any tool results after it (indirect injection).
/// System prompt, assistant, and earlier user messages are skipped.
pub fn screen_payload_to_string(payload: &AnthropicScreenPayload) -> String {
    // Find the last user message
    let last_user_idx = payload.messages.iter().rposition(|msg| msg.role == "user");

    let Some(idx) = last_user_idx else {
        return String::new();
    };

    let mut parts = Vec::new();
    parts.push(format!("[user] {}", payload.messages[idx].content));

    // Tool results after the last user message
    for msg in payload.messages.iter().skip(idx + 1) {
        if msg.role == "tool" {
            parts.push(format!("[tool] {}", msg.content));
        }
    }

    parts.join("\n")
}

/// Check if the request is a streaming request.
pub fn is_streaming(req: &AnthropicRequest) -> bool {
    req.stream
}

// ---------------------------------------------------------------------------
// Provider detection
// ---------------------------------------------------------------------------

/// Check if request headers contain the `anthropic-version` header.
pub fn has_anthropic_version_header(headers: &HashMap<String, String>) -> bool {
    headers.contains_key("anthropic-version")
}

/// Detected LLM provider from request headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedProvider {
    Anthropic,
    OpenAI,
    Unknown,
}

/// Detect the upstream provider from request headers.
///
/// - Anthropic: has `anthropic-version` header
/// - OpenAI: has `Authorization: Bearer sk-*` pattern
/// - Unknown: neither detected
pub fn detect_provider(headers: &HashMap<String, String>) -> DetectedProvider {
    if headers.contains_key("anthropic-version") {
        return DetectedProvider::Anthropic;
    }

    if let Some(auth) = headers.get("authorization")
        && auth.starts_with("Bearer sk-")
    {
        return DetectedProvider::OpenAI;
    }

    DetectedProvider::Unknown
}

/// Build the 422 error response for unsupported providers (D31-A).
pub fn unsupported_provider_response(detected: DetectedProvider) -> Response {
    let message = match detected {
        DetectedProvider::OpenAI => {
            "OpenAI provider detected but not yet supported. Phase 2 will add OpenAI support."
        }
        _ => "Unknown provider. Missing anthropic-version header.",
    };

    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "provider_not_supported",
            "message": message,
            "detected": format!("{:?}", detected),
            "supported": ["anthropic"],
            "docs": "https://docs.anthropic.com/en/api/messages"
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_request() {
        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Hello, Claude"}
            ]
        });
        let req = parse_request(body.to_string().as_bytes()).unwrap();
        assert_eq!(req.model, "claude-sonnet-4-20250514");
        assert_eq!(req.messages.len(), 1);
        assert!(!req.stream);
        assert!(req.system.is_none());
    }

    #[test]
    fn parse_streaming_request() {
        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "stream": true,
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });
        let req = parse_request(body.to_string().as_bytes()).unwrap();
        assert!(is_streaming(&req));
    }

    #[test]
    fn parse_request_with_system() {
        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": "You are a helpful assistant.",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });
        let req = parse_request(body.to_string().as_bytes()).unwrap();
        assert_eq!(req.system.as_deref(), Some("You are a helpful assistant."));
    }

    #[test]
    fn parse_request_with_content_blocks() {
        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What is this?"}
                    ]
                }
            ]
        });
        let req = parse_request(body.to_string().as_bytes()).unwrap();
        let payload = extract_screen_payload(&req);
        assert_eq!(payload.messages[0].content, "What is this?");
    }

    #[test]
    fn parse_tool_result_content() {
        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Check the weather"},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_123",
                            "content": "Temperature is 72F"
                        }
                    ]
                }
            ]
        });
        let req = parse_request(body.to_string().as_bytes()).unwrap();
        let payload = extract_screen_payload(&req);
        assert_eq!(payload.messages[1].content, "Temperature is 72F");
    }

    #[test]
    fn screen_payload_includes_last_user_only() {
        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": "Be helpful",
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"},
                {"role": "user", "content": "What is 2+2?"}
            ]
        });
        let req = parse_request(body.to_string().as_bytes()).unwrap();
        let payload = extract_screen_payload(&req);
        let text = screen_payload_to_string(&payload);
        // Only last user message (actual human input)
        assert!(text.contains("[user] What is 2+2?"));
        // Earlier user messages excluded (already screened in prior requests)
        assert!(
            !text.contains("[user] Hello"),
            "earlier user messages should be excluded"
        );
        // System excluded (validated via baseline, not injection screening)
        assert!(
            !text.contains("[system]"),
            "system prompt should be excluded from injection screening"
        );
        // Assistant excluded (self-generated)
        assert!(
            !text.contains("[assistant]"),
            "assistant messages should be excluded"
        );
    }

    #[test]
    fn has_anthropic_version_header_check() {
        let mut headers = HashMap::new();
        assert!(!has_anthropic_version_header(&headers));

        headers.insert("anthropic-version".to_string(), "2023-06-01".to_string());
        assert!(has_anthropic_version_header(&headers));
    }

    #[test]
    fn detect_provider_anthropic() {
        let mut headers = HashMap::new();
        headers.insert("anthropic-version".to_string(), "2023-06-01".to_string());
        assert_eq!(detect_provider(&headers), DetectedProvider::Anthropic);
    }

    #[test]
    fn detect_provider_openai() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer sk-abc123".to_string());
        assert_eq!(detect_provider(&headers), DetectedProvider::OpenAI);
    }

    #[test]
    fn detect_provider_unknown() {
        let headers = HashMap::new();
        assert_eq!(detect_provider(&headers), DetectedProvider::Unknown);
    }

    #[test]
    fn detect_provider_anthropic_takes_priority() {
        let mut headers = HashMap::new();
        headers.insert("anthropic-version".to_string(), "2023-06-01".to_string());
        headers.insert("authorization".to_string(), "Bearer sk-abc123".to_string());
        assert_eq!(detect_provider(&headers), DetectedProvider::Anthropic);
    }
}
