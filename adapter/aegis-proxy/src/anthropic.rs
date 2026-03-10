//! Anthropic wire format parsing and provider detection.
//!
//! Isolates all Anthropic-specific knowledge to one module. When OpenAI
//! support is added in Phase 2, a parallel `openai.rs` module is added
//! without touching the core proxy logic.

use std::collections::HashMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
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
    let messages = req.messages.iter().map(|msg| {
        let content = match &msg.content {
            MessageContent::Text(s) => s.clone(),
            MessageContent::Blocks(blocks) => {
                blocks.iter()
                    .filter_map(|b| {
                        match b.block_type.as_str() {
                            "text" => b.text.clone(),
                            "tool_result" => b.content.clone(),
                            _ => None,
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        };
        ScreenMessage {
            role: msg.role.clone(),
            content,
        }
    }).collect();

    AnthropicScreenPayload {
        system: req.system.clone(),
        messages,
        model: req.model.clone(),
    }
}

/// Concatenate the screen payload into a single string for the SLM hook.
pub fn screen_payload_to_string(payload: &AnthropicScreenPayload) -> String {
    let mut parts = Vec::new();
    if let Some(ref system) = payload.system {
        parts.push(format!("[system] {system}"));
    }
    for msg in &payload.messages {
        parts.push(format!("[{}] {}", msg.role, msg.content));
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

/// Build the 422 error response for unsupported providers (D31-A).
pub fn unsupported_provider_response() -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({
        "error": "provider_not_supported",
        "message": "aegis-proxy Phase 1 supports Anthropic only",
        "supported": ["anthropic"],
        "docs": "https://docs.anthropic.com/en/api/messages"
    }))).into_response()
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
    fn extract_screen_payload_concatenates() {
        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": "Be helpful",
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there"}
            ]
        });
        let req = parse_request(body.to_string().as_bytes()).unwrap();
        let payload = extract_screen_payload(&req);
        let text = screen_payload_to_string(&payload);
        assert!(text.contains("[system] Be helpful"));
        assert!(text.contains("[user] Hello"));
        assert!(text.contains("[assistant] Hi there"));
    }

    #[test]
    fn has_anthropic_version_header_check() {
        let mut headers = HashMap::new();
        assert!(!has_anthropic_version_header(&headers));

        headers.insert("anthropic-version".to_string(), "2023-06-01".to_string());
        assert!(has_anthropic_version_header(&headers));
    }
}
