//! Anthropic Messages API client engine.
//!
//! Calls the Anthropic `/v1/messages` endpoint for SLM screening.
//! API key is read from `ANTHROPIC_API_KEY` environment variable.
//!
//! Timeout: 30 seconds for inference.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::debug;

use super::SlmEngine;

const INFERENCE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: String,
}

/// Anthropic Messages API engine.
pub struct AnthropicEngine {
    url: String,
    model: String,
    api_key: String,
    client: reqwest::blocking::Client,
}

impl AnthropicEngine {
    /// Create a new engine pointing at the Anthropic API.
    ///
    /// `base_url` defaults to `https://api.anthropic.com`.
    /// `api_key` if None, reads from `ANTHROPIC_API_KEY` env var.
    pub fn new(base_url: &str, model: &str, api_key: Option<&str>) -> Self {
        let key = api_key
            .map(String::from)
            .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
            .unwrap_or_default();

        let client = reqwest::blocking::Client::builder()
            .timeout(INFERENCE_TIMEOUT)
            .build()
            .expect("failed to build reqwest blocking client");

        Self {
            url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key: key,
            client,
        }
    }
}

impl SlmEngine for AnthropicEngine {
    fn generate(&self, prompt: &str) -> Result<String, String> {
        if self.api_key.is_empty() {
            return Err(
                "ANTHROPIC_API_KEY not set. Required for anthropic SLM engine.".to_string(),
            );
        }

        let endpoint = format!("{}/v1/messages", self.url);

        let request_body = MessagesRequest {
            model: &self.model,
            max_tokens: 256,
            messages: vec![Message {
                role: "user",
                content: prompt,
            }],
        };

        debug!(
            model = %self.model,
            url = %endpoint,
            prompt_len = prompt.len(),
            "sending inference request to Anthropic Messages API"
        );

        let resp = self
            .client
            .post(&endpoint)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    format!(
                        "Anthropic inference timed out after {}s for model '{}'",
                        INFERENCE_TIMEOUT.as_secs(),
                        self.model
                    )
                } else {
                    format!("Anthropic inference request failed: {e}")
                }
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!("Anthropic API returned {status}: {body}"));
        }

        let messages_resp: MessagesResponse = resp
            .json()
            .map_err(|e| format!("failed to parse Anthropic response: {e}"))?;

        messages_resp
            .content
            .into_iter()
            .next()
            .map(|c| c.text)
            .ok_or_else(|| "Anthropic returned empty content".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_creation() {
        let engine = AnthropicEngine::new(
            "https://api.anthropic.com",
            "claude-haiku-4-5-20251001",
            Some("test-key"),
        );
        assert_eq!(engine.url, "https://api.anthropic.com");
        assert_eq!(engine.model, "claude-haiku-4-5-20251001");
        assert_eq!(engine.api_key, "test-key");
    }

    #[test]
    fn url_trailing_slash_trimmed() {
        let engine = AnthropicEngine::new("https://api.anthropic.com/", "test-model", Some("key"));
        assert_eq!(engine.url, "https://api.anthropic.com");
    }

    // Integration test (requires API key). Run with: cargo test -p aegis-slm -- --ignored
    #[test]
    #[ignore]
    fn integration_generate() {
        let engine = AnthropicEngine::new(
            "https://api.anthropic.com",
            "claude-haiku-4-5-20251001",
            None,
        );
        let result = engine.generate("Respond with JSON: {\"greeting\": \"hello\"}");
        println!("generate result: {result:?}");
        assert!(result.is_ok());
    }
}
