//! OpenAI-compatible HTTP client engine.
//!
//! Works with any server that implements the `/v1/chat/completions` endpoint:
//! LM Studio, vLLM, llama.cpp server, text-generation-inference, LocalAI, etc.
//!
//! Timeout: 30 seconds for inference.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::debug;

use super::SlmEngine;

const INFERENCE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ChatCompletionRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    temperature: f32,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Serialize)]
struct ResponseFormat {
    r#type: String,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: MessageContent,
}

#[derive(Deserialize)]
struct MessageContent {
    content: String,
}

/// OpenAI-compatible HTTP client engine.
pub struct OpenAiCompatEngine {
    url: String,
    model: String,
    client: reqwest::blocking::Client,
}

impl OpenAiCompatEngine {
    /// Create a new engine pointing at the given base URL and model.
    ///
    /// `base_url` should be the server root (e.g., `http://localhost:1234`).
    /// The `/v1/chat/completions` path is appended automatically.
    pub fn new(base_url: &str, model: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(INFERENCE_TIMEOUT)
            .build()
            .expect("failed to build reqwest blocking client");

        Self {
            url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            client,
        }
    }
}

impl SlmEngine for OpenAiCompatEngine {
    fn generate(&self, prompt: &str) -> Result<String, String> {
        let endpoint = format!("{}/v1/chat/completions", self.url);

        // Don't send response_format — not all servers support json_object
        // (LM Studio requires json_schema, vLLM may not support it at all).
        // The screening prompt already instructs the model to output JSON.
        let request_body = ChatCompletionRequest {
            model: &self.model,
            messages: vec![ChatMessage {
                role: "user",
                content: prompt,
            }],
            temperature: 0.0,
            max_tokens: 256,
            response_format: None,
        };

        debug!(
            model = %self.model,
            url = %endpoint,
            prompt_len = prompt.len(),
            "sending inference request to OpenAI-compatible server"
        );

        let resp = self
            .client
            .post(&endpoint)
            .json(&request_body)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    format!(
                        "SLM inference timed out after {}s for model '{}'",
                        INFERENCE_TIMEOUT.as_secs(),
                        self.model
                    )
                } else {
                    format!("SLM inference request failed: {e}")
                }
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!(
                "SLM server returned {status}: {body}"
            ));
        }

        let chat_resp: ChatCompletionResponse = resp.json().map_err(|e| {
            format!("failed to parse SLM response: {e}")
        })?;

        chat_resp
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| "SLM returned empty choices".to_string())
    }
}
