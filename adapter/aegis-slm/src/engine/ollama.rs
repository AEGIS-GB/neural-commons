//! Ollama HTTP client engine.
//!
//! Uses blocking reqwest to POST to Ollama's `/api/generate` endpoint.
//! The caller (loopback) wraps this in `spawn_blocking` if needed.
//!
//! Timeout: 30 seconds for inference (small models on local hardware).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::debug;

use super::SlmEngine;

/// Ollama inference timeout (30 seconds).
const INFERENCE_TIMEOUT: Duration = Duration::from_secs(30);

/// Ollama generate request body.
#[derive(Serialize)]
struct OllamaGenerateRequest<'a> {
    model: &'a str,
    prompt: &'a str,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'a str>,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaOptions {
    num_predict: u32,
    /// Limit context window for SLM screening to avoid KvSize mismatch
    /// with the main chat runner. Without this, Ollama allocates the model's
    /// full context (e.g. 262144 for Qwen3), which forces a runner restart
    /// when a subsequent /api/chat arrives with a different KvSize.
    num_ctx: u32,
}

/// Ollama generate response body.
#[derive(Deserialize)]
struct OllamaGenerateResponse {
    response: String,
    /// Qwen3 "thinking" models put their output here instead of `response`.
    #[serde(default)]
    thinking: Option<String>,
}

/// Ollama tags response (for model listing).
#[derive(Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModelInfo>,
}

/// Individual model info from /api/tags.
#[derive(Deserialize)]
struct OllamaModelInfo {
    name: String,
}

/// Ollama HTTP client engine.
pub struct OllamaEngine {
    url: String,
    model: String,
    client: reqwest::blocking::Client,
}

impl OllamaEngine {
    /// Create a new Ollama engine pointing at the given URL and model.
    pub fn new(ollama_url: &str, model: &str) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(INFERENCE_TIMEOUT)
            .build()
            .expect("failed to build reqwest blocking client");

        Self {
            url: ollama_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            client,
        }
    }

    /// Check if the model is available in Ollama.
    /// Returns Ok(()) if the model is found, or an error suggesting `ollama pull`.
    pub fn ensure_model(&self) -> Result<(), String> {
        let tags_url = format!("{}/api/tags", self.url);

        let resp = self
            .client
            .get(&tags_url)
            .timeout(Duration::from_secs(5))
            .send()
            .map_err(|e| {
                format!(
                    "failed to connect to Ollama at {}: {e}. Is Ollama running?",
                    self.url
                )
            })?;

        if !resp.status().is_success() {
            return Err(format!(
                "Ollama /api/tags returned status {}",
                resp.status()
            ));
        }

        let tags: OllamaTagsResponse = resp
            .json()
            .map_err(|e| format!("failed to parse Ollama tags response: {e}"))?;

        // Check if model is available (exact match or prefix match for tagged models)
        let model_found = tags
            .models
            .iter()
            .any(|m| m.name == self.model || m.name.starts_with(&format!("{}:", self.model)));

        if model_found {
            debug!(model = %self.model, "Ollama model available");
            Ok(())
        } else {
            let available: Vec<&str> = tags.models.iter().map(|m| m.name.as_str()).collect();
            Err(format!(
                "model '{}' not found in Ollama. Available: {:?}. Run: ollama pull {}",
                self.model, available, self.model
            ))
        }
    }
}

impl SlmEngine for OllamaEngine {
    fn generate(&self, prompt: &str) -> Result<String, String> {
        // First, check if the model exists
        self.ensure_model()?;

        let generate_url = format!("{}/api/generate", self.url);

        // aegis-screen models output plain SAFE/DANGEROUS — don't force JSON format.
        // Generic models output schema_version JSON — force JSON format.
        let is_aegis = crate::prompt::is_aegis_screen_model(&self.model);
        let request_body = OllamaGenerateRequest {
            model: &self.model,
            prompt,
            stream: false,
            format: if is_aegis { None } else { Some("json") },
            options: OllamaOptions {
                num_predict: if is_aegis { 5 } else { 256 },
                num_ctx: 32768,
            },
        };

        debug!(
            model = %self.model,
            url = %generate_url,
            prompt_len = prompt.len(),
            "sending inference request to Ollama"
        );

        let resp = self
            .client
            .post(&generate_url)
            .json(&request_body)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    format!(
                        "Ollama inference timed out after {}s for model '{}'",
                        INFERENCE_TIMEOUT.as_secs(),
                        self.model
                    )
                } else {
                    format!("Ollama inference request failed: {e}")
                }
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(format!("Ollama generate returned status {status}: {body}"));
        }

        let response: OllamaGenerateResponse = resp
            .json()
            .map_err(|e| format!("failed to parse Ollama generate response: {e}"))?;

        // Qwen3 thinking models put output in `thinking` field with empty `response`.
        // Fall back to `thinking` content when `response` is empty.
        let output = if response.response.is_empty() {
            response.thinking.unwrap_or_default()
        } else {
            response.response
        };

        debug!(response_len = output.len(), "Ollama inference complete");

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_creation() {
        let engine = OllamaEngine::new("http://localhost:11434", "llama3.2:1b");
        assert_eq!(engine.url, "http://localhost:11434");
        assert_eq!(engine.model, "llama3.2:1b");
    }

    #[test]
    fn url_trailing_slash_trimmed() {
        let engine = OllamaEngine::new("http://localhost:11434/", "test-model");
        assert_eq!(engine.url, "http://localhost:11434");
    }

    // Integration tests (require running Ollama) are skipped by default.
    // Run with: cargo test -p aegis-slm -- --ignored
    #[test]
    #[ignore]
    fn integration_ensure_model() {
        let engine = OllamaEngine::new("http://localhost:11434", "llama3.2:1b");
        let result = engine.ensure_model();
        println!("ensure_model result: {result:?}");
    }

    #[test]
    #[ignore]
    fn integration_generate() {
        let engine = OllamaEngine::new("http://localhost:11434", "llama3.2:1b");
        let result = engine.generate("Say hello in JSON format: {\"greeting\": \"...\"}");
        println!("generate result: {result:?}");
        assert!(result.is_ok());
    }
}
