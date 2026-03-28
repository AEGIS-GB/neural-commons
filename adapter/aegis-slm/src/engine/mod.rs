//! Engine trait for SLM inference.
//!
//! Five implementations:
//!   - `OllamaEngine`: HTTP client for Ollama API (`/api/generate`)
//!   - `OpenAiCompatEngine`: HTTP client for any OpenAI-compatible API (`/v1/chat/completions`)
//!     — works with LM Studio, vLLM, llama.cpp, text-generation-inference, LocalAI
//!   - `AnthropicEngine`: HTTP client for Anthropic Messages API (`/v1/messages`)
//!   - `HeuristicEngine`: Regex-based fallback (no model required)
//!   - `PromptGuardEngine`: ONNX classifier (ProtectAI DeBERTa-v2, 184M params)

pub mod anthropic;
pub mod heuristic;
pub mod ollama;
pub mod openai_compat;
#[cfg(feature = "prompt-guard")]
pub mod prompt_guard;

/// Engine trait for SLM inference.
pub trait SlmEngine: Send + Sync {
    /// Generate a screening analysis from the given prompt.
    /// Returns raw JSON string on success, or an error description.
    fn generate(&self, prompt: &str) -> Result<String, String>;
}
