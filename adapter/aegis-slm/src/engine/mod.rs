//! Engine trait for SLM inference.
//!
//! Three implementations:
//!   - `OllamaEngine`: HTTP client for Ollama API (`/api/generate`)
//!   - `OpenAiCompatEngine`: HTTP client for any OpenAI-compatible API (`/v1/chat/completions`)
//!     — works with LM Studio, vLLM, llama.cpp, text-generation-inference, LocalAI
//!   - `HeuristicEngine`: Regex-based fallback (no model required)

pub mod heuristic;
pub mod ollama;
pub mod openai_compat;

/// Engine trait for SLM inference.
pub trait SlmEngine: Send + Sync {
    /// Generate a screening analysis from the given prompt.
    /// Returns raw JSON string on success, or an error description.
    fn generate(&self, prompt: &str) -> Result<String, String>;
}
