//! Engine trait for SLM inference.
//!
//! Two implementations:
//!   - `OllamaEngine`: HTTP client for Ollama API (primary)
//!   - `HeuristicEngine`: Regex-based fallback (no model required)

pub mod heuristic;
pub mod ollama;

/// Engine trait for SLM inference.
pub trait SlmEngine: Send + Sync {
    /// Generate a screening analysis from the given prompt.
    /// Returns raw JSON string on success, or an error description.
    fn generate(&self, prompt: &str) -> Result<String, String>;
}
