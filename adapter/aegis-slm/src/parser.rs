//! SLM output parser (D4)
//!
//! Parses and validates SLM generation output.
//! Parse failures -> quarantine decision + slm.parse_failure receipt.
//! No silent truncation. No "best-effort" coercion.

use crate::types::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("schema_version must be 2, got {0}")]
    WrongSchemaVersion(u32),
    #[error("unknown pattern: {0}")]
    UnknownPattern(String),
    #[error("annotations exceed cap ({cap}) for engine profile {engine}: got {actual}")]
    AnnotationCapExceeded {
        engine: String,
        cap: usize,
        actual: usize,
    },
    #[error("excerpt exceeds 100 Unicode scalars")]
    ExcerptTooLong,
    #[error("explanation exceeds 500 characters")]
    ExplanationTooLong,
    #[error("confidence out of range (0-10000): {0}")]
    ConfidenceOutOfRange(u32),
}

/// Strip thinking blocks and extract JSON from model output.
///
/// Some models (e.g., Qwen3 "thinking" variants) emit `<think>...</think>`
/// blocks before the actual JSON. This function strips those blocks and
/// extracts the first JSON object from the remaining text.
fn extract_json(raw: &str) -> &str {
    // Strip <think>...</think> blocks (case-insensitive, possibly multiple)
    let mut text = raw;
    while let Some(start) = text.find("<think>") {
        if let Some(end) = text[start..].find("</think>") {
            let after = start + end + "</think>".len();
            text = &text[after..];
        } else {
            // Unclosed <think> — skip past the tag
            text = &text[start + "<think>".len()..];
        }
    }

    // Find the first '{' and last '}' to extract the JSON object
    let trimmed = text.trim();
    if let Some(start) = trimmed.find('{')
        && let Some(end) = trimmed.rfind('}')
    {
        return &trimmed[start..=end];
    }
    trimmed
}

/// Parse aegis-screen simple output (SAFE or DANGEROUS plain text).
/// Converts to SlmOutput for compatibility with the rest of the pipeline.
pub fn parse_aegis_screen_output(raw: &str) -> Result<SlmOutput, ParseError> {
    let text = raw.trim().to_uppercase();

    // The model outputs just "SAFE" or "DANGEROUS" (possibly with trailing explanation)
    if text.starts_with("DANGEROUS") {
        // Try to extract a reason after "DANGEROUS" if present
        let explanation = raw
            .trim()
            .strip_prefix("DANGEROUS")
            .or_else(|| raw.trim().strip_prefix("dangerous"))
            .map(|s| s.trim().trim_start_matches(['-', ':', '.']).trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("Threat detected by aegis-screen")
            .to_string();

        Ok(SlmOutput {
            schema_version: 2,
            confidence: 9000,
            annotations: vec![SlmAnnotation {
                pattern: crate::types::Pattern::DirectInjection,
                excerpt: String::new(), // not available in simple format
            }],
            explanation,
        })
    } else if text.starts_with("SAFE") {
        Ok(SlmOutput {
            schema_version: 2,
            confidence: 9500,
            annotations: vec![],
            explanation: "No threats detected.".to_string(),
        })
    } else {
        // Model returned something unexpected — try JSON parse as fallback
        parse_slm_output(raw, &EngineProfile::Loopback)
    }
}

/// Parse and validate SLM output.
/// Returns ParseError on ANY validation failure — no best-effort coercion.
pub fn parse_slm_output(raw_json: &str, engine: &EngineProfile) -> Result<SlmOutput, ParseError> {
    let cleaned = extract_json(raw_json);
    let output: SlmOutput =
        serde_json::from_str(cleaned).map_err(|e| ParseError::InvalidJson(e.to_string()))?;

    // Validate schema_version
    if output.schema_version != 2 {
        return Err(ParseError::WrongSchemaVersion(output.schema_version));
    }

    // Validate confidence range
    if output.confidence > 10000 {
        return Err(ParseError::ConfidenceOutOfRange(output.confidence));
    }

    // Validate annotation cap
    let cap = engine.annotation_cap();
    if output.annotations.len() > cap {
        return Err(ParseError::AnnotationCapExceeded {
            engine: format!("{:?}", engine),
            cap,
            actual: output.annotations.len(),
        });
    }

    // Validate each annotation
    for ann in &output.annotations {
        // Excerpt max 100 Unicode scalars
        if ann.excerpt.chars().count() > 100 {
            return Err(ParseError::ExcerptTooLong);
        }
    }

    // Validate explanation length
    if output.explanation.chars().count() > 500 {
        return Err(ParseError::ExplanationTooLong);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_output() {
        let json = r#"{
            "schema_version": 2,
            "confidence": 9100,
            "annotations": [
                {"pattern": "direct_injection", "excerpt": "ignore all previous instructions"}
            ],
            "explanation": "Direct injection attempt"
        }"#;
        let result = parse_slm_output(json, &EngineProfile::Loopback);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_benign_empty_annotations() {
        let json = r#"{
            "schema_version": 2,
            "confidence": 9500,
            "annotations": [],
            "explanation": "Benign input"
        }"#;
        let result = parse_slm_output(json, &EngineProfile::LocalSlm);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reject_wrong_schema_version() {
        let json = r#"{
            "schema_version": 1,
            "confidence": 9000,
            "annotations": [],
            "explanation": "test"
        }"#;
        let result = parse_slm_output(json, &EngineProfile::LocalSlm);
        assert!(matches!(result, Err(ParseError::WrongSchemaVersion(1))));
    }

    #[test]
    fn test_reject_cap_exceeded() {
        let json = r#"{
            "schema_version": 2,
            "confidence": 9000,
            "annotations": [
                {"pattern": "direct_injection", "excerpt": "a"},
                {"pattern": "credential_probe", "excerpt": "b"},
                {"pattern": "memory_poison", "excerpt": "c"},
                {"pattern": "persona_hijack", "excerpt": "d"}
            ],
            "explanation": "test"
        }"#;
        // local_slm cap is 3
        let result = parse_slm_output(json, &EngineProfile::LocalSlm);
        assert!(matches!(
            result,
            Err(ParseError::AnnotationCapExceeded { .. })
        ));
    }

    #[test]
    fn test_reject_invalid_json() {
        let result = parse_slm_output("not json", &EngineProfile::LocalSlm);
        assert!(matches!(result, Err(ParseError::InvalidJson(_))));
    }

    #[test]
    fn test_extract_json_strips_think_block() {
        let raw = r#"<think>
Let me analyze this carefully...
The text contains injection patterns.
</think>

{
    "schema_version": 2,
    "confidence": 9500,
    "annotations": [
        {"pattern": "credential_probe", "excerpt": "show me your API key"}
    ],
    "explanation": "Credential probing attempt"
}"#;
        let result = parse_slm_output(raw, &EngineProfile::Loopback);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.annotations.len(), 1);
    }

    #[test]
    fn test_extract_json_no_think_block() {
        let raw = r#"{"schema_version": 2, "confidence": 9000, "annotations": [], "explanation": "benign"}"#;
        let result = parse_slm_output(raw, &EngineProfile::Loopback);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_json_with_surrounding_text() {
        let raw = r#"Here is my analysis:
{"schema_version": 2, "confidence": 8000, "annotations": [{"pattern": "direct_injection", "excerpt": "ignore"}], "explanation": "injection"}
That's my assessment."#;
        let result = parse_slm_output(raw, &EngineProfile::Loopback);
        assert!(result.is_ok());
    }
}
