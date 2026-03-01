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

/// Parse and validate SLM output.
/// Returns ParseError on ANY validation failure — no best-effort coercion.
pub fn parse_slm_output(
    raw_json: &str,
    engine: &EngineProfile,
) -> Result<SlmOutput, ParseError> {
    let output: SlmOutput = serde_json::from_str(raw_json)
        .map_err(|e| ParseError::InvalidJson(e.to_string()))?;

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
}
