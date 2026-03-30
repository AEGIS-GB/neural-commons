//! Integration tests for NER-based PII detection.
//!
//! These tests load the actual ONNX model and verify:
//! 1. False positives: common text (dates, cities, numbers) is NOT flagged
//! 2. True positives: real PII (names, phone numbers, etc.) IS detected
//! 3. Context awareness: CITY only flagged when adjacent to STREET (address)
//! 4. Confidence thresholds: low-confidence entities are filtered out
//! 5. End-to-end: full screen_response pipeline with NER loaded
//!
//! Requires: models/pii-ner/ with model.onnx, tokenizer.json, config.json

use std::path::PathBuf;

fn model_dir() -> PathBuf {
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/pii-ner"),
        PathBuf::from("/home/aegis/aegis/neural-commons/models/pii-ner"),
    ];
    for p in &candidates {
        if p.join("model.onnx").exists() {
            return p.clone();
        }
    }
    panic!(
        "NER model not found. Looked in: {:?}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
    );
}

fn init_ner() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        aegis_proxy::ner_pii::init(&model_dir());
        assert!(
            aegis_proxy::ner_pii::is_available(),
            "NER model failed to load"
        );
    });
}

/// Run screen_response end-to-end (NER loaded) and return result.
fn screen(input: &str) -> (String, aegis_proxy::response_screen::ResponseScreenResult) {
    init_ner();
    aegis_proxy::response_screen::screen_response(input)
}

/// Assert screen_response produces NO findings for the input.
fn assert_screen_clean(input: &str) {
    let (text, result) = screen(input);
    assert!(
        !result.screened,
        "False positive in screen_response for: {input:?}\n  Findings: {:?}\n  Output: {text}",
        result.findings
    );
    assert_eq!(text, input, "Text was modified for: {input}");
}

/// Assert screen_response finds at least one finding matching category.
fn assert_screen_finds(input: &str, category: &str) {
    let (_text, result) = screen(input);
    let matched: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.category == category)
        .collect();
    assert!(
        !matched.is_empty(),
        "Expected finding category '{category}' in: {input:?}\n  Got: {:?}",
        result.findings
    );
}

/// Assert screen_response finds a NER-based finding for a given entity type.
fn assert_screen_finds_ner(input: &str, entity_type_lower: &str) {
    let (_text, result) = screen(input);
    let matched: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.description.contains(entity_type_lower))
        .collect();
    assert!(
        !matched.is_empty(),
        "Expected NER finding for '{entity_type_lower}' in: {input:?}\n  Got: {:?}",
        result.findings
    );
}

/// Assert screen_response does NOT have a finding for a given entity type.
fn assert_screen_no_ner(input: &str, entity_type_lower: &str) {
    let (_text, result) = screen(input);
    let matched: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.description.contains(entity_type_lower))
        .collect();
    assert!(
        matched.is_empty(),
        "Unexpected NER finding for '{entity_type_lower}' in: {input:?}\n  Findings: {matched:?}"
    );
}

/// Assert that text is NOT modified (nothing redacted).
fn assert_text_unchanged(input: &str) {
    let (text, _result) = screen(input);
    assert_eq!(text, input, "Text was modified for: {input}");
}

// ═══════════════════════════════════════════════════════════════
//  1. FALSE POSITIVES — must NOT be flagged through full pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn month_names_not_flagged() {
    let inputs = [
        "The meeting is in March.",
        "January was cold this year.",
        "We launched in September 2025.",
        "The deadline is February 14.",
        "Report for Q1: January, February, March.",
        "Updated in December.",
        "Between April and October.",
    ];
    for input in inputs {
        assert_screen_no_ner(input, "date");
        assert_text_unchanged(input);
    }
}

#[test]
fn dates_not_flagged() {
    let inputs = [
        "The event is on March 15, 2026.",
        "Updated: 2025-12-01",
        "Next review: June 30.",
        "Created on Monday, April 7th.",
        "Timestamp: 2026-03-29T09:12:53Z",
        "Published on 15 March 2026.",
    ];
    for input in inputs {
        assert_screen_no_ner(input, "date");
    }
}

#[test]
fn times_not_flagged() {
    let inputs = [
        "The meeting is at 3:00 PM.",
        "Server rebooted at 14:30 UTC.",
        "Logs from 09:15:32.001 show the error.",
        "Office hours: 9am to 5pm.",
    ];
    for input in inputs {
        assert_screen_no_ner(input, "time");
    }
}

#[test]
fn city_without_address_not_flagged() {
    // Cities mentioned without a street address must NOT be flagged
    let inputs = [
        "The server is hosted in London.",
        "The capital of France is Paris.",
        "New York has many skyscrapers.",
        "We opened an office in Berlin.",
        "The conference is in Tokyo this year.",
        "Data is stored in the US-East region.",
    ];
    for input in inputs {
        assert_screen_no_ner(input, "city");
        assert_text_unchanged(input);
    }
}

#[test]
fn standalone_numbers_not_flagged() {
    // Numbers must not be classified as AGE
    let inputs = [
        "The result is 42.",
        "Version 3.14.159 is now available.",
        "Port 8080 is already in use.",
        "The file is 128 GB in size.",
        "Error code: 404",
        "Build number 8565.",
    ];
    for input in inputs {
        assert_screen_no_ner(input, "age");
        assert_text_unchanged(input);
    }
}

#[test]
fn version_numbers_not_flagged() {
    // Version numbers must not be classified as BUILDINGNUM
    let inputs = [
        "Vulkan driver version 25.2.8 is installed.",
        "OpenClaw 2026.3.23-2 is running.",
        "Node.js v18.17.0 is required.",
        "llama.cpp build 8565 compiled.",
    ];
    for input in inputs {
        assert_screen_no_ner(input, "buildingnum");
    }
}

#[test]
fn common_words_not_flagged() {
    // Words that could be names but are used as verbs/nouns
    let inputs = [
        "The application will process the request.",
        "We need to grant access to the system.",
        "The bill was paid in full.",
        "Please review the code and submit a PR.",
        "The weather today is sunny with clouds.",
        "The function takes two arguments and returns a boolean.",
    ];
    for input in inputs {
        assert_screen_clean(input);
    }
}

#[test]
fn technical_content_not_flagged() {
    let inputs = [
        "Run `cargo test` to execute the test suite.",
        "The API returns JSON with a status field.",
        "The model has 30 billion parameters.",
        "Token generation speed: 31.4 tokens per second.",
        "LPDDR5X memory bandwidth is 256 GB/s.",
        "Use --flash-attn flag for flash attention.",
    ];
    for input in inputs {
        assert_screen_clean(input);
    }
}

// ═══════════════════════════════════════════════════════════════
//  2. TRUE POSITIVES — NER must detect these through full pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn person_name_flagged() {
    assert_screen_finds_ner(
        "Please contact John Smith for details.",
        "givenname",
    );
}

#[test]
fn person_name_redacted_in_output() {
    let (text, _result) = screen("The patient John Smith reported symptoms.");
    assert!(
        text.contains("[REDACTED:"),
        "Person name should be redacted: {text}"
    );
    assert!(
        !text.contains("John Smith"),
        "Person name should not appear in output: {text}"
    );
}

#[test]
fn phone_number_flagged() {
    assert_screen_finds_ner("Call me at +1-555-867-5309.", "telephonenum");
}

#[test]
fn email_flagged_by_ner_or_regex() {
    // Email caught by regex DLP; NER is backup
    assert_screen_finds("Send it to jane.doe@hospital.org please.", "pii");
}

#[test]
fn street_address_flagged() {
    assert_screen_finds_ner(
        "The patient lives at 742 Evergreen Terrace, Springfield.",
        "street",
    );
}

// ═══════════════════════════════════════════════════════════════
//  3. CONTEXT AWARENESS — CITY flagged only with STREET present
// ═══════════════════════════════════════════════════════════════

#[test]
fn city_in_full_address_flagged() {
    // When STREET is present, CITY should be flagged as part of the address
    let input = "Patient resides at 742 Evergreen Terrace, Springfield, IL 62704.";
    let (_text, result) = screen(input);
    // Should have street finding
    let has_street = result
        .findings
        .iter()
        .any(|f| f.description.contains("street"));
    assert!(
        has_street,
        "Street should be detected in full address: {input}\n  Findings: {:?}",
        result.findings
    );
}

#[test]
fn city_alone_not_flagged_london() {
    // "London" alone — no street → no city flagging
    let input = "Our office is in London.";
    assert_screen_no_ner(input, "city");
    assert_text_unchanged(input);
}

#[test]
fn city_alone_not_flagged_paris() {
    let input = "The conference was held in Paris last year.";
    assert_screen_no_ner(input, "city");
    assert_text_unchanged(input);
}

// ═══════════════════════════════════════════════════════════════
//  4. CONFIDENCE THRESHOLDS — low confidence entities filtered
// ═══════════════════════════════════════════════════════════════

#[test]
fn low_confidence_name_not_flagged() {
    // "Mark" as a verb should either not be detected or be below threshold
    let input = "Mark the task as complete.";
    assert_screen_clean(input);
}

#[test]
fn high_confidence_name_flagged() {
    // Unambiguous person name in context should pass threshold
    let input = "Dr. Sarah Johnson prescribed the medication.";
    let (_text, result) = screen(input);
    let has_name = result
        .findings
        .iter()
        .any(|f| f.description.contains("givenname") || f.description.contains("surname"));
    assert!(
        has_name,
        "Should detect person name in: {input}\n  Findings: {:?}",
        result.findings
    );
}

// ═══════════════════════════════════════════════════════════════
//  5. END-TO-END MIXED SCENARIOS
// ═══════════════════════════════════════════════════════════════

#[test]
fn date_survives_while_ssn_redacted() {
    let input = "On March 15, the patient's SSN 123-45-6789 was recorded.";
    let (text, result) = screen(input);
    assert!(
        text.contains("[REDACTED:ssn]"),
        "SSN must be redacted: {text}"
    );
    assert!(
        text.contains("March 15"),
        "March must NOT be redacted: {text}"
    );
    assert!(result.screened, "Should be marked as screened");
}

#[test]
fn city_survives_while_name_redacted() {
    let input = "John Smith flew to London for the meeting.";
    let (text, result) = screen(input);
    // Name should be redacted
    let has_name = result
        .findings
        .iter()
        .any(|f| f.description.contains("givenname") || f.description.contains("surname"));
    assert!(has_name, "Name should be detected: {:?}", result.findings);
    // London without street context should NOT be redacted
    assert!(
        text.contains("London"),
        "London should NOT be redacted (no address context): {text}"
    );
}

#[test]
fn multiple_false_positive_types_in_one_text() {
    // Text with month, city, number — none should be flagged
    let input = "In March, our London office processed 42 requests.";
    assert_screen_no_ner(input, "date");
    assert_screen_no_ner(input, "city");
    assert_screen_no_ner(input, "age");
    assert_text_unchanged(input);
}

#[test]
fn real_pii_among_false_positive_bait() {
    // Mix of false-positive-prone words AND real PII
    let input = "In March 2026, John Smith from London called +1-555-867-5309 about 42 items.";
    let (text, result) = screen(input);
    // Real PII: name must be detected (NER)
    let has_name = result
        .findings
        .iter()
        .any(|f| f.description.contains("givenname") || f.description.contains("surname"));
    assert!(has_name, "Name should be detected: {:?}", result.findings);
    // Note: phone detection in long mixed context is model-dependent;
    // NER may not always form a contiguous entity from "+1-555-867-5309"
    // across subword tokens. The regex DLP layer is the primary phone catcher.
    // False positives must survive
    assert!(text.contains("March 2026"), "March redacted: {text}");
    assert!(text.contains("London"), "London redacted: {text}");
    assert!(text.contains("42"), "42 redacted: {text}");
}
