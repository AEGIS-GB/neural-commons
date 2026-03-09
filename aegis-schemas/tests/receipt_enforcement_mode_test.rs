use aegis_schemas::receipt::{generate_blinding_nonce, ReceiptContext};

#[test]
fn enforcement_mode_field_omitted_when_none() {
    let ctx = ReceiptContext {
        blinding_nonce: generate_blinding_nonce(),
        enforcement_mode: None,
        action: None,
        subject: None,
        trigger: None,
        outcome: None,
        detail: None,
        enterprise: None,
    };
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(
        json.get("enforcement_mode").is_none(),
        "field must be omitted, not null"
    );
}

#[test]
fn enforcement_mode_field_present_when_set() {
    let ctx = ReceiptContext {
        blinding_nonce: generate_blinding_nonce(),
        enforcement_mode: Some("observe".to_string()),
        action: None,
        subject: None,
        trigger: None,
        outcome: None,
        detail: None,
        enterprise: None,
    };
    let json = serde_json::to_value(&ctx).unwrap();
    assert_eq!(json["enforcement_mode"], "observe");
}
