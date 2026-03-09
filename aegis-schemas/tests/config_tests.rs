use aegis_schemas::config::{CheckMode, EnforcementConfig};

#[test]
fn observe_default_is_observe() {
    let cfg = EnforcementConfig::observe_default();
    assert!(cfg.write_barrier.is_observe());
    assert!(cfg.slm_reject.is_observe());
}

#[test]
fn enforce_default_is_enforce() {
    let cfg = EnforcementConfig::enforce_default();
    assert!(cfg.write_barrier.is_enforce());
    assert!(cfg.slm_reject.is_enforce());
}

#[test]
fn apply_observe_only_flag_only_touches_switchable_checks() {
    let mut cfg = EnforcementConfig::enforce_default();
    cfg.apply_observe_only_flag();
    assert!(cfg.write_barrier.is_observe());
    assert!(cfg.slm_reject.is_observe());
    // vault, memory, identity, failure are not in EnforcementConfig
    // so they cannot be changed — no assertions needed, compiler enforces it
}

#[test]
fn enforcement_config_roundtrip_json() {
    let cfg = EnforcementConfig::observe_default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: EnforcementConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg.write_barrier, back.write_barrier);
    assert_eq!(cfg.slm_reject, back.slm_reject);
}

#[test]
fn check_mode_serializes_as_snake_case() {
    assert_eq!(
        serde_json::to_string(&CheckMode::Observe).unwrap(),
        "\"observe\""
    );
    assert_eq!(
        serde_json::to_string(&CheckMode::Enforce).unwrap(),
        "\"enforce\""
    );
}
