//! 3-layer content screening for mesh relay messages.
//!
//! Extracted from Gateway (routes.rs mesh_send) into standalone module.
//! Same cascade: heuristic → classifier → deep SLM, with trust-aware logic.

use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info, warn};

use aegis_slm::engine::SlmEngine;
use aegis_slm::engine::heuristic::HeuristicEngine;
use aegis_slm::engine::openai_compat::OpenAiCompatEngine;
use aegis_slm::parser::parse_slm_output;
use aegis_slm::prompt::screening_prompt_combined_with_trust;
use aegis_slm::types::EngineProfile;

/// Classifier confidence threshold for low-trust senders.
/// Above this: quarantine. Below: pass to Layer 3.
const RELAY_CLASSIFIER_THRESHOLD: f32 = 0.9;

/// TRUSTMARK basis points threshold for "high trust" (Tier 3).
const HIGH_TRUST_BP: u32 = 4000;

/// Screening verdict for a relay message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreeningVerdict {
    /// "admit" or "quarantine"
    pub verdict: String,
    /// Which layer produced the verdict (1=heuristic, 2=classifier, 3=deep_slm, 0=none)
    pub layer: u8,
    /// Detected patterns (empty if clean)
    pub patterns: Vec<String>,
    /// Human-readable reason (empty if clean)
    pub reason: String,
}

impl ScreeningVerdict {
    pub fn admit() -> Self {
        Self {
            verdict: "admit".into(),
            layer: 0,
            patterns: vec![],
            reason: String::new(),
        }
    }

    pub fn quarantine(layer: u8, patterns: Vec<String>, reason: String) -> Self {
        Self {
            verdict: "quarantine".into(),
            layer,
            patterns,
            reason,
        }
    }

    pub fn is_quarantined(&self) -> bool {
        self.verdict == "quarantine"
    }
}

/// Screening engines — optional classifier and SLM.
/// Heuristic is always available (no external deps).
pub struct ScreeningEngines {
    heuristic: HeuristicEngine,
    #[cfg(feature = "prompt-guard")]
    pub classifier: Option<aegis_slm::engine::prompt_guard::PromptGuardEngine>,
    pub slm: Option<OpenAiCompatEngine>,
}

impl ScreeningEngines {
    /// Create screening engines with optional classifier and SLM.
    pub fn new(
        #[cfg(feature = "prompt-guard")] classifier_model_dir: Option<&Path>,
        slm_server_url: Option<&str>,
        slm_model: Option<&str>,
    ) -> Self {
        let heuristic = HeuristicEngine::new();

        #[cfg(feature = "prompt-guard")]
        let classifier = classifier_model_dir.and_then(|dir| {
            match aegis_slm::engine::prompt_guard::PromptGuardEngine::load(dir) {
                Ok(engine) => {
                    info!("PromptGuard classifier loaded from {}", dir.display());
                    Some(engine)
                }
                Err(e) => {
                    warn!("Failed to load PromptGuard classifier: {e}");
                    None
                }
            }
        });

        let slm = match (slm_server_url, slm_model) {
            (Some(url), Some(model)) => {
                info!(url, model, "Deep SLM engine configured");
                Some(OpenAiCompatEngine::new(url, model))
            }
            _ => None,
        };

        Self {
            heuristic,
            #[cfg(feature = "prompt-guard")]
            classifier,
            slm,
        }
    }

    /// Create engines with heuristic only (for testing).
    pub fn heuristic_only() -> Self {
        Self {
            heuristic: HeuristicEngine::new(),
            #[cfg(feature = "prompt-guard")]
            classifier: None,
            slm: None,
        }
    }

    /// Screen a relay message body with the 3-layer cascade.
    ///
    /// `sender_trustmark_bp`: sender's TRUSTMARK score in basis points.
    /// Returns a `ScreeningVerdict`.
    pub fn screen(&self, body: &str, sender_trustmark_bp: u32) -> ScreeningVerdict {
        let is_high_trust = sender_trustmark_bp >= HIGH_TRUST_BP;
        let _sender_tier = if sender_trustmark_bp >= HIGH_TRUST_BP {
            "tier3"
        } else if sender_trustmark_bp >= 2000 {
            "tier2"
        } else {
            "tier1"
        };

        // Layer 1: Heuristic (<1ms) — always blocks on match
        if let Some(verdict) = self.screen_heuristic(body) {
            return verdict;
        }

        // Layer 2: Classifier (if available, ~15ms)
        let classifier_flag = self.screen_classifier(body, is_high_trust);
        if let Some(ref flag) = classifier_flag
            && flag.starts_with("quarantine:")
        {
            let reason = flag.strip_prefix("quarantine:").unwrap().to_string();
            return ScreeningVerdict::quarantine(2, vec!["direct_injection".into()], reason);
        } else if classifier_flag.is_some() {
            // It's a context flag for Layer 3
        }

        // Layer 3: Deep SLM (if available, 2-3s)
        if let Some(verdict) =
            self.screen_slm(body, is_high_trust, sender_trustmark_bp, &classifier_flag)
        {
            return verdict;
        }

        ScreeningVerdict::admit()
    }

    /// Layer 1: Heuristic pattern matching.
    fn screen_heuristic(&self, body: &str) -> Option<ScreeningVerdict> {
        if let Ok(output) = SlmEngine::generate(&self.heuristic, body)
            && let Ok(parsed) = parse_slm_output(&output, &EngineProfile::Loopback)
            && !parsed.annotations.is_empty()
        {
            let patterns: Vec<String> = parsed
                .annotations
                .iter()
                .map(|a| {
                    serde_json::to_value(&a.pattern)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_else(|| format!("{:?}", a.pattern))
                })
                .collect();
            let reason = format!("heuristic: {}", patterns.join(", "));
            debug!(reason, "Layer 1 heuristic caught injection");
            return Some(ScreeningVerdict::quarantine(1, patterns, reason));
        }
        None
    }

    /// Layer 2: Classifier screening.
    /// Returns None if no classifier or message is clean.
    /// Returns Some("quarantine:...") if should quarantine.
    /// Returns Some("flag:...") if should pass to Layer 3 with context.
    #[allow(unused_variables)]
    fn screen_classifier(&self, body: &str, is_high_trust: bool) -> Option<String> {
        #[cfg(feature = "prompt-guard")]
        if let Some(ref pg) = self.classifier {
            match pg.classify(body) {
                Ok((is_malicious, probability)) if is_malicious => {
                    if is_high_trust {
                        // Tier 3: pass verdict to SLM as context
                        info!(
                            probability,
                            "Classifier flagged relay from Tier 3 sender — passing to SLM"
                        );
                        return Some(format!(
                            "flag:classifier flagged at {:.0}% confidence",
                            probability * 100.0
                        ));
                    } else if probability > RELAY_CLASSIFIER_THRESHOLD {
                        // Low-trust above threshold: quarantine
                        return Some(format!(
                            "quarantine:classifier: direct_injection ({:.0}% confidence)",
                            probability * 100.0
                        ));
                    } else {
                        // Low-trust below threshold: pass to Layer 3
                        debug!(
                            probability,
                            "Classifier flagged below threshold, passing to Layer 3"
                        );
                    }
                }
                Err(e) => {
                    warn!("PromptGuard classifier error: {e}");
                }
                _ => {}
            }
        }
        None
    }

    /// Layer 3: Deep SLM screening with trust context.
    fn screen_slm(
        &self,
        body: &str,
        is_high_trust: bool,
        sender_trustmark_bp: u32,
        classifier_flag: &Option<String>,
    ) -> Option<ScreeningVerdict> {
        let slm = self.slm.as_ref()?;

        // Build trust-aware screening prompt
        let trust_context = if is_high_trust {
            let mut ctx = format!("Sender is Tier 3, TRUSTMARK {sender_trustmark_bp}bp. ");
            if let Some(flag) = classifier_flag {
                let flag_text = flag.strip_prefix("flag:").unwrap_or(flag);
                ctx.push_str(&format!(
                    "Note: {flag_text} — this may be because the sender is discussing security patterns, not executing them. Evaluate based on intent."
                ));
            }
            Some(ctx)
        } else {
            None
        };

        let screening_prompt = screening_prompt_combined_with_trust(body, trust_context.as_deref());

        let result = tokio::task::block_in_place(|| SlmEngine::generate(slm, &screening_prompt));

        if let Ok(output) = result
            && let Ok(parsed) = parse_slm_output(&output, &EngineProfile::Loopback)
            && !parsed.annotations.is_empty()
        {
            let patterns: Vec<String> = parsed
                .annotations
                .iter()
                .map(|a| {
                    serde_json::to_value(&a.pattern)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_else(|| format!("{:?}", a.pattern))
                })
                .collect();
            let reason = format!("deep_slm: {}", patterns.join(", "));
            debug!(reason, "Layer 3 SLM caught injection");
            return Some(ScreeningVerdict::quarantine(3, patterns, reason));
        }

        None
    }
}
