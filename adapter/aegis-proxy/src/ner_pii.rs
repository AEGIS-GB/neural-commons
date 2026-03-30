//! NER-based PII detection for response screening.
//!
//! Uses a token classification ONNX model (XLM-RoBERTa) to detect
//! person names, addresses, phone numbers, and other semantic PII.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use ort::value::Value;
use tokenizers::Tokenizer;
use tracing::{debug, info, warn};

const MAX_SEQ_LEN: usize = 512;

/// A detected PII entity.
#[derive(Debug, Clone)]
pub struct NerEntity {
    pub entity_type: String,
    pub text: String,
    pub score: f32,
}

static NER_ENGINE: OnceLock<Option<NerEngine>> = OnceLock::new();

struct NerEngine {
    session: Mutex<ort::session::Session>,
    tokenizer: Tokenizer,
    id2label: std::collections::HashMap<i64, String>,
}

/// Initialize NER from model directory (model.onnx + tokenizer.json + config.json).
pub fn init(model_dir: &Path) {
    NER_ENGINE.get_or_init(|| {
        let model_path = model_dir.join("model.onnx");
        let tokenizer_path = model_dir.join("tokenizer.json");
        let config_path = model_dir.join("config.json");

        if !model_path.exists() {
            info!("NER PII model not found — disabled");
            return None;
        }

        // Load id2label from config
        let id2label = match std::fs::read_to_string(&config_path) {
            Ok(content) => {
                let config: serde_json::Value = serde_json::from_str(&content).ok()?;
                let mut map = std::collections::HashMap::new();
                if let Some(labels) = config.get("id2label").and_then(|v| v.as_object()) {
                    for (k, v) in labels {
                        if let (Ok(id), Some(label)) = (k.parse::<i64>(), v.as_str()) {
                            map.insert(id, label.to_string());
                        }
                    }
                }
                map
            }
            Err(_) => return None,
        };

        let num_threads = std::thread::available_parallelism()
            .map(|p| p.get().min(4))
            .unwrap_or(2);

        let session = ort::session::Session::builder()
            .ok()?
            .with_intra_threads(num_threads)
            .ok()?
            .commit_from_file(&model_path)
            .ok()?;

        let tokenizer = Tokenizer::from_file(&tokenizer_path).ok()?;

        let entity_count = id2label.values().filter(|v| v.starts_with("B-")).count();
        info!(entity_count, "NER PII model loaded");

        Some(NerEngine {
            session: Mutex::new(session),
            tokenizer,
            id2label,
        })
    });
}

/// Detect PII entities in text.
pub fn detect_entities(text: &str) -> Vec<NerEntity> {
    let engine = match NER_ENGINE.get().and_then(|e| e.as_ref()) {
        Some(e) => e,
        None => return Vec::new(),
    };

    if text.len() < 3 {
        return Vec::new();
    }

    let truncated: String = text.chars().take(2000).collect();

    let encoding = match engine.tokenizer.encode(truncated.as_str(), true) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let input_ids: Vec<i64> = encoding
        .get_ids()
        .iter()
        .take(MAX_SEQ_LEN)
        .map(|&id| id as i64)
        .collect();
    let attention_mask: Vec<i64> = encoding
        .get_attention_mask()
        .iter()
        .take(MAX_SEQ_LEN)
        .map(|&m| m as i64)
        .collect();
    let seq_len = input_ids.len();
    if seq_len == 0 {
        return Vec::new();
    }

    let shape = [1usize, seq_len];
    let input_ids_val = match Value::from_array((&shape[..], input_ids)) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let attention_val = match Value::from_array((&shape[..], attention_mask)) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut session = match engine.session.lock() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let logits_vec: Vec<f32>;
    let num_labels = engine.id2label.len();
    {
        let outputs = match session.run(ort::inputs![input_ids_val, attention_val]) {
            Ok(o) => o,
            Err(e) => {
                debug!("NER inference error: {e}");
                return Vec::new();
            }
        };

        let (_logits_shape, logits_data) = match outputs[0].try_extract_tensor::<f32>() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        if logits_data.len() < seq_len * num_labels {
            return Vec::new();
        }
        logits_vec = logits_data.to_vec();
    }
    drop(session);

    let offsets = encoding.get_offsets();
    let mut entities = Vec::new();
    let mut current: Option<(String, String, f32)> = None;

    for i in 0..seq_len {
        let row = i * num_labels;
        let mut best_label = 0usize;
        let mut best_score = f32::MIN;
        for j in 0..num_labels {
            let s = logits_vec[row + j];
            if s > best_score {
                best_score = s;
                best_label = j;
            }
        }

        // Softmax confidence
        let exp_sum: f32 = (0..num_labels)
            .map(|j| (logits_vec[row + j] - best_score).exp())
            .sum();
        let confidence = 1.0 / exp_sum;

        let label = engine
            .id2label
            .get(&(best_label as i64))
            .cloned()
            .unwrap_or_else(|| "O".to_string());

        // Extract entity type from label (strip B- or I- prefix)
        let entity_type = if label.starts_with("B-") || label.starts_with("I-") {
            Some(&label[2..])
        } else {
            None
        };

        if let Some(etype) = entity_type {
            let (start, end) = offsets[i];
            let span = &truncated[start..end.min(truncated.len())];

            if let Some((ref cur_type, ref mut etext, ref mut escore)) = current {
                if cur_type == etype {
                    // Same entity type — continue (use original text spans for proper spacing)
                    let (_, prev_end) = offsets[i.saturating_sub(1)];
                    if start > prev_end {
                        // Gap between tokens — add space
                        etext.push(' ');
                    }
                    etext.push_str(span);
                    if confidence > *escore {
                        *escore = confidence;
                    }
                } else {
                    // Different type — flush and start new
                    let (etype_out, etext_out, escore_out) = current.take().unwrap();
                    if escore_out > 0.5 && etext_out.trim().len() > 1 {
                        entities.push(NerEntity {
                            entity_type: etype_out,
                            text: etext_out.trim().to_string(),
                            score: escore_out,
                        });
                    }
                    current = Some((etype.to_string(), span.to_string(), confidence));
                }
            } else {
                // Start new entity
                current = Some((etype.to_string(), span.to_string(), confidence));
            }
        } else {
            // O label — flush current entity
            if let Some((etype, etext, escore)) = current.take() {
                if escore > 0.5 && etext.trim().len() > 1 {
                    entities.push(NerEntity {
                        entity_type: etype,
                        text: etext.trim().to_string(),
                        score: escore,
                    });
                }
            }
        }
    }

    // Flush last
    if let Some((etype, etext, escore)) = current {
        if escore > 0.5 && etext.trim().len() > 1 {
            entities.push(NerEntity {
                entity_type: etype,
                text: etext.trim().to_string(),
                score: escore,
            });
        }
    }

    debug!(count = entities.len(), "NER detected entities");
    entities
}

pub fn is_available() -> bool {
    NER_ENGINE.get().map(|e| e.is_some()).unwrap_or(false)
}
