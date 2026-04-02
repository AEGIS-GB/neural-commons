//! DistilBERT-NER + GDPR/NIST PII filter test
//! Tests that only identifiable PII (full names, title+surname) is flagged.
//! Single first names, cities, brands are NOT PII.

use std::path::PathBuf;

fn model_dir() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/distilbert-ner"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/pii-ner"),
    ];
    candidates
        .into_iter()
        .find(|p| p.join("model.onnx").exists() && p.join("config.json").exists())
}

fn has_pii_name(entities: &[aegis_proxy::ner_pii::NerEntity]) -> bool {
    entities.iter().any(|e| {
        let t = e.entity_type.to_uppercase();
        let is_name =
            t == "PER" || t.contains("GIVENNAME") || t.contains("SURNAME") || t.contains("NAME");
        is_name && e.score > 0.5 && aegis_proxy::ner_pii::is_pii_name(&e.text)
    })
}

#[test]
fn gdpr_pii_benchmark() {
    let dir = match model_dir() {
        Some(d) => d,
        None => {
            eprintln!("SKIP: NER model not found");
            return;
        }
    };

    aegis_proxy::ner_pii::init(&dir);
    if !aegis_proxy::ner_pii::is_available() {
        eprintln!("SKIP: NER model failed to load");
        return;
    }

    struct Case {
        text: &'static str,
        has_pii: bool,
        desc: &'static str,
    }

    let cases = vec![
        // CLEAN — not PII under GDPR/NIST
        Case {
            text: "The meeting is in March in London.",
            has_pii: false,
            desc: "month + city",
        },
        Case {
            text: "Version 25.2.8 of Vulkan driver.",
            has_pii: false,
            desc: "version",
        },
        Case {
            text: "Mark task complete. Grant access.",
            has_pii: false,
            desc: "verbs (single names NOT PII)",
        },
        Case {
            text: "Bill paid. Grace period 30 days.",
            has_pii: false,
            desc: "nouns (single names NOT PII)",
        },
        Case {
            text: "Ford Mustang, Lincoln Memorial.",
            has_pii: false,
            desc: "brands",
        },
        Case {
            text: "Amazon earnings, Wall Street.",
            has_pii: false,
            desc: "companies",
        },
        Case {
            text: "CPU 78%, memory 62/128 GB, 42 days.",
            has_pii: false,
            desc: "metrics",
        },
        Case {
            text: "Nurse Sarah documented the vitals.",
            has_pii: false,
            desc: "single first name",
        },
        Case {
            text: "Ask Alice about the schedule.",
            has_pii: false,
            desc: "single first name casual",
        },
        Case {
            text: "The patient named Grace was discharged.",
            has_pii: false,
            desc: "single first name patient",
        },
        // PII — identifiable individuals
        Case {
            text: "Patient Sarah Johnson, anemia.",
            has_pii: true,
            desc: "full name medical",
        },
        Case {
            text: "Engineer Michael Chen, v3.2.1, Berlin.",
            has_pii: true,
            desc: "full name tech",
        },
        Case {
            text: "Nurse Alice Brown, chart, 14:30.",
            has_pii: true,
            desc: "full name + time",
        },
        Case {
            text: "Manager Lisa Park, 128 requests, Q3.",
            has_pii: true,
            desc: "full name metrics",
        },
        Case {
            text: "Dr. Sarah Johnson, March 15, London.",
            has_pii: true,
            desc: "full name+date+city",
        },
        Case {
            text: "Dear Mr. Tanaka, account ending 7890.",
            has_pii: true,
            desc: "title+surname",
        },
        Case {
            text: "Employee Robert Chen (ID: EMP-2847), Singapore.",
            has_pii: true,
            desc: "full name+ID",
        },
        Case {
            text: "Patient Rosa Martinez, DOB 1987-06-15.",
            has_pii: true,
            desc: "full name+DOB",
        },
        Case {
            text: "Invoice client Elizabeth Warren-Scott, April.",
            has_pii: true,
            desc: "hyphenated full name",
        },
        Case {
            text: "Consultant Raj Patel-Mehta reviewed Q4.",
            has_pii: true,
            desc: "compound surname",
        },
    ];

    let clean_n = cases.iter().filter(|c| !c.has_pii).count();
    let pii_n = cases.iter().filter(|c| c.has_pii).count();

    println!("\n{:=<90}", "");
    println!(
        "  NER + GDPR/NIST PII Filter: {} cases ({} clean, {} PII)",
        cases.len(),
        clean_n,
        pii_n
    );
    println!("{:=<90}", "");

    let mut tp = 0u32;
    let mut fp = 0u32;
    let mut tn = 0u32;
    let mut fn_ = 0u32;

    for case in &cases {
        let entities = aegis_proxy::ner_pii::detect_entities(case.text);
        let found = has_pii_name(&entities);

        if !case.has_pii && !found {
            tn += 1;
        } else if !case.has_pii && found {
            fp += 1;
            let names: Vec<_> = entities
                .iter()
                .filter(|e| e.score > 0.5)
                .map(|e| format!("{}:\"{}\"", e.entity_type, e.text))
                .collect();
            println!("    FP: {:40} → {:?}", case.desc, names);
        } else if case.has_pii && found {
            tp += 1;
        } else {
            fn_ += 1;
            println!("    FN: {:40} (missed)", case.desc);
        }
    }

    let total = cases.len() as f64;
    let acc = (tp + tn) as f64 / total * 100.0;
    let prec = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64 * 100.0
    } else {
        0.0
    };
    let rec = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64 * 100.0
    } else {
        0.0
    };
    let f1 = if prec + rec > 0.0 {
        2.0 * prec * rec / (prec + rec)
    } else {
        0.0
    };

    println!("\n  Results:");
    println!("    TP={} FP={} TN={} FN={}", tp, fp, tn, fn_);
    println!(
        "    Accuracy={:.1}% Precision={:.1}% Recall={:.1}% F1={:.1}%",
        acc, prec, rec, f1
    );
    println!("{:=<90}\n", "");

    // Assert quality thresholds
    assert!(fp == 0, "Expected zero false positives, got {fp}");
    assert!(fn_ <= 2, "Expected at most 2 false negatives, got {fn_}");
}
