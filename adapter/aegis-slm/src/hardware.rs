//! Hardware detection and SLM model recommendation.
//!
//! Detects GPU type, VRAM, and system RAM to recommend the optimal SLM
//! configuration for the warden's hardware. No external crate dependencies —
//! uses system commands (nvidia-smi, rocm-smi, system_profiler, /proc/meminfo).

use std::process::Command;

/// Detected GPU information.
#[derive(Debug, Clone)]
pub struct GpuInfo {
    /// GPU vendor: "nvidia", "amd", "apple", "intel", or "none"
    pub vendor: String,
    /// GPU model name (e.g., "NVIDIA GeForce RTX 3090")
    pub name: String,
    /// VRAM in MB (0 if unknown)
    pub vram_mb: u64,
}

/// System hardware summary.
#[derive(Debug, Clone)]
pub struct HardwareInfo {
    /// Detected GPUs
    pub gpus: Vec<GpuInfo>,
    /// Total system RAM in MB
    pub ram_mb: u64,
    /// CPU architecture (x86_64, aarch64, etc.)
    pub arch: String,
    /// Operating system
    pub os: String,
}

/// Recommended SLM configuration based on hardware.
#[derive(Debug, Clone)]
pub struct SlmRecommendation {
    /// Recommended hardware tier name
    pub tier: String,
    /// Recommended SLM engine ("openai" for LM Studio, "ollama" for Ollama)
    pub engine: String,
    /// Recommended model identifier
    pub model: String,
    /// Human-readable model description
    pub model_description: String,
    /// Expected detection rate (approximate)
    pub expected_detection: String,
    /// Expected latency per query
    pub expected_latency: String,
    /// Additional notes for the warden
    pub notes: Vec<String>,
}

/// Detect system hardware (GPU, RAM, CPU arch).
pub fn detect_hardware() -> HardwareInfo {
    let gpus = detect_gpus();
    let ram_mb = detect_ram_mb();
    let arch = std::env::consts::ARCH.to_string();
    let os = std::env::consts::OS.to_string();

    HardwareInfo {
        gpus,
        ram_mb,
        arch,
        os,
    }
}

/// Recommend SLM configuration based on detected hardware.
pub fn recommend(hw: &HardwareInfo) -> SlmRecommendation {
    let best_gpu = hw.gpus.iter().max_by_key(|g| g.vram_mb);
    let vram = best_gpu.map(|g| g.vram_mb).unwrap_or(0);
    let is_apple_silicon = hw.arch == "aarch64" && hw.os == "macos";

    // Apple Silicon uses unified memory — can use a large portion of RAM for models
    let effective_vram = if is_apple_silicon {
        // Apple Silicon can use ~75% of unified memory for model inference
        (hw.ram_mb as f64 * 0.75) as u64
    } else {
        vram
    };

    if effective_vram >= 12_000 {
        // 12GB+ VRAM: Can run Qwen 30B-A3B (MoE, only 3B active)
        SlmRecommendation {
            tier: "optimal".to_string(),
            engine: "openai".to_string(),
            model: "qwen/qwen3-30b-a3b".to_string(),
            model_description: "Qwen3 30B-A3B (MoE: 30B total, 3B active per token)".to_string(),
            expected_detection: "100% with 2-pass screening".to_string(),
            expected_latency: "3-8s per query (2 passes)".to_string(),
            notes: vec![
                "Best detection rate. MoE architecture keeps inference fast despite 30B params.".to_string(),
                "Use LM Studio (lmstudio.ai) to serve the model on localhost:1234.".to_string(),
                format!("Detected: {}MB VRAM{}.",
                    if is_apple_silicon { hw.ram_mb } else { vram },
                    if is_apple_silicon { " (Apple Silicon unified memory)" } else { "" }
                ),
            ],
        }
    } else if effective_vram >= 6_000 {
        // 6-12GB VRAM: Can run Qwen 8B
        SlmRecommendation {
            tier: "good".to_string(),
            engine: "openai".to_string(),
            model: "qwen/qwen3-8b".to_string(),
            model_description: "Qwen3 8B (dense, 8B active)".to_string(),
            expected_detection: "~70% with 2-pass screening".to_string(),
            expected_latency: "4-10s per query (2 passes)".to_string(),
            notes: vec![
                "Good detection for most common attacks. Misses some subtle social engineering.".to_string(),
                "Heuristic + ProtectAI classifier still catch ~65% without SLM.".to_string(),
                "Use LM Studio (lmstudio.ai) to serve the model on localhost:1234.".to_string(),
                format!("Detected: {}MB VRAM.", if is_apple_silicon { hw.ram_mb } else { vram }),
            ],
        }
    } else if effective_vram >= 3_000 {
        // 3-6GB VRAM: Can run smaller models (Qwen 1.5B, Phi-3 Mini)
        SlmRecommendation {
            tier: "basic".to_string(),
            engine: "openai".to_string(),
            model: "qwen/qwen3-1.7b".to_string(),
            model_description: "Qwen3 1.7B (dense, lightweight)".to_string(),
            expected_detection: "~45% with 2-pass screening".to_string(),
            expected_latency: "1-3s per query (2 passes)".to_string(),
            notes: vec![
                "Limited SLM detection. Heuristic + classifier do most of the work.".to_string(),
                "Consider upgrading GPU or using API-based SLM for better detection.".to_string(),
                format!("Detected: {}MB VRAM.", if is_apple_silicon { hw.ram_mb } else { vram }),
            ],
        }
    } else {
        // No GPU or <3GB: Classifier + heuristic only
        SlmRecommendation {
            tier: "cpu-only".to_string(),
            engine: "ollama".to_string(),
            model: "disabled".to_string(),
            model_description: "Heuristic + ProtectAI classifier only (no LLM)".to_string(),
            expected_detection: "~65% (heuristic + classifier ensemble)".to_string(),
            expected_latency: "<10ms per query".to_string(),
            notes: vec![
                "No SLM model needed. Heuristic patterns + ProtectAI DeBERTa classifier provide baseline screening.".to_string(),
                "Run with: aegis --no-slm".to_string(),
                "Metaprompt hardening still protects against indirect injection.".to_string(),
                if vram == 0 && !is_apple_silicon {
                    "No GPU detected. To enable SLM screening, add a GPU with 6GB+ VRAM or use an API endpoint.".to_string()
                } else {
                    format!("Detected: {}MB VRAM (insufficient for SLM models, minimum 3GB recommended).", vram)
                },
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// GPU detection (cross-platform)
// ---------------------------------------------------------------------------

fn detect_gpus() -> Vec<GpuInfo> {
    let mut gpus = Vec::new();

    // Try NVIDIA (nvidia-smi)
    if let Some(gpu) = detect_nvidia() {
        gpus.push(gpu);
    }

    // Try AMD (rocm-smi)
    if let Some(gpu) = detect_amd() {
        gpus.push(gpu);
    }

    // Try Apple Silicon
    if std::env::consts::OS == "macos" {
        if let Some(gpu) = detect_apple_gpu() {
            gpus.push(gpu);
        }
    }

    // Try Intel (Linux)
    if gpus.is_empty() && std::env::consts::OS == "linux" {
        if let Some(gpu) = detect_intel_linux() {
            gpus.push(gpu);
        }
    }

    gpus
}

fn detect_nvidia() -> Option<GpuInfo> {
    let output = Command::new("nvidia-smi")
        .args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?;
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

    let name = parts.first().unwrap_or(&"NVIDIA GPU").to_string();
    let vram_mb: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    Some(GpuInfo {
        vendor: "nvidia".to_string(),
        name,
        vram_mb,
    })
}

fn detect_amd() -> Option<GpuInfo> {
    // Get product name
    let name_output = Command::new("rocm-smi")
        .args(["--showproductname"])
        .output()
        .ok()?;

    if !name_output.status.success() {
        return None;
    }

    let name_text = String::from_utf8_lossy(&name_output.stdout);

    // Parse: "GPU[0]		: Card series: 		0x1586"
    // and   "GPU[0]		: Card vendor: 		Advanced Micro Devices, Inc. [AMD/ATI]"
    // and   "GPU[0]		: Card SKU: 		STRXLGEN"
    let mut vendor_str = String::new();
    let mut sku = String::new();
    for line in name_text.lines() {
        if line.contains("Card vendor:") {
            vendor_str = line.split(':').last().unwrap_or("").trim().to_string();
        }
        if line.contains("Card SKU:") {
            sku = line.split(':').last().unwrap_or("").trim().to_string();
        }
    }
    let name = if !sku.is_empty() && !vendor_str.is_empty() {
        format!("{} ({})", vendor_str, sku)
    } else if !vendor_str.is_empty() {
        vendor_str
    } else {
        "AMD GPU".to_string()
    };

    // Get VRAM
    let vram_output = Command::new("rocm-smi")
        .args(["--showmeminfo", "vram"])
        .output()
        .ok();

    // Parse: "GPU[0]		: VRAM Total Memory (B): 34359738368"
    let vram_mb = vram_output.and_then(|o| {
        if !o.status.success() { return None; }
        let text = String::from_utf8_lossy(&o.stdout).to_string();
        text.lines()
            .find(|l| l.contains("VRAM Total Memory"))
            .and_then(|l| {
                l.rsplit(':').next()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(|bytes| bytes / (1024 * 1024))
            })
    }).unwrap_or(0);

    Some(GpuInfo {
        vendor: "amd".to_string(),
        name,
        vram_mb,
    })
}

fn detect_apple_gpu() -> Option<GpuInfo> {
    let output = Command::new("system_profiler")
        .args(["SPDisplaysDataType", "-json"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;

    let displays = json.get("SPDisplaysDataType")?.as_array()?;
    let gpu = displays.first()?;

    let name = gpu.get("sppci_model")
        .or_else(|| gpu.get("_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("Apple GPU")
        .to_string();

    let vram_str = gpu.get("sppci_vram")
        .or_else(|| gpu.get("spdisplays_vram"))
        .and_then(|v| v.as_str())
        .unwrap_or("0");

    // Parse VRAM string like "16 GB" or "8192 MB"
    let vram_mb = parse_memory_string(vram_str);

    Some(GpuInfo {
        vendor: "apple".to_string(),
        name,
        vram_mb,
    })
}

fn detect_intel_linux() -> Option<GpuInfo> {
    // Check lspci for Intel GPU
    let output = Command::new("lspci")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let gpu_line = text.lines()
        .find(|l| l.contains("VGA") && l.to_lowercase().contains("intel"))?;

    // Intel integrated GPUs share system RAM
    let name = gpu_line
        .split(':')
        .last()
        .unwrap_or("Intel GPU")
        .trim()
        .to_string();

    Some(GpuInfo {
        vendor: "intel".to_string(),
        name,
        vram_mb: 0, // Shared memory, not useful for LLM inference
    })
}

// ---------------------------------------------------------------------------
// RAM detection
// ---------------------------------------------------------------------------

fn detect_ram_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    let kb: u64 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    return kb / 1024;
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("sysctl").args(["-n", "hw.memsize"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Ok(bytes) = text.trim().parse::<u64>() {
                    return bytes / (1024 * 1024);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("wmic")
            .args(["OS", "get", "TotalVisibleMemorySize", "/Value"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if line.starts_with("TotalVisibleMemorySize=") {
                        let kb: u64 = line
                            .split('=')
                            .nth(1)
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(0);
                        return kb / 1024;
                    }
                }
            }
        }
    }

    0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_memory_string(s: &str) -> u64 {
    let lower = s.to_lowercase();
    let num: f64 = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect::<String>()
        .parse()
        .unwrap_or(0.0);

    if lower.contains("tb") {
        (num * 1024.0 * 1024.0) as u64
    } else if lower.contains("gb") {
        (num * 1024.0) as u64
    } else if lower.contains("mb") {
        num as u64
    } else {
        // Assume MB if no unit
        num as u64
    }
}

/// Format hardware info as a human-readable string.
pub fn format_hardware_info(hw: &HardwareInfo) -> String {
    let mut lines = Vec::new();
    lines.push(format!("  OS:   {} ({})", hw.os, hw.arch));
    lines.push(format!("  RAM:  {} MB ({:.1} GB)", hw.ram_mb, hw.ram_mb as f64 / 1024.0));

    if hw.gpus.is_empty() {
        lines.push("  GPU:  none detected".to_string());
    } else {
        for gpu in &hw.gpus {
            if gpu.vram_mb > 0 {
                lines.push(format!("  GPU:  {} ({} MB VRAM)", gpu.name, gpu.vram_mb));
            } else {
                lines.push(format!("  GPU:  {} (shared memory)", gpu.name));
            }
        }
    }

    lines.join("\n")
}

/// Format recommendation as a human-readable string.
pub fn format_recommendation(rec: &SlmRecommendation) -> String {
    let mut lines = Vec::new();
    lines.push(format!("  Tier:       {} ({})", rec.tier, rec.model_description));
    if rec.model != "disabled" {
        lines.push(format!("  Engine:     {}", rec.engine));
        lines.push(format!("  Model:      {}", rec.model));
    }
    lines.push(format!("  Detection:  {}", rec.expected_detection));
    lines.push(format!("  Latency:    {}", rec.expected_latency));

    if !rec.notes.is_empty() {
        lines.push(String::new());
        for note in &rec.notes {
            lines.push(format!("  * {}", note));
        }
    }

    // Configuration commands
    lines.push(String::new());
    if rec.model == "disabled" {
        lines.push("  To apply:".to_string());
        lines.push("    aegis --no-slm".to_string());
    } else {
        lines.push("  To apply:".to_string());
        lines.push(format!("    aegis slm engine {}", rec.engine));
        lines.push(format!("    aegis slm use {}", rec.model));
        if rec.engine == "openai" {
            lines.push("    aegis slm server http://localhost:1234".to_string());
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memory_gb() {
        assert_eq!(parse_memory_string("16 GB"), 16384);
        assert_eq!(parse_memory_string("8GB"), 8192);
    }

    #[test]
    fn parse_memory_mb() {
        assert_eq!(parse_memory_string("4096 MB"), 4096);
        assert_eq!(parse_memory_string("8192MB"), 8192);
    }

    #[test]
    fn recommend_optimal_tier() {
        let hw = HardwareInfo {
            gpus: vec![GpuInfo {
                vendor: "nvidia".to_string(),
                name: "RTX 4090".to_string(),
                vram_mb: 24576,
            }],
            ram_mb: 32768,
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
        };
        let rec = recommend(&hw);
        assert_eq!(rec.tier, "optimal");
        assert!(rec.model.contains("30b"));
    }

    #[test]
    fn recommend_good_tier() {
        let hw = HardwareInfo {
            gpus: vec![GpuInfo {
                vendor: "nvidia".to_string(),
                name: "RTX 3060".to_string(),
                vram_mb: 8192,
            }],
            ram_mb: 16384,
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
        };
        let rec = recommend(&hw);
        assert_eq!(rec.tier, "good");
        assert!(rec.model.contains("8b"));
    }

    #[test]
    fn recommend_cpu_only() {
        let hw = HardwareInfo {
            gpus: vec![],
            ram_mb: 8192,
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
        };
        let rec = recommend(&hw);
        assert_eq!(rec.tier, "cpu-only");
        assert_eq!(rec.model, "disabled");
    }

    #[test]
    fn recommend_apple_silicon_uses_unified_memory() {
        let hw = HardwareInfo {
            gpus: vec![GpuInfo {
                vendor: "apple".to_string(),
                name: "Apple M2 Pro".to_string(),
                vram_mb: 0,
            }],
            ram_mb: 32768, // 32GB unified → 75% = 24GB effective
            arch: "aarch64".to_string(),
            os: "macos".to_string(),
        };
        let rec = recommend(&hw);
        assert_eq!(rec.tier, "optimal");
    }

    #[test]
    fn format_recommendation_has_apply_commands() {
        let hw = HardwareInfo {
            gpus: vec![GpuInfo {
                vendor: "nvidia".to_string(),
                name: "RTX 3090".to_string(),
                vram_mb: 24576,
            }],
            ram_mb: 32768,
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
        };
        let rec = recommend(&hw);
        let text = format_recommendation(&rec);
        assert!(text.contains("aegis slm engine"));
        assert!(text.contains("aegis slm use"));
    }
}
