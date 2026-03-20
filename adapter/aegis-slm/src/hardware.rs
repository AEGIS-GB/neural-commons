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
    /// Whether VRAM was actually detected or is unknown
    pub vram_detected: bool,
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
    /// Detection issues — tools that were missing or failed
    pub warnings: Vec<String>,
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
    let mut warnings = Vec::new();
    let gpus = detect_gpus(&mut warnings);
    let ram_mb = detect_ram_mb();
    let arch = std::env::consts::ARCH.to_string();
    let os = std::env::consts::OS.to_string();

    HardwareInfo {
        gpus,
        ram_mb,
        arch,
        os,
        warnings,
    }
}

/// Recommend SLM configuration based on detected hardware.
pub fn recommend(hw: &HardwareInfo) -> SlmRecommendation {
    let best_gpu = hw.gpus.iter().max_by_key(|g| g.vram_mb);
    let vram = best_gpu.map(|g| g.vram_mb).unwrap_or(0);
    let has_gpu = !hw.gpus.is_empty();
    let vram_known = best_gpu.map(|g| g.vram_detected).unwrap_or(false);
    let is_apple_silicon = hw.arch == "aarch64" && hw.os == "macos";

    // Apple Silicon uses unified memory — can use a large portion of RAM for models
    let effective_vram = if is_apple_silicon {
        // Apple Silicon can use ~75% of unified memory for model inference
        (hw.ram_mb as f64 * 0.75) as u64
    } else {
        vram
    };

    // GPU detected but VRAM unknown — can't auto-recommend, ask the warden
    if has_gpu && !vram_known && !is_apple_silicon {
        let gpu_name = best_gpu.map(|g| g.name.as_str()).unwrap_or("Unknown GPU");
        return SlmRecommendation {
            tier: "unknown".to_string(),
            engine: "openai".to_string(),
            model: "auto".to_string(),
            model_description: format!("GPU detected ({}) but VRAM unknown", gpu_name),
            expected_detection: "depends on model chosen".to_string(),
            expected_latency: "depends on model chosen".to_string(),
            notes: vec![
                format!("GPU found: {} — but VRAM could not be detected.", gpu_name),
                "Install GPU drivers to enable automatic detection:".to_string(),
                "  NVIDIA: install nvidia-drivers (provides nvidia-smi)".to_string(),
                "  AMD:    install rocm (provides rocm-smi)".to_string(),
                String::new(),
                "Or choose manually based on your VRAM:".to_string(),
                "  12GB+:  aegis slm use qwen/qwen3-30b-a3b  (100% detection)".to_string(),
                "  6-12GB: aegis slm use qwen/qwen3-8b       (~70% detection)".to_string(),
                "  3-6GB:  aegis slm use qwen/qwen3-1.7b     (~45% detection)".to_string(),
                "  <3GB:   aegis --no-slm                     (~65% heuristic only)".to_string(),
            ],
        };
    }

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

fn detect_gpus(warnings: &mut Vec<String>) -> Vec<GpuInfo> {
    let mut gpus = Vec::new();

    // Try NVIDIA (nvidia-smi)
    match detect_nvidia() {
        Some(gpu) => gpus.push(gpu),
        None => {
            // Check if NVIDIA hardware exists but driver tools are missing
            if has_nvidia_hardware() {
                warnings.push(
                    "NVIDIA GPU detected via PCI but nvidia-smi not found. \
                     Install NVIDIA drivers for accurate VRAM detection: \
                     https://www.nvidia.com/drivers".to_string()
                );
                gpus.push(GpuInfo {
                    vendor: "nvidia".to_string(),
                    name: "NVIDIA GPU (drivers not installed)".to_string(),
                    vram_mb: 0,
                    vram_detected: false,
                });
            }
        }
    }

    // Try AMD (rocm-smi)
    match detect_amd() {
        Some(gpu) => gpus.push(gpu),
        None => {
            // Check if AMD hardware exists but ROCm tools are missing
            if has_amd_hardware() {
                warnings.push(
                    "AMD GPU detected via PCI but rocm-smi not found. \
                     Install ROCm for accurate VRAM detection: \
                     https://rocm.docs.amd.com/en/latest/deploy/linux/install.html".to_string()
                );
                // Try to estimate VRAM from PCI config space
                let (name, vram_mb) = estimate_amd_from_pci();
                gpus.push(GpuInfo {
                    vendor: "amd".to_string(),
                    name,
                    vram_mb,
                    vram_detected: vram_mb > 0,
                });
            }
        }
    }

    // Try Apple Silicon
    if std::env::consts::OS == "macos" {
        if let Some(gpu) = detect_apple_gpu() {
            gpus.push(gpu);
        }
    }

    // Fallback: scan PCI/sysfs for any GPU if nothing detected yet
    if gpus.is_empty() && std::env::consts::OS == "linux" {
        if let Some(gpu) = detect_gpu_from_sysfs(warnings) {
            gpus.push(gpu);
        } else if let Some(gpu) = detect_intel_linux() {
            gpus.push(gpu);
        }
    }

    // Windows fallback
    if gpus.is_empty() && std::env::consts::OS == "windows" {
        if let Some(gpu) = detect_gpu_windows(warnings) {
            gpus.push(gpu);
        }
    }

    gpus
}

/// Check if NVIDIA hardware exists via lspci or /sys
fn has_nvidia_hardware() -> bool {
    // Check lspci
    if let Ok(output) = Command::new("lspci").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if text.contains("nvidia") && (text.contains("vga") || text.contains("3d controller")) {
                return true;
            }
        }
    }
    // Check sysfs
    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for entry in entries.flatten() {
            if let Ok(vendor) = std::fs::read_to_string(entry.path().join("device/vendor")) {
                if vendor.trim() == "0x10de" { // NVIDIA vendor ID
                    return true;
                }
            }
        }
    }
    false
}

/// Check if AMD discrete GPU hardware exists via lspci or /sys
fn has_amd_hardware() -> bool {
    if let Ok(output) = Command::new("lspci").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if text.contains("amd") && (text.contains("vga") || text.contains("display")) {
                return true;
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for entry in entries.flatten() {
            if let Ok(vendor) = std::fs::read_to_string(entry.path().join("device/vendor")) {
                if vendor.trim() == "0x1002" { // AMD vendor ID
                    return true;
                }
            }
        }
    }
    false
}

/// Try to get AMD GPU name and VRAM from PCI/sysfs
fn estimate_amd_from_pci() -> (String, u64) {
    let name = if let Ok(output) = Command::new("lspci").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            text.lines()
                .find(|l| l.to_lowercase().contains("amd") && (l.contains("VGA") || l.contains("Display")))
                .and_then(|l| l.split(':').last())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "AMD GPU".to_string())
        } else {
            "AMD GPU".to_string()
        }
    } else {
        "AMD GPU".to_string()
    };

    // Try to read VRAM from sysfs (amdgpu driver exposes this)
    let vram_mb = read_amd_vram_from_sysfs().unwrap_or(0);

    (name, vram_mb)
}

/// Read AMD VRAM from sysfs (works without rocm-smi if amdgpu driver is loaded)
fn read_amd_vram_from_sysfs() -> Option<u64> {
    let drm_dir = std::fs::read_dir("/sys/class/drm").ok()?;
    for entry in drm_dir.flatten() {
        let path = entry.path();
        // Look for card0/device/mem_info_vram_total
        let vram_path = path.join("device/mem_info_vram_total");
        if vram_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&vram_path) {
                if let Ok(bytes) = content.trim().parse::<u64>() {
                    return Some(bytes / (1024 * 1024));
                }
            }
        }
    }
    None
}

/// Detect GPU on Linux from sysfs when no vendor-specific tools are available
fn detect_gpu_from_sysfs(warnings: &mut Vec<String>) -> Option<GpuInfo> {
    let drm_dir = std::fs::read_dir("/sys/class/drm").ok()?;
    for entry in drm_dir.flatten() {
        let path = entry.path();
        let vendor_path = path.join("device/vendor");
        let vram_path = path.join("device/mem_info_vram_total");

        if let Ok(vendor_id) = std::fs::read_to_string(&vendor_path) {
            let vendor_id = vendor_id.trim();
            let (vendor, driver_hint) = match vendor_id {
                "0x10de" => ("nvidia", "Install NVIDIA drivers: https://www.nvidia.com/drivers"),
                "0x1002" => ("amd", "Install ROCm: https://rocm.docs.amd.com"),
                "0x8086" => ("intel", "Intel integrated GPU (shared memory)"),
                _ => continue,
            };

            let vram_mb = if vram_path.exists() {
                std::fs::read_to_string(&vram_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(|b| b / (1024 * 1024))
                    .unwrap_or(0)
            } else {
                0
            };

            let name = get_pci_device_name(vendor_id).unwrap_or_else(|| format!("{} GPU", vendor));

            if vram_mb == 0 && vendor != "intel" {
                warnings.push(format!(
                    "{} GPU found but VRAM size unknown. {}",
                    vendor.to_uppercase(), driver_hint
                ));
            }

            return Some(GpuInfo {
                vendor: vendor.to_string(),
                name,
                vram_mb,
                vram_detected: vram_mb > 0,
            });
        }
    }
    None
}

/// Try to get a human-readable PCI device name from lspci
fn get_pci_device_name(vendor_id: &str) -> Option<String> {
    let vendor_name = match vendor_id {
        "0x10de" => "nvidia",
        "0x1002" => "amd",
        "0x8086" => "intel",
        _ => return None,
    };

    let output = Command::new("lspci").output().ok()?;
    if !output.status.success() { return None; }

    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|l| l.to_lowercase().contains(vendor_name) && (l.contains("VGA") || l.contains("3D") || l.contains("Display")))
        .and_then(|l| l.split(':').last())
        .map(|s| s.trim().to_string())
}

/// Detect GPU on Windows using WMIC
fn detect_gpu_windows(warnings: &mut Vec<String>) -> Option<GpuInfo> {
    let output = Command::new("wmic")
        .args(["path", "Win32_VideoController", "get", "Name,AdapterRAM", "/format:csv"])
        .output()
        .ok()?;

    if !output.status.success() {
        // Try PowerShell as fallback (WMIC deprecated on newer Windows)
        return detect_gpu_powershell(warnings);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 3 {
            let adapter_ram: u64 = parts[1].trim().parse().unwrap_or(0);
            let name = parts[2].trim().to_string();
            if !name.is_empty() {
                let vram_mb = adapter_ram / (1024 * 1024);
                let vendor = if name.to_lowercase().contains("nvidia") {
                    "nvidia"
                } else if name.to_lowercase().contains("amd") || name.to_lowercase().contains("radeon") {
                    "amd"
                } else if name.to_lowercase().contains("intel") {
                    "intel"
                } else {
                    "unknown"
                };

                return Some(GpuInfo {
                    vendor: vendor.to_string(),
                    name,
                    vram_mb,
                    vram_detected: vram_mb > 0,
                });
            }
        }
    }

    warnings.push("Could not detect GPU via WMIC. Try running as administrator.".to_string());
    None
}

/// PowerShell fallback for Windows GPU detection
fn detect_gpu_powershell(_warnings: &mut Vec<String>) -> Option<GpuInfo> {
    let output = Command::new("powershell")
        .args(["-Command", "Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM | ConvertTo-Json"])
        .output()
        .ok()?;

    if !output.status.success() { return None; }

    let text = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;

    // Can be a single object or array
    let gpu = if json.is_array() {
        json.as_array()?.first()?.clone()
    } else {
        json
    };

    let name = gpu.get("Name")?.as_str()?.to_string();
    let adapter_ram = gpu.get("AdapterRAM").and_then(|v| v.as_u64()).unwrap_or(0);
    let vram_mb = adapter_ram / (1024 * 1024);

    let vendor = if name.to_lowercase().contains("nvidia") {
        "nvidia"
    } else if name.to_lowercase().contains("amd") || name.to_lowercase().contains("radeon") {
        "amd"
    } else if name.to_lowercase().contains("intel") {
        "intel"
    } else {
        "unknown"
    };

    Some(GpuInfo {
        vendor: vendor.to_string(),
        name,
        vram_mb,
        vram_detected: vram_mb > 0,
    })
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
        vram_detected: vram_mb > 0,
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
        vram_detected: vram_mb > 0,
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
        vram_detected: true, // Apple always reports GPU info via system_profiler
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
        vram_detected: true, // Intel iGPU uses shared memory, 0 is accurate
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
                lines.push(format!("  GPU:  {} ({} MB / {:.0} GB VRAM)", gpu.name, gpu.vram_mb, gpu.vram_mb as f64 / 1024.0));
            } else if gpu.vram_detected {
                lines.push(format!("  GPU:  {} (shared memory)", gpu.name));
            } else {
                lines.push(format!("  GPU:  {} (VRAM unknown — install drivers)", gpu.name));
            }
        }
    }

    if !hw.warnings.is_empty() {
        lines.push(String::new());
        for warning in &hw.warnings {
            lines.push(format!("  WARNING: {}", warning));
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
                vram_detected: true,
            }],
            ram_mb: 32768,
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
            warnings: vec![],
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
                vram_detected: true,
            }],
            ram_mb: 16384,
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
            warnings: vec![],
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
            warnings: vec![],
        };
        let rec = recommend(&hw);
        assert_eq!(rec.tier, "cpu-only");
        assert_eq!(rec.model, "disabled");
    }

    #[test]
    fn recommend_unknown_when_vram_not_detected() {
        let hw = HardwareInfo {
            gpus: vec![GpuInfo {
                vendor: "nvidia".to_string(),
                name: "NVIDIA GPU (drivers not installed)".to_string(),
                vram_mb: 0,
                vram_detected: false,
            }],
            ram_mb: 32768,
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
            warnings: vec!["NVIDIA GPU detected but nvidia-smi not found.".to_string()],
        };
        let rec = recommend(&hw);
        assert_eq!(rec.tier, "unknown");
        // Should give manual instructions, not auto-recommend cpu-only
        let text = format_recommendation(&rec);
        assert!(text.contains("choose manually"));
    }

    #[test]
    fn recommend_apple_silicon_uses_unified_memory() {
        let hw = HardwareInfo {
            gpus: vec![GpuInfo {
                vendor: "apple".to_string(),
                name: "Apple M2 Pro".to_string(),
                vram_mb: 0,
                vram_detected: true,
            }],
            ram_mb: 32768, // 32GB unified → 75% = 24GB effective
            arch: "aarch64".to_string(),
            os: "macos".to_string(),
            warnings: vec![],
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
                vram_detected: true,
            }],
            ram_mb: 32768,
            arch: "x86_64".to_string(),
            os: "linux".to_string(),
            warnings: vec![],
        };
        let rec = recommend(&hw);
        let text = format_recommendation(&rec);
        assert!(text.contains("aegis slm engine"));
        assert!(text.contains("aegis slm use"));
    }
}
