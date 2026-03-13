//! Scans text content for plaintext credentials.
//!
//! Detects: API keys, tokens, passwords, private keys, connection strings.
//! Returns findings with location and confidence level.
//!
//! The scanner is side-effect-free: it only reads content and reports findings.
//! Storing detected secrets is handled separately by the storage module.

use std::path::{Path, PathBuf};

use regex::Regex;

use crate::VaultError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of scanning a piece of content.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
}

/// A single credential finding.
#[derive(Debug, Clone)]
pub struct Finding {
    pub credential_type: CredentialType,
    pub location: Location,
    pub confidence: Confidence,
    /// A masked preview of the credential (e.g. "AKIA****6789").
    pub masked_preview: String,
}

/// The kind of credential detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialType {
    ApiKey,
    BearerToken,
    PrivateKey,
    Password,
    ConnectionString,
    AwsKey,
    GenericSecret,
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => write!(f, "api_key"),
            Self::BearerToken => write!(f, "bearer_token"),
            Self::PrivateKey => write!(f, "private_key"),
            Self::Password => write!(f, "password"),
            Self::ConnectionString => write!(f, "connection_string"),
            Self::AwsKey => write!(f, "aws_key"),
            Self::GenericSecret => write!(f, "generic_secret"),
        }
    }
}

/// Confidence level of the detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Where in the content the credential was found.
#[derive(Debug, Clone)]
pub struct Location {
    /// Optional file path (set when scanning files).
    pub file_path: Option<String>,
    /// Line number (1-based) if computable.
    pub line: Option<usize>,
    /// Byte offset from the start of content.
    pub offset: usize,
    /// Length of the matched credential text in bytes.
    pub length: usize,
}

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

struct PatternDef {
    credential_type: CredentialType,
    confidence: Confidence,
    pattern: &'static str,
    /// Which capture group holds the secret value (0 = entire match).
    secret_group: usize,
}

const PATTERNS: &[PatternDef] = &[
    PatternDef {
        credential_type: CredentialType::AwsKey,
        confidence: Confidence::High,
        pattern: r"(?i)(AKIA[0-9A-Z]{16})",
        secret_group: 1,
    },
    PatternDef {
        credential_type: CredentialType::PrivateKey,
        confidence: Confidence::High,
        pattern: r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        secret_group: 0,
    },
    PatternDef {
        credential_type: CredentialType::BearerToken,
        confidence: Confidence::High,
        pattern: r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})",
        secret_group: 1,
    },
    PatternDef {
        credential_type: CredentialType::ApiKey,
        confidence: Confidence::Medium,
        pattern: r#"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})"#,
        secret_group: 2,
    },
    PatternDef {
        credential_type: CredentialType::Password,
        confidence: Confidence::Medium,
        pattern: r"://[^:]+:([^@]{3,})@",
        secret_group: 1,
    },
    PatternDef {
        credential_type: CredentialType::ConnectionString,
        confidence: Confidence::Medium,
        pattern: r"(?i)(postgres|mysql|mongodb|redis)://",
        secret_group: 0,
    },
    PatternDef {
        credential_type: CredentialType::GenericSecret,
        confidence: Confidence::Low,
        pattern: r#"(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{8,})"#,
        secret_group: 2,
    },
];

// ---------------------------------------------------------------------------
// Masking
// ---------------------------------------------------------------------------

/// Mask a credential string: show first 4 and last 4 characters with `****` in between.
/// For secrets shorter than 12 characters, returns `****`.
pub fn mask_credential(raw: &str) -> String {
    if raw.len() < 12 {
        return "****".to_string();
    }
    let first4: String = raw.chars().take(4).collect();
    let last4: String = raw.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{first4}****{last4}")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the 1-based line number for a byte offset within `content`.
fn line_number_at(content: &str, byte_offset: usize) -> usize {
    content[..byte_offset].matches('\n').count() + 1
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Redact all detected credentials in the text, replacing them with masked versions.
/// Returns the redacted text and the list of findings.
pub fn redact_text(content: &str) -> (String, ScanResult) {
    let result = scan_text(content);
    if result.findings.is_empty() {
        return (content.to_string(), result);
    }

    // Collect all match ranges with their replacements, sorted by offset descending
    // so we can replace from the end without invalidating earlier offsets.
    let mut replacements: Vec<(usize, usize, String)> = Vec::new();

    for pdef in PATTERNS {
        let re = match Regex::new(pdef.pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for caps in re.captures_iter(content) {
            let secret_match = caps.get(pdef.secret_group).unwrap_or(caps.get(0).unwrap());
            let masked = mask_credential(secret_match.as_str());
            replacements.push((secret_match.start(), secret_match.end(), masked));
        }
    }

    // Sort by offset descending so replacements don't shift earlier offsets
    replacements.sort_by(|a, b| b.0.cmp(&a.0));

    // Deduplicate overlapping ranges (keep the first/largest)
    let mut redacted = content.to_string();
    let mut last_start = usize::MAX;
    for (start, end, masked) in &replacements {
        if *start >= last_start {
            continue; // skip overlapping
        }
        redacted.replace_range(*start..*end, masked);
        last_start = *start;
    }

    (redacted, result)
}

/// Scan arbitrary text for plaintext credentials.
pub fn scan_text(content: &str) -> ScanResult {
    let mut findings = Vec::new();

    for pdef in PATTERNS {
        let re = match Regex::new(pdef.pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for caps in re.captures_iter(content) {
            let full_match = caps.get(0).unwrap();
            let secret_match = caps.get(pdef.secret_group).unwrap_or(full_match);
            let secret_text = secret_match.as_str();

            findings.push(Finding {
                credential_type: pdef.credential_type.clone(),
                location: Location {
                    file_path: None,
                    line: Some(line_number_at(content, full_match.start())),
                    offset: full_match.start(),
                    length: full_match.len(),
                },
                confidence: pdef.confidence.clone(),
                masked_preview: mask_credential(secret_text),
            });
        }
    }

    ScanResult { findings }
}

/// Scan a file on disk for plaintext credentials.
pub fn scan_file(path: &Path) -> Result<ScanResult, VaultError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| VaultError::ScannerError(format!("failed to read {}: {e}", path.display())))?;
    let mut result = scan_text(&content);
    // Patch in file path for every finding.
    let path_str = path.to_string_lossy().to_string();
    for finding in &mut result.findings {
        finding.location.file_path = Some(path_str.clone());
    }
    Ok(result)
}

/// Scan a directory for credential leaks.
///
/// Only files whose extension matches one of `extensions` are scanned.
/// Pass an empty slice to scan all files.
pub fn scan_directory(
    dir: &Path,
    extensions: &[&str],
) -> Result<Vec<(PathBuf, ScanResult)>, VaultError> {
    let mut results = Vec::new();

    let entries = std::fs::read_dir(dir)
        .map_err(|e| VaultError::ScannerError(format!("failed to read dir {}: {e}", dir.display())))?;

    for entry in entries {
        let entry = entry.map_err(|e| VaultError::ScannerError(e.to_string()))?;
        let path = entry.path();

        if path.is_dir() {
            // Recurse into subdirectories.
            let mut sub = scan_directory(&path, extensions)?;
            results.append(&mut sub);
            continue;
        }

        if path.is_file() {
            // Filter by extension if the caller specified any.
            if !extensions.is_empty() {
                let ext_matches = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|ext| extensions.iter().any(|&wanted| wanted == ext));
                if !ext_matches {
                    continue;
                }
            }

            match scan_file(&path) {
                Ok(sr) if !sr.findings.is_empty() => {
                    results.push((path, sr));
                }
                Ok(_) => {} // no findings, skip
                Err(e) => {
                    tracing::warn!("skipping {}: {e}", path.display());
                }
            }
        }
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_aws_key() {
        let content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let result = scan_text(content);
        assert!(
            result.findings.iter().any(|f| f.credential_type == CredentialType::AwsKey),
            "should detect AWS key"
        );
    }

    #[test]
    fn detect_bearer_token() {
        let content = r#"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test_payload"#;
        let result = scan_text(content);
        assert!(
            result.findings.iter().any(|f| f.credential_type == CredentialType::BearerToken),
            "should detect bearer token"
        );
    }

    #[test]
    fn detect_private_key_header() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...";
        let result = scan_text(content);
        assert!(
            result.findings.iter().any(|f| f.credential_type == CredentialType::PrivateKey),
            "should detect private key"
        );
    }

    #[test]
    fn detect_api_key() {
        let content = r#"API_KEY = "sk_live_abcdefghijklmnopqrstuv""#;
        let result = scan_text(content);
        assert!(
            result.findings.iter().any(|f| f.credential_type == CredentialType::ApiKey),
            "should detect api key"
        );
    }

    #[test]
    fn detect_connection_string() {
        let content = "DATABASE_URL=postgres://user:pass@localhost/db";
        let result = scan_text(content);
        let types: Vec<_> = result.findings.iter().map(|f| &f.credential_type).collect();
        assert!(
            types.contains(&&CredentialType::ConnectionString),
            "should detect connection string, got: {types:?}"
        );
    }

    #[test]
    fn detect_password_in_url() {
        let content = "postgres://admin:supersecretpassword@db.example.com/mydb";
        let result = scan_text(content);
        assert!(
            result.findings.iter().any(|f| f.credential_type == CredentialType::Password),
            "should detect password in URL"
        );
    }

    #[test]
    fn detect_generic_secret() {
        let content = r#"token = "abcdef1234567890""#;
        let result = scan_text(content);
        assert!(
            result.findings.iter().any(|f| f.credential_type == CredentialType::GenericSecret),
            "should detect generic secret"
        );
    }

    #[test]
    fn mask_long_credential() {
        assert_eq!(mask_credential("AKIAIOSFODNN7EXAMPLE"), "AKIA****MPLE");
    }

    #[test]
    fn mask_short_credential() {
        assert_eq!(mask_credential("short"), "****");
    }

    #[test]
    fn no_findings_in_clean_text() {
        let result = scan_text("This is perfectly clean text with no secrets at all.");
        assert!(result.findings.is_empty(), "should find nothing in clean text");
    }

    #[test]
    fn line_numbers_correct() {
        let content = "line1\nline2\napi_key = abcdefghijklmnopqrstuvwxyz\nline4";
        let result = scan_text(content);
        assert!(!result.findings.is_empty());
        let finding = &result.findings[0];
        assert_eq!(finding.location.line, Some(3), "credential is on line 3");
    }

    #[test]
    fn scan_file_sets_path() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.env");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            writeln!(f, "API_KEY=sk_live_abcdefghijklmnopqrstuvwx").unwrap();
        }
        let result = scan_file(&file_path).unwrap();
        assert!(!result.findings.is_empty());
        assert_eq!(
            result.findings[0].location.file_path.as_deref(),
            Some(file_path.to_str().unwrap())
        );
    }

    #[test]
    fn scan_directory_finds_secrets() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join("config.env");
        {
            let mut f = std::fs::File::create(&env_file).unwrap();
            writeln!(f, "SECRET=abcdef1234567890").unwrap();
        }
        let clean_file = dir.path().join("readme.txt");
        {
            let mut f = std::fs::File::create(&clean_file).unwrap();
            writeln!(f, "Nothing secret here").unwrap();
        }

        let results = scan_directory(dir.path(), &["env"]).unwrap();
        assert_eq!(results.len(), 1, "only the .env file should have findings");
    }
}
